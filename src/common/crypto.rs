use std::collections::{BTreeMap, HashMap, HashSet};
use std::fs;
use std::io::Read;
use std::num::NonZeroUsize;
use std::path::Path;
use std::time::Duration;

use collection::config::{
    CollectionConfigInternal, CollectionEncryptionConfig, CollectionParams, EncryptionSelector,
};
use data_encoding::BASE64URL_NOPAD;
use qdrant_sec::{
    AeadCipher, CKKS_PROFILE_OPENFHE_128_N16384_D4_SCALE50, CKKS_VECTOR_KEY_DOMAIN,
    CLIENT_PAYLOAD_ENVELOPE_BINDING, CkksParameters, CkksPublicMaterial, CkksVectorEncryptor,
    ClientPayloadNonceReplayKey, ClientPayloadSignatureVerification,
    ClientPayloadValidationContext, ClientPayloadVerifiedEnvelopeKey, CommandOpenFheBackend,
    EncryptedCkksVector, ExistingPayloadMode, LocalMasterKeyProvider,
    METADATA_BLIND_INDEX_PROVIDER, METADATA_EXACT_MATCH_TOKEN_BINDING, MasterKeyProvider,
    PAYLOAD_AES_GCM_PROVIDER, PAYLOAD_CLIENT_AEAD_PROVIDER, PAYLOAD_FIELD_BINDING,
    PayloadEncryptionError, PayloadEncryptionPolicy, PayloadTextEncryptor,
    RESOURCE_KEY_WRAP_ALGORITHM, SecretKey, VECTOR_ENVELOPE_BINDING, VECTOR_OPENFHE_CKKS_PROVIDER,
    WrappedKeyBlob, client_payload_nonce_replay_key, client_payload_signature_key_id,
    encrypted_ckks_vector_payload_value, rewrap_resource_key,
    validate_client_payload_value_for_runtime,
};
use segment::json_path::JsonPath;
use segment::types::{Distance, Payload};
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
    #[error("crypto material {material} must set source explicitly")]
    MissingMaterialSource { material: String },
    #[error("crypto material {material} has unsupported source {material_source}")]
    UnsupportedMaterialSource {
        material: String,
        material_source: String,
    },
    #[error("crypto material {material} uses unsupported kind {kind}")]
    UnsupportedMaterialKind { material: String, kind: String },
    #[error("crypto material {material} source does not match configured fields")]
    MaterialSourceMismatch { material: String },
    #[error("crypto material {material} file source {path} is invalid: {reason}")]
    InvalidMaterialFileSource {
        material: String,
        path: String,
        reason: String,
    },
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
    #[error("crypto backend {backend} requires sha256_b64 program pin")]
    MissingBackendSha256Pin { backend: String },
    #[error("crypto backend {backend} program path is invalid: {program}")]
    InvalidBackendProgram { backend: String, program: String },
    #[error("crypto backend {backend} size is invalid: {reason}")]
    InvalidBackendSize { backend: String, reason: String },
    #[error("crypto backend {backend} timeout is invalid: {reason}")]
    InvalidBackendTimeout { backend: String, reason: String },
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
    #[error("crypto instance name {instance} is invalid")]
    InvalidInstanceName { instance: String },
    #[error("crypto material name {material} is invalid")]
    InvalidMaterialName { material: String },
    #[error("crypto backend name {backend} is invalid")]
    InvalidBackendName { backend: String },
    #[error("crypto backend {backend} uses unsupported kind {kind}")]
    UnsupportedBackendKind { backend: String, kind: String },
    #[error("crypto instance {instance} option {option} is invalid: {reason}")]
    InvalidInstanceOption {
        instance: String,
        option: String,
        reason: String,
    },
    #[error("legacy ckks runtime settings are unsupported; use crypto.* runtime settings")]
    LegacyCkksRuntimeUnsupported,
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
const CKKS_CRYPTO_CONTEXT_B64_OPTION: &str = "crypto_context_b64";
const CKKS_PUBLIC_KEY_B64_OPTION: &str = "public_key_b64";
const VAULT_KV2_RESPONSE_MAX_BYTES: u64 = 64 * 1024;
const PAYLOAD_AES_GCM_ALLOWED_OPTIONS: &[&str] = &[
    "key_id",
    MATERIAL_FINGERPRINT_ID_OPTION,
    RETIRED_MATERIALS_OPTION,
];
const PAYLOAD_AES_GCM_ALLOWED_MATERIAL_ROLES: &[&str] = &[PAYLOAD_SYM_KEY_ROLE];
const CLIENT_AEAD_ALLOWED_OPTIONS: &[&str] = &[
    "key_id",
    KEY_ID_REQUIRED_OPTION,
    EXPECTED_RK_ID_OPTION,
    MIN_RK_EPOCH_OPTION,
    MAX_RK_EPOCH_OPTION,
    SIGNATURE_PUBLIC_KEY_B64_OPTION,
    SIGNATURE_PUBLIC_KEYS_OPTION,
    SIGNATURE_KEY_ID_OPTION,
];
const VECTOR_OPENFHE_CKKS_ALLOWED_OPTIONS: &[&str] = &[
    "key_id",
    MATERIAL_FINGERPRINT_ID_OPTION,
    CKKS_PROFILE_OPTION,
    CKKS_CRYPTO_CONTEXT_B64_OPTION,
    CKKS_PUBLIC_KEY_B64_OPTION,
];
const VECTOR_OPENFHE_CKKS_ALLOWED_MATERIAL_ROLES: &[&str] = &[PAYLOAD_SYM_KEY_ROLE];
const METADATA_BLIND_INDEX_ALLOWED_OPTIONS: &[&str] = &[
    "key_id",
    EXPECTED_RK_ID_OPTION,
    MIN_RK_EPOCH_OPTION,
    MAX_RK_EPOCH_OPTION,
];

fn unsupported_instance_option(options: &Value, allowed_options: &[&str]) -> Option<String> {
    let options = options.as_object()?;
    options
        .keys()
        .find(|option| !allowed_options.contains(&option.as_str()))
        .cloned()
}

fn unsupported_material_role(
    materials: &HashMap<String, String>,
    allowed_roles: &[&str],
) -> Option<String> {
    materials
        .keys()
        .find(|role| !allowed_roles.contains(&role.as_str()))
        .cloned()
}

fn validate_optional_instance_key_id(
    instance_name: &str,
    instance: &CryptoInstanceConfig,
    provider: &str,
) -> Result<(), CryptoSetupError> {
    match instance.options.get("key_id") {
        None | Some(Value::Null) => Ok(()),
        Some(Value::String(key_id)) if is_crypto_identifier(key_id) => Ok(()),
        Some(_) => Err(CryptoSetupError::InvalidInstanceOption {
            instance: instance_name.to_string(),
            option: "key_id".to_string(),
            reason: format!("{provider} key_id must be a crypto identifier string"),
        }),
    }
}

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
    #[error("payload crypto instance {instance} uses unsupported option {option}")]
    UnsupportedInstanceOption { instance: String, option: String },
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
    #[error("payload crypto material {material} must set source explicitly")]
    MissingMaterialSource { material: String },
    #[error("payload crypto material {material} has unsupported source {material_source}")]
    UnsupportedMaterialSource {
        material: String,
        material_source: String,
    },
    #[error("payload crypto material {material} is missing environment variable {env}")]
    MissingMaterialEnv { material: String, env: String },
    #[error("payload crypto material {material} file path is missing")]
    MissingMaterialPath { material: String },
    #[error("payload crypto material {material} fd is missing")]
    MissingMaterialFd { material: String },
    #[error("payload crypto material {material} inline value is missing")]
    MissingInlineMaterial { material: String },
    #[error("payload crypto material {material} file {path} could not be read")]
    UnreadableMaterialFile { material: String, path: String },
    #[error("payload crypto material {material} file {path} is invalid: {reason}")]
    InvalidMaterialFileSource {
        material: String,
        path: String,
        reason: String,
    },
    #[error("payload crypto material {material} must be base64url without padding")]
    InvalidMaterialEncoding { material: String },
    #[error("payload crypto material {material} must decode to exactly 32 bytes")]
    InvalidMaterialLength { material: String },
    #[error("legacy ckks collection config is unsupported; use collection encryption rules")]
    LegacyCkksUnsupported,
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
        signature_verifier: ClientPayloadSignatureVerifier,
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

pub(crate) struct PayloadWriteOutcome {
    pub changed: usize,
    pub verified_client_envelope_keys: HashSet<ClientPayloadVerifiedEnvelopeKey>,
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

    #[cfg(test)]
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
        Ok(self
            .process_payload_with_replay_cache(point_id, payload, seen_client_nonces)?
            .changed)
    }

    pub(crate) fn process_payload_with_replay_cache(
        &self,
        point_id: &str,
        payload: &mut Payload,
        seen_client_nonces: &mut HashSet<ClientPayloadNonceReplayKey>,
    ) -> Result<PayloadWriteOutcome, PayloadWriteSetupError> {
        let mut changed = 0;
        let mut verified_client_envelope_keys = HashSet::new();

        for rule in &self.rules {
            match rule {
                PayloadWriteRule::ServerEncrypt { encryptor, policy } => {
                    changed += encryptor.encrypt_selected_fields_with_mode(
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
                    signature_verifier,
                } => {
                    for field in policy.fields() {
                        let encrypted_path = field.parse::<JsonPath>().map_err(|_| {
                            PayloadWriteSetupError::Payload(
                                PayloadEncryptionError::InvalidFieldPath(field.clone()),
                            )
                        })?;
                        for value in encrypted_path.value_get(&payload.0) {
                            let signature_verification =
                                signature_verifier.verification_for_value(value, field)?;
                            let verified_envelope_key = validate_client_payload_value_for_runtime(
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
                                    signature_required: true,
                                    signature_verification: Some(signature_verification),
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
                            verified_client_envelope_keys.insert(verified_envelope_key);
                            changed += 1;
                        }
                    }
                }
            }
        }

        Ok(PayloadWriteOutcome {
            changed,
            verified_client_envelope_keys,
        })
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
                    signature_verifier,
                } => {
                    for field in policy.fields() {
                        let encrypted_path = field.parse::<JsonPath>().map_err(|_| {
                            PayloadWriteSetupError::Payload(
                                PayloadEncryptionError::InvalidFieldPath(field.clone()),
                            )
                        })?;
                        for value in encrypted_path.value_get(&payload.0) {
                            let signature_verification =
                                signature_verifier.verification_for_value(value, field)?;
                            validate_client_payload_value_for_runtime(
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
                                    signature_required: true,
                                    signature_verification: Some(signature_verification),
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

#[cfg(test)]
pub(crate) fn payload_write_plan_for_collection(
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
    let _ = ckks;
    Err(PayloadWriteSetupError::LegacyCkksUnsupported)
}

struct VectorWriteRule {
    vector_name: String,
    distance: Distance,
    encryptor: CkksVectorEncryptor<CommandOpenFheBackend>,
    public_material: CkksPublicMaterial,
}

pub struct VectorWritePlan {
    rules: Vec<VectorWriteRule>,
}

impl VectorWritePlan {
    pub fn contains_vector_name(&self, vector_name: &str) -> bool {
        self.rules
            .iter()
            .any(|rule| rule.vector_name == vector_name)
    }

    pub fn distance_for_vector(&self, vector_name: &str) -> Option<Distance> {
        self.rules
            .iter()
            .find(|rule| rule.vector_name == vector_name)
            .map(|rule| rule.distance)
    }

    pub fn encrypt_dense_vector_payload_value(
        &self,
        collection_name: &str,
        point_id: &str,
        vector_name: &str,
        values: &[f32],
    ) -> Result<Option<Value>, StorageError> {
        let Some(rule) = self
            .rules
            .iter()
            .find(|rule| rule.vector_name == vector_name)
        else {
            return Ok(None);
        };
        let values: Vec<f64> = values.iter().map(|value| *value as f64).collect();
        let encrypted = rule
            .encryptor
            .encrypt(
                collection_name,
                point_id,
                &rule.public_material,
                values.as_slice(),
            )
            .map_err(|err| {
                StorageError::service_error(format!(
                    "CKKS vector encryption failed for vector '{vector_name}' in collection {collection_name}: {err}",
                ))
            })?;
        encrypted_ckks_vector_payload_value(&encrypted).map_err(|err| {
            StorageError::service_error(format!(
                "failed to serialize CKKS vector envelope for vector '{vector_name}' in collection {collection_name}: {err}",
            ))
        })
        .map(Some)
    }

    pub fn score_encrypted_query_batch(
        &self,
        collection_name: &str,
        vector_name: &str,
        encrypted_items: &[(String, EncryptedCkksVector)],
        query_values: &[f32],
    ) -> Result<Option<Vec<f32>>, StorageError> {
        let Some(rule) = self
            .rules
            .iter()
            .find(|rule| rule.vector_name == vector_name)
        else {
            return Ok(None);
        };
        let query_values = query_values
            .iter()
            .map(|value| *value as f64)
            .collect::<Vec<_>>();
        let encrypted_items = encrypted_items
            .iter()
            .map(|(point_id, encrypted)| (point_id.as_str(), encrypted))
            .collect::<Vec<_>>();
        let scores = rule
            .encryptor
            .score_encrypted_query_batch(
                collection_name,
                &rule.public_material,
                &encrypted_items,
                ckks_score_distance_name(rule.distance),
                query_values.as_slice(),
            )
            .map_err(|err| {
                StorageError::service_error(format!(
                    "CKKS vector encrypted-query batch scoring failed for vector '{vector_name}' in collection {collection_name}: {err}",
                ))
            })?;
        let scores = scores
            .into_iter()
            .map(|score| {
                let score = score as f32;
                if !score.is_finite() {
                    return Err(StorageError::service_error(format!(
                        "CKKS vector encrypted-query batch scoring returned non-finite score for vector '{vector_name}' in collection {collection_name}",
                    )));
                }
                Ok(score)
            })
            .collect::<Result<Vec<_>, _>>()?;

        Ok(Some(scores))
    }

    pub fn score_client_encrypted_query_batch(
        &self,
        collection_name: &str,
        vector_name: &str,
        encrypted_items: &[(String, EncryptedCkksVector)],
        context_digest: &str,
        slots: usize,
        encrypted_query: &[u8],
    ) -> Result<Option<Vec<f32>>, StorageError> {
        let Some(rule) = self
            .rules
            .iter()
            .find(|rule| rule.vector_name == vector_name)
        else {
            return Ok(None);
        };
        let expected_digest = rule.encryptor.context_digest_for(&rule.public_material);
        if context_digest != expected_digest {
            return Err(StorageError::bad_input(format!(
                "encrypted query context digest does not match active CKKS public material for vector '{vector_name}' in collection {collection_name}",
            )));
        }
        let encrypted_items = encrypted_items
            .iter()
            .map(|(point_id, encrypted)| (point_id.as_str(), encrypted))
            .collect::<Vec<_>>();
        let scores = rule
            .encryptor
            .score_pre_encrypted_query_batch(
                collection_name,
                &rule.public_material,
                encrypted_query,
                slots,
                &encrypted_items,
                ckks_score_distance_name(rule.distance),
            )
            .map_err(|err| {
                StorageError::service_error(format!(
                    "CKKS vector client-encrypted-query batch scoring failed for vector '{vector_name}' in collection {collection_name}: {err}",
                ))
            })?;
        let scores = scores
            .into_iter()
            .map(|score| {
                let score = score as f32;
                if !score.is_finite() {
                    return Err(StorageError::service_error(format!(
                        "CKKS vector client-encrypted-query batch scoring returned non-finite score for vector '{vector_name}' in collection {collection_name}",
                    )));
                }
                Ok(score)
            })
            .collect::<Result<Vec<_>, _>>()?;

        Ok(Some(scores))
    }

    pub fn score_stored_query_batch(
        &self,
        collection_name: &str,
        vector_name: &str,
        query_point_id: &str,
        query_encrypted: &EncryptedCkksVector,
        encrypted_items: &[(String, EncryptedCkksVector)],
    ) -> Result<Option<Vec<f32>>, StorageError> {
        let Some(rule) = self
            .rules
            .iter()
            .find(|rule| rule.vector_name == vector_name)
        else {
            return Ok(None);
        };
        let encrypted_items = encrypted_items
            .iter()
            .map(|(point_id, encrypted)| (point_id.as_str(), encrypted))
            .collect::<Vec<_>>();
        let scores = rule
            .encryptor
            .score_stored_query_batch(
                collection_name,
                &rule.public_material,
                query_point_id,
                query_encrypted,
                &encrypted_items,
                ckks_score_distance_name(rule.distance),
            )
            .map_err(|err| {
                StorageError::service_error(format!(
                    "CKKS vector stored-ciphertext batch scoring failed for vector '{vector_name}' in collection {collection_name}: {err}",
                ))
            })?;
        let scores = scores
            .into_iter()
            .map(|score| {
                let score = score as f32;
                if !score.is_finite() {
                    return Err(StorageError::service_error(format!(
                        "CKKS vector stored-ciphertext batch scoring returned non-finite score for vector '{vector_name}' in collection {collection_name}",
                    )));
                }
                Ok(score)
            })
            .collect::<Result<Vec<_>, _>>()?;

        Ok(Some(scores))
    }
}

pub fn vector_write_plan_for_collection_with_crypto_id(
    settings: &Settings,
    collection_name: &str,
    collection_crypto_id: &str,
    params: &CollectionParams,
) -> Result<Option<VectorWritePlan>, StorageError> {
    let Some(encryption) = &params.encryption else {
        if params.ckks.is_some() {
            return Err(StorageError::bad_input(
                "legacy ckks collection config is unsupported; use collection encryption rules",
            ));
        }
        return Ok(None);
    };

    generic_vector_write_plan(
        &effective_settings(settings),
        collection_name,
        collection_crypto_id,
        params,
        encryption,
    )
}

fn generic_vector_write_plan(
    runtime_settings: &CryptoSettings,
    collection_name: &str,
    collection_crypto_id: &str,
    params: &CollectionParams,
    encryption: &CollectionEncryptionConfig,
) -> Result<Option<VectorWritePlan>, StorageError> {
    let mut rules = Vec::new();

    for rule in &encryption.rules {
        let EncryptionSelector::VectorNames { names } = &rule.selector else {
            continue;
        };
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
        let instance = runtime_settings
            .instances
            .get(&rule.instance)
            .ok_or_else(|| {
                StorageError::bad_input(format!(
                    "collection {collection_name} references unknown crypto instance {}",
                    rule.instance
                ))
            })?;
        if instance.provider != VECTOR_OPENFHE_CKKS_PROVIDER {
            return Err(StorageError::bad_input(format!(
                "collection {collection_name} rule {} must use provider {VECTOR_OPENFHE_CKKS_PROVIDER}, found {}",
                rule.id, instance.provider
            )));
        }
        let profile = required_string_option(instance, &rule.instance, CKKS_PROFILE_OPTION)?;
        if profile != CKKS_PROFILE_OPENFHE_128_N16384_D4_SCALE50 {
            return Err(StorageError::bad_input(format!(
                "collection {collection_name} vector crypto instance {} profile {profile} is not allowlisted; expected {CKKS_PROFILE_OPENFHE_128_N16384_D4_SCALE50}",
                rule.instance
            )));
        }
        let crypto_context =
            required_base64url_option(instance, &rule.instance, CKKS_CRYPTO_CONTEXT_B64_OPTION)?;
        let public_key =
            required_base64url_option(instance, &rule.instance, CKKS_PUBLIC_KEY_B64_OPTION)?;
        let public_material = CkksPublicMaterial::new(crypto_context, public_key).map_err(|err| {
            StorageError::bad_input(format!(
                "collection {collection_name} vector crypto instance {} public material is invalid: {err}",
                rule.instance
            ))
        })?;

        let key_id = resolve_payload_key_id(collection_name, encryption, &rule.instance, instance)
            .map_err(|err| {
                StorageError::bad_input(format!(
                    "collection {collection_name} vector crypto key id validation failed: {err}"
                ))
            })?;
        let material_ref = instance
            .materials
            .get(PAYLOAD_SYM_KEY_ROLE)
            .ok_or_else(|| {
                StorageError::bad_input(format!(
                    "collection {collection_name} vector crypto instance {} is missing metadata key material binding {PAYLOAD_SYM_KEY_ROLE}",
                    rule.instance
                ))
            })?;
        let material = runtime_settings.materials.get(material_ref).ok_or_else(|| {
            StorageError::bad_input(format!(
                "collection {collection_name} vector crypto instance {} references unknown metadata key material {material_ref}",
                rule.instance
            ))
        })?;
        let resource_key = decode_resource_key(runtime_settings, material_ref, material).map_err(
            |err| {
                StorageError::bad_input(format!(
                    "collection {collection_name} vector crypto metadata key validation failed: {err}"
                ))
            },
        )?;
        let material_fingerprint_id =
            required_string_option(instance, &rule.instance, MATERIAL_FINGERPRINT_ID_OPTION)?;
        let backend_ref = instance.backend_ref.as_deref().ok_or_else(|| {
            StorageError::bad_input(format!(
                "collection {collection_name} vector crypto instance {} is missing backend_ref",
                rule.instance
            ))
        })?;
        let backend_config = runtime_settings.backends.get(backend_ref).ok_or_else(|| {
            StorageError::bad_input(format!(
                "collection {collection_name} vector crypto instance {} references unknown backend {backend_ref}",
                rule.instance
            ))
        })?;
        let backend = openfhe_backend_from_config(backend_ref, backend_config)?;

        for vector_name in names {
            let distance = ckks_vector_distance(params, collection_name, vector_name)?;
            let encryptor = if let Some(rk_epoch) = material.rk_epoch {
                CkksVectorEncryptor::new_from_resource_key_with_metadata(
                    key_id,
                    vector_name,
                    CkksParameters::openfhe_default_128_bit(),
                    &resource_key,
                    material_fingerprint_id,
                    material_ref.clone(),
                    rk_epoch,
                    backend.clone(),
                )
            } else {
                CkksVectorEncryptor::new_from_resource_key_with_material_fingerprint(
                    key_id,
                    vector_name,
                    CkksParameters::openfhe_default_128_bit(),
                    &resource_key,
                    material_fingerprint_id,
                    backend.clone(),
                )
            }
            .and_then(|encryptor| encryptor.with_collection_identity(collection_crypto_id))
            .map(|encryptor| encryptor.with_encryption_epoch(encryption.encryption_epoch))
            .map_err(|err| {
                StorageError::bad_input(format!(
                    "collection {collection_name} vector crypto instance {} is invalid for vector '{vector_name}': {err}",
                    rule.instance
                ))
            })?;
            rules.push(VectorWriteRule {
                vector_name: vector_name.clone(),
                distance,
                encryptor,
                public_material: public_material.clone(),
            });
        }
    }

    if rules.is_empty() {
        Ok(None)
    } else {
        Ok(Some(VectorWritePlan { rules }))
    }
}

fn ckks_vector_distance(
    params: &CollectionParams,
    collection_name: &str,
    vector_name: &str,
) -> Result<Distance, StorageError> {
    params.get_distance(vector_name).map_err(|err| {
        StorageError::bad_input(format!(
            "collection {collection_name} encrypted vector '{vector_name}' is not configured: {err}",
        ))
    })
}

fn ckks_score_distance_name(distance: Distance) -> &'static str {
    match distance {
        Distance::Cosine => "cosine",
        Distance::Euclid => "euclid",
        Distance::Dot => "dot",
        Distance::Manhattan => "manhattan",
    }
}

fn required_string_option<'a>(
    instance: &'a CryptoInstanceConfig,
    instance_id: &str,
    option: &str,
) -> Result<&'a str, StorageError> {
    match instance.options.get(option) {
        Some(Value::String(value)) => Ok(value.as_str()),
        Some(_) => Err(StorageError::bad_input(format!(
            "crypto instance {instance_id} option {option} must be a string",
        ))),
        None => Err(StorageError::bad_input(format!(
            "crypto instance {instance_id} must set option {option}",
        ))),
    }
}

fn required_base64url_option(
    instance: &CryptoInstanceConfig,
    instance_id: &str,
    option: &str,
) -> Result<Vec<u8>, StorageError> {
    let value = required_string_option(instance, instance_id, option)?;
    BASE64URL_NOPAD.decode(value.as_bytes()).map_err(|_| {
        StorageError::bad_input(format!(
            "crypto instance {instance_id} option {option} must be base64url without padding",
        ))
    })
}

fn openfhe_backend_from_config(
    backend_name: &str,
    backend: &CryptoBackendConfig,
) -> Result<CommandOpenFheBackend, StorageError> {
    let Some(program) = backend.program.as_deref() else {
        return Err(StorageError::bad_input(format!(
            "crypto backend {backend_name} requires program",
        )));
    };
    let Some(expected_sha256_b64) = backend.sha256_b64.as_deref() else {
        return Err(StorageError::bad_input(format!(
            "crypto backend {backend_name} requires sha256_b64 program pin",
        )));
    };
    let mut command_backend =
        CommandOpenFheBackend::new_checked_with_sha256_b64(program, expected_sha256_b64).map_err(
            |err| {
                StorageError::bad_input(format!(
                    "crypto backend {backend_name} program path is invalid: {err}",
                ))
            },
        )?;
    if let Some(timeout_ms) = backend.timeout_ms {
        command_backend = command_backend.with_timeout(Duration::from_millis(timeout_ms));
    }
    let pool_size = match backend.kind.as_str() {
        "process_pool" => backend.size.unwrap_or(1),
        "process" => 1,
        kind => {
            return Err(StorageError::bad_input(format!(
                "crypto backend {backend_name} has unsupported kind {kind}",
            )));
        }
    };
    let Some(pool_size) = NonZeroUsize::new(pool_size) else {
        return Err(StorageError::bad_input(format!(
            "crypto backend {backend_name} size must be at least 1",
        )));
    };
    Ok(command_backend.with_pool_size(pool_size))
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
    params.validate().map_err(|err| {
        StorageError::bad_input(format!(
            "collection {collection_name} crypto config is invalid: {err}"
        ))
    })?;
    validate_collection_crypto_runtime_inner(settings, collection_name, &params)
}

pub fn validate_collection_crypto_runtime(
    settings: &Settings,
    collection_name: &str,
    params: &CollectionParams,
) -> Result<(), StorageError> {
    params.validate().map_err(|err| {
        StorageError::bad_input(format!(
            "collection {collection_name} crypto config is invalid: {err}"
        ))
    })?;
    validate_collection_crypto_runtime_inner(settings, collection_name, params)
}

fn validate_collection_crypto_runtime_inner(
    settings: &Settings,
    collection_name: &str,
    params: &CollectionParams,
) -> Result<(), StorageError> {
    if let Some(encryption) = &params.encryption {
        if settings.cluster.enabled {
            for rule in &encryption.rules {
                let EncryptionSelector::PayloadPaths { .. } = &rule.selector else {
                    continue;
                };
                let Some(instance) = settings.crypto.instances.get(&rule.instance) else {
                    continue;
                };
                if instance.provider == PAYLOAD_CLIENT_AEAD_PROVIDER {
                    return Err(StorageError::bad_input(format!(
                        "collection {collection_name} rule {} uses {PAYLOAD_CLIENT_AEAD_PROVIDER}, \
                         which requires a cluster-wide nonce replay ledger when cluster.enabled=true",
                        rule.id,
                    )));
                }
            }
        }
        return validate_generic_collection_crypto_runtime(
            &effective_settings(settings),
            collection_name,
            params,
            encryption,
        );
    }

    let Some(ckks) = params.ckks.as_ref() else {
        return Ok(());
    };
    let _ = ckks;
    Err(StorageError::bad_input(format!(
        "collection {collection_name} legacy ckks config is unsupported; use collection encryption rules"
    )))
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
    settings.crypto.clone()
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
                "has_fd": material.fd.is_some(),
                "has_value_b64": material.value_b64.is_some(),
                "vault_field": material.vault_field,
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

    let view = json!({
        "version": 1,
        "crypto": {
            "allow_inline_key_material": settings.crypto.allow_inline_key_material,
            "instances": instances,
            "materials": materials,
            "backends": backends,
        },
    });
    let canonical = serde_json::to_vec(&view)
        .expect("serializing sanitized crypto runtime capability fingerprint cannot fail");
    let digest = Sha256::digest(&canonical);
    BASE64URL_NOPAD.encode(&digest)
}

#[cfg(test)]
fn validate_crypto_runtime_capability_parity<'a>(
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
        return Err(CryptoSetupError::LegacyCkksRuntimeUnsupported);
    }

    Ok(())
}

fn validate_crypto_settings(settings: &CryptoSettings) -> Result<(), CryptoSetupError> {
    for material_name in settings.materials.keys() {
        if !is_crypto_identifier(material_name) {
            return Err(CryptoSetupError::InvalidMaterialName {
                material: material_name.clone(),
            });
        }
    }
    for backend_name in settings.backends.keys() {
        if !is_crypto_identifier(backend_name) {
            return Err(CryptoSetupError::InvalidBackendName {
                backend: backend_name.clone(),
            });
        }
    }
    for instance_name in settings.instances.keys() {
        if !is_crypto_identifier(instance_name) {
            return Err(CryptoSetupError::InvalidInstanceName {
                instance: instance_name.clone(),
            });
        }
    }

    for (material_name, material) in &settings.materials {
        validate_material(material_name, material, settings.allow_inline_key_material)?;
    }

    for (material_name, material) in &settings.materials {
        if material.kind != WRAPPED_SYMMETRIC_KEY_32_KIND {
            continue;
        }
        if wrapped_resource_key_state(material) == RESOURCE_KEY_STATE_DESTROYED {
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
        if !is_crypto_identifier(&instance.provider) {
            return Err(CryptoSetupError::InvalidInstanceOption {
                instance: instance_name.clone(),
                option: "provider".to_string(),
                reason: format!("invalid provider {}", instance.provider),
            });
        }
        if !matches!(
            instance.provider.as_str(),
            PAYLOAD_AES_GCM_PROVIDER
                | PAYLOAD_CLIENT_AEAD_PROVIDER
                | VECTOR_OPENFHE_CKKS_PROVIDER
                | METADATA_BLIND_INDEX_PROVIDER
        ) {
            return Err(CryptoSetupError::InvalidInstanceOption {
                instance: instance_name.clone(),
                option: "provider".to_string(),
                reason: format!("unsupported provider {}", instance.provider),
            });
        }
        if instance.provider == PAYLOAD_CLIENT_AEAD_PROVIDER
            && (!instance.materials.is_empty() || instance.backend_ref.is_some())
        {
            return Err(CryptoSetupError::InvalidInstanceOption {
                instance: instance_name.clone(),
                option: "provider".to_string(),
                reason: "payload/client-aead@v1 must not configure server materials or backend"
                    .to_string(),
            });
        }
        if instance.provider == PAYLOAD_CLIENT_AEAD_PROVIDER {
            if let Some(option) =
                unsupported_instance_option(&instance.options, CLIENT_AEAD_ALLOWED_OPTIONS)
            {
                return Err(CryptoSetupError::InvalidInstanceOption {
                    instance: instance_name.clone(),
                    option,
                    reason: "unsupported option for payload/client-aead@v1".to_string(),
                });
            }
            let configured_key_id = match instance.options.get("key_id") {
                None | Some(Value::Null) => None,
                Some(Value::String(key_id)) if is_crypto_identifier(key_id) => {
                    Some(key_id.as_str())
                }
                Some(_) => {
                    return Err(CryptoSetupError::InvalidInstanceOption {
                        instance: instance_name.clone(),
                        option: "key_id".to_string(),
                        reason: "expected a crypto identifier string".to_string(),
                    });
                }
            };
            match instance.options.get(KEY_ID_REQUIRED_OPTION) {
                None | Some(Value::Null) | Some(Value::Bool(true)) => {}
                Some(Value::Bool(false)) => {
                    return Err(CryptoSetupError::InvalidInstanceOption {
                        instance: instance_name.clone(),
                        option: KEY_ID_REQUIRED_OPTION.to_string(),
                        reason: "payload/client-aead@v1 must require key_id".to_string(),
                    });
                }
                Some(_) => {
                    return Err(CryptoSetupError::InvalidInstanceOption {
                        instance: instance_name.clone(),
                        option: KEY_ID_REQUIRED_OPTION.to_string(),
                        reason: "expected a boolean".to_string(),
                    });
                }
            }
            let expected_rk_id = match instance.options.get(EXPECTED_RK_ID_OPTION) {
                Some(Value::String(expected_rk_id)) if is_crypto_identifier(expected_rk_id) => {
                    expected_rk_id.as_str()
                }
                Some(Value::String(_)) | Some(_) => {
                    return Err(CryptoSetupError::InvalidInstanceOption {
                        instance: instance_name.clone(),
                        option: EXPECTED_RK_ID_OPTION.to_string(),
                        reason: "expected a crypto identifier string".to_string(),
                    });
                }
                None => {
                    return Err(CryptoSetupError::InvalidInstanceOption {
                        instance: instance_name.clone(),
                        option: EXPECTED_RK_ID_OPTION.to_string(),
                        reason: "missing expected_rk_id".to_string(),
                    });
                }
            };
            if let Some(configured_key_id) = configured_key_id
                && configured_key_id != expected_rk_id
            {
                return Err(CryptoSetupError::InvalidInstanceOption {
                    instance: instance_name.clone(),
                    option: EXPECTED_RK_ID_OPTION.to_string(),
                    reason: "expected_rk_id must match key_id when both are configured".to_string(),
                });
            }
            let min_rk_epoch = match instance.options.get(MIN_RK_EPOCH_OPTION) {
                Some(Value::Number(min_rk_epoch)) => min_rk_epoch.as_u64(),
                Some(_) => None,
                None => {
                    return Err(CryptoSetupError::InvalidInstanceOption {
                        instance: instance_name.clone(),
                        option: MIN_RK_EPOCH_OPTION.to_string(),
                        reason: "missing min_rk_epoch".to_string(),
                    });
                }
            };
            let Some(min_rk_epoch) = min_rk_epoch else {
                return Err(CryptoSetupError::InvalidInstanceOption {
                    instance: instance_name.clone(),
                    option: MIN_RK_EPOCH_OPTION.to_string(),
                    reason: "expected an unsigned integer".to_string(),
                });
            };
            let max_rk_epoch = match instance.options.get(MAX_RK_EPOCH_OPTION) {
                Some(Value::Number(max_rk_epoch)) => max_rk_epoch.as_u64(),
                Some(_) => None,
                None => {
                    return Err(CryptoSetupError::InvalidInstanceOption {
                        instance: instance_name.clone(),
                        option: MAX_RK_EPOCH_OPTION.to_string(),
                        reason: "missing max_rk_epoch".to_string(),
                    });
                }
            };
            let Some(max_rk_epoch) = max_rk_epoch else {
                return Err(CryptoSetupError::InvalidInstanceOption {
                    instance: instance_name.clone(),
                    option: MAX_RK_EPOCH_OPTION.to_string(),
                    reason: "expected an unsigned integer".to_string(),
                });
            };
            if min_rk_epoch != max_rk_epoch {
                return Err(CryptoSetupError::InvalidInstanceOption {
                    instance: instance_name.clone(),
                    option: MAX_RK_EPOCH_OPTION.to_string(),
                    reason: "client payload provider must pin one active rk_epoch".to_string(),
                });
            }
            client_payload_signature_verifier(instance, instance_name).map_err(|err| {
                CryptoSetupError::InvalidInstanceOption {
                    instance: instance_name.clone(),
                    option: "signature".to_string(),
                    reason: err.to_string(),
                }
            })?;
        }
        if instance.provider == METADATA_BLIND_INDEX_PROVIDER {
            if !instance.materials.is_empty() || instance.backend_ref.is_some() {
                return Err(CryptoSetupError::InvalidInstanceOption {
                    instance: instance_name.clone(),
                    option: "provider".to_string(),
                    reason:
                        "metadata/blind-index-hmac@v1 stores client-generated tokens and must not configure server materials or backend"
                            .to_string(),
                });
            }
            if let Some(option) =
                unsupported_instance_option(&instance.options, METADATA_BLIND_INDEX_ALLOWED_OPTIONS)
            {
                return Err(CryptoSetupError::InvalidInstanceOption {
                    instance: instance_name.clone(),
                    option,
                    reason: "unsupported option for metadata/blind-index-hmac@v1".to_string(),
                });
            }
            let configured_key_id = match instance.options.get("key_id") {
                None | Some(Value::Null) => None,
                Some(Value::String(key_id)) if is_crypto_identifier(key_id) => {
                    Some(key_id.as_str())
                }
                Some(_) => {
                    return Err(CryptoSetupError::InvalidInstanceOption {
                        instance: instance_name.clone(),
                        option: "key_id".to_string(),
                        reason: "expected a crypto identifier string".to_string(),
                    });
                }
            };
            let expected_rk_id = match instance.options.get(EXPECTED_RK_ID_OPTION) {
                Some(Value::String(expected_rk_id)) if is_crypto_identifier(expected_rk_id) => {
                    expected_rk_id.as_str()
                }
                Some(_) => {
                    return Err(CryptoSetupError::InvalidInstanceOption {
                        instance: instance_name.clone(),
                        option: EXPECTED_RK_ID_OPTION.to_string(),
                        reason: "expected a crypto identifier string".to_string(),
                    });
                }
                None => {
                    return Err(CryptoSetupError::InvalidInstanceOption {
                        instance: instance_name.clone(),
                        option: EXPECTED_RK_ID_OPTION.to_string(),
                        reason: "missing expected_rk_id".to_string(),
                    });
                }
            };
            if let Some(configured_key_id) = configured_key_id
                && configured_key_id != expected_rk_id
            {
                return Err(CryptoSetupError::InvalidInstanceOption {
                    instance: instance_name.clone(),
                    option: EXPECTED_RK_ID_OPTION.to_string(),
                    reason: "expected_rk_id must match key_id when both are configured".to_string(),
                });
            }
            let min_rk_epoch = match instance.options.get(MIN_RK_EPOCH_OPTION) {
                Some(Value::Number(min_rk_epoch)) => min_rk_epoch.as_u64(),
                Some(_) => None,
                None => {
                    return Err(CryptoSetupError::InvalidInstanceOption {
                        instance: instance_name.clone(),
                        option: MIN_RK_EPOCH_OPTION.to_string(),
                        reason: "missing min_rk_epoch".to_string(),
                    });
                }
            };
            let Some(min_rk_epoch) = min_rk_epoch else {
                return Err(CryptoSetupError::InvalidInstanceOption {
                    instance: instance_name.clone(),
                    option: MIN_RK_EPOCH_OPTION.to_string(),
                    reason: "expected an unsigned integer".to_string(),
                });
            };
            let max_rk_epoch = match instance.options.get(MAX_RK_EPOCH_OPTION) {
                Some(Value::Number(max_rk_epoch)) => max_rk_epoch.as_u64(),
                Some(_) => None,
                None => {
                    return Err(CryptoSetupError::InvalidInstanceOption {
                        instance: instance_name.clone(),
                        option: MAX_RK_EPOCH_OPTION.to_string(),
                        reason: "missing max_rk_epoch".to_string(),
                    });
                }
            };
            let Some(max_rk_epoch) = max_rk_epoch else {
                return Err(CryptoSetupError::InvalidInstanceOption {
                    instance: instance_name.clone(),
                    option: MAX_RK_EPOCH_OPTION.to_string(),
                    reason: "expected an unsigned integer".to_string(),
                });
            };
            if min_rk_epoch != max_rk_epoch {
                return Err(CryptoSetupError::InvalidInstanceOption {
                    instance: instance_name.clone(),
                    option: MAX_RK_EPOCH_OPTION.to_string(),
                    reason: "metadata blind-index provider must pin one active rk_epoch"
                        .to_string(),
                });
            }
        }
        if instance.provider == PAYLOAD_AES_GCM_PROVIDER
            && let Some(option) =
                unsupported_instance_option(&instance.options, PAYLOAD_AES_GCM_ALLOWED_OPTIONS)
        {
            return Err(CryptoSetupError::InvalidInstanceOption {
                instance: instance_name.clone(),
                option,
                reason: "unsupported option for payload/aes-256-gcm@v1".to_string(),
            });
        }
        if instance.provider == PAYLOAD_AES_GCM_PROVIDER {
            validate_optional_instance_key_id(instance_name, instance, PAYLOAD_AES_GCM_PROVIDER)?;
        }
        if instance.provider == PAYLOAD_AES_GCM_PROVIDER && instance.backend_ref.is_some() {
            return Err(CryptoSetupError::InvalidInstanceOption {
                instance: instance_name.clone(),
                option: "backend_ref".to_string(),
                reason: "payload/aes-256-gcm@v1 must not configure backend_ref".to_string(),
            });
        }
        for (role, material_ref) in &instance.materials {
            if !is_crypto_identifier(role) {
                return Err(CryptoSetupError::InvalidInstanceOption {
                    instance: instance_name.clone(),
                    option: "materials".to_string(),
                    reason: format!("invalid material role {role}"),
                });
            }
            if !settings.materials.contains_key(material_ref) {
                return Err(CryptoSetupError::UnknownMaterial {
                    instance: instance_name.clone(),
                    role: role.clone(),
                    material_ref: material_ref.clone(),
                });
            }
        }
        if instance.provider == PAYLOAD_AES_GCM_PROVIDER
            && let Some(role) = unsupported_material_role(
                &instance.materials,
                PAYLOAD_AES_GCM_ALLOWED_MATERIAL_ROLES,
            )
        {
            return Err(CryptoSetupError::InvalidInstanceOption {
                instance: instance_name.clone(),
                option: format!("materials.{role}"),
                reason: "unsupported material role for payload/aes-256-gcm@v1".to_string(),
            });
        }
        if instance.provider == VECTOR_OPENFHE_CKKS_PROVIDER
            && let Some(role) = unsupported_material_role(
                &instance.materials,
                VECTOR_OPENFHE_CKKS_ALLOWED_MATERIAL_ROLES,
            )
        {
            return Err(CryptoSetupError::InvalidInstanceOption {
                instance: instance_name.clone(),
                option: format!("materials.{role}"),
                reason: "unsupported material role for vector/openfhe-ckks@v1".to_string(),
            });
        }
        if matches!(
            instance.provider.as_str(),
            PAYLOAD_AES_GCM_PROVIDER | VECTOR_OPENFHE_CKKS_PROVIDER
        ) && !instance.materials.contains_key(PAYLOAD_SYM_KEY_ROLE)
        {
            return Err(CryptoSetupError::InvalidInstanceOption {
                instance: instance_name.clone(),
                option: "materials".to_string(),
                reason: format!("{} must configure materials.sym_key", instance.provider),
            });
        }
        if matches!(
            instance.provider.as_str(),
            PAYLOAD_AES_GCM_PROVIDER | VECTOR_OPENFHE_CKKS_PROVIDER
        ) && let Some(active_material_ref) = instance.materials.get(PAYLOAD_SYM_KEY_ROLE)
            && let Some(active_material) = settings.materials.get(active_material_ref)
            && active_material.kind == WRAPPED_SYMMETRIC_KEY_32_KIND
            && wrapped_resource_key_state(active_material) != RESOURCE_KEY_STATE_ACTIVE
        {
            return Err(CryptoSetupError::InvalidInstanceOption {
                instance: instance_name.clone(),
                option: "materials".to_string(),
                reason: format!(
                    "active sym_key material {active_material_ref} must have state active"
                ),
            });
        }
        if instance.provider == VECTOR_OPENFHE_CKKS_PROVIDER && instance.backend_ref.is_none() {
            return Err(CryptoSetupError::InvalidInstanceOption {
                instance: instance_name.clone(),
                option: "backend_ref".to_string(),
                reason: "vector/openfhe-ckks@v1 must configure backend_ref".to_string(),
            });
        }
        if instance.provider == VECTOR_OPENFHE_CKKS_PROVIDER
            && let Some(option) =
                unsupported_instance_option(&instance.options, VECTOR_OPENFHE_CKKS_ALLOWED_OPTIONS)
        {
            return Err(CryptoSetupError::InvalidInstanceOption {
                instance: instance_name.clone(),
                option,
                reason: "unsupported option for vector/openfhe-ckks@v1".to_string(),
            });
        }
        if instance.provider == VECTOR_OPENFHE_CKKS_PROVIDER {
            validate_optional_instance_key_id(
                instance_name,
                instance,
                VECTOR_OPENFHE_CKKS_PROVIDER,
            )?;
            match instance.options.get(CKKS_PROFILE_OPTION) {
                Some(Value::String(profile))
                    if profile == CKKS_PROFILE_OPENFHE_128_N16384_D4_SCALE50 => {}
                Some(Value::String(_)) => {
                    return Err(CryptoSetupError::InvalidInstanceOption {
                        instance: instance_name.clone(),
                        option: CKKS_PROFILE_OPTION.to_string(),
                        reason: format!(
                            "expected allowlisted profile {CKKS_PROFILE_OPENFHE_128_N16384_D4_SCALE50}"
                        ),
                    });
                }
                Some(_) => {
                    return Err(CryptoSetupError::InvalidInstanceOption {
                        instance: instance_name.clone(),
                        option: CKKS_PROFILE_OPTION.to_string(),
                        reason: "expected a string".to_string(),
                    });
                }
                None => {
                    return Err(CryptoSetupError::InvalidInstanceOption {
                        instance: instance_name.clone(),
                        option: CKKS_PROFILE_OPTION.to_string(),
                        reason: "missing profile".to_string(),
                    });
                }
            }
            for option in [CKKS_CRYPTO_CONTEXT_B64_OPTION, CKKS_PUBLIC_KEY_B64_OPTION] {
                let Some(Value::String(encoded)) = instance.options.get(option) else {
                    return Err(CryptoSetupError::InvalidInstanceOption {
                        instance: instance_name.clone(),
                        option: option.to_string(),
                        reason: "expected a base64url string".to_string(),
                    });
                };
                let decoded = BASE64URL_NOPAD.decode(encoded.as_bytes()).map_err(|_| {
                    CryptoSetupError::InvalidInstanceOption {
                        instance: instance_name.clone(),
                        option: option.to_string(),
                        reason: "expected base64url without padding".to_string(),
                    }
                })?;
                if decoded.is_empty() {
                    return Err(CryptoSetupError::InvalidInstanceOption {
                        instance: instance_name.clone(),
                        option: option.to_string(),
                        reason: "decoded value must not be empty".to_string(),
                    });
                }
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

        if matches!(
            instance.provider.as_str(),
            PAYLOAD_AES_GCM_PROVIDER | VECTOR_OPENFHE_CKKS_PROVIDER
        ) {
            let Some(material_fingerprint_id) =
                instance.options.get(MATERIAL_FINGERPRINT_ID_OPTION)
            else {
                return Err(CryptoSetupError::InvalidInstanceOption {
                    instance: instance_name.clone(),
                    option: MATERIAL_FINGERPRINT_ID_OPTION.to_string(),
                    reason: "missing material_fingerprint_id".to_string(),
                });
            };
            let Some(material_fingerprint_id) = material_fingerprint_id.as_str() else {
                return Err(CryptoSetupError::InvalidInstanceOption {
                    instance: instance_name.clone(),
                    option: MATERIAL_FINGERPRINT_ID_OPTION.to_string(),
                    reason: "expected a string".to_string(),
                });
            };
            if !is_crypto_identifier(material_fingerprint_id) {
                return Err(CryptoSetupError::InvalidInstanceOption {
                    instance: instance_name.clone(),
                    option: MATERIAL_FINGERPRINT_ID_OPTION.to_string(),
                    reason: "invalid material_fingerprint_id".to_string(),
                });
            }
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
    if !matches!(
        material.kind.as_str(),
        SYMMETRIC_KEY_32_KIND | WRAPPING_KEY_32_KIND
    ) {
        return Err(CryptoSetupError::UnsupportedMaterialKind {
            material: material_name.to_string(),
            kind: material.kind.clone(),
        });
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
        + usize::from(material.fd.is_some())
        + usize::from(material.value_b64.is_some());

    if material.source.as_deref() == Some("vault_kv2") {
        if material.env.is_none()
            || material.path.is_none()
            || material.vault_field.is_none()
            || material.fd.is_some()
            || material.value_b64.is_some()
        {
            return Err(CryptoSetupError::MaterialSourceMismatch {
                material: material_name.to_string(),
            });
        }
    } else if configured_sources != 1 || material.vault_field.is_some() {
        return Err(CryptoSetupError::InvalidMaterialSourceCount {
            material: material_name.to_string(),
        });
    }

    match material.source.as_deref() {
        None => Err(CryptoSetupError::MissingMaterialSource {
            material: material_name.to_string(),
        }),
        Some("env")
            if material.env.is_some()
                && material.path.is_none()
                && material.fd.is_none()
                && material.value_b64.is_none() =>
        {
            let env = material.env.as_deref().unwrap();
            if !is_material_env_name(env) {
                return Err(CryptoSetupError::InvalidMaterialFileSource {
                    material: material_name.to_string(),
                    path: format!("env:{env}"),
                    reason: "environment variable name is invalid".to_string(),
                });
            }
            Ok(())
        }
        Some("file")
            if material.path.is_some()
                && material.env.is_none()
                && material.fd.is_none()
                && material.value_b64.is_none() =>
        {
            validate_material_file_source(material_name, material.path.as_deref().unwrap())?;
            Ok(())
        }
        Some("unix_socket")
            if material.path.is_some()
                && material.env.is_none()
                && material.fd.is_none()
                && material.value_b64.is_none() =>
        {
            validate_material_unix_socket_source(material_name, material.path.as_deref().unwrap())?;
            Ok(())
        }
        Some("vault_kv2")
            if material.env.is_some()
                && material.path.is_some()
                && material.vault_field.is_some()
                && material.fd.is_none()
                && material.value_b64.is_none() =>
        {
            validate_material_vault_kv2_source(
                material_name,
                material.path.as_deref().unwrap(),
                material.env.as_deref().unwrap(),
                material.vault_field.as_deref(),
            )?;
            Ok(())
        }
        Some("fd")
            if material.fd.is_some()
                && material.env.is_none()
                && material.path.is_none()
                && material.value_b64.is_none() =>
        {
            validate_material_fd_source(material_name, material.fd.unwrap())?;
            Ok(())
        }
        Some("inline")
            if material.value_b64.is_some()
                && material.env.is_none()
                && material.fd.is_none()
                && material.path.is_none() =>
        {
            if allow_inline_key_material {
                let decoded = BASE64URL_NOPAD
                    .decode(material.value_b64.as_deref().unwrap().trim().as_bytes());
                let decoded = decoded.map_err(|_| CryptoSetupError::InvalidMaterialFileSource {
                    material: material_name.to_string(),
                    path: "inline".to_string(),
                    reason: "inline material must be base64url without padding".to_string(),
                })?;
                if decoded.len() != 32 {
                    return Err(CryptoSetupError::InvalidMaterialFileSource {
                        material: material_name.to_string(),
                        path: "inline".to_string(),
                        reason: "inline material must decode to exactly 32 bytes".to_string(),
                    });
                }
                Ok(())
            } else {
                Err(CryptoSetupError::InlineMaterialDisabled {
                    material: material_name.to_string(),
                })
            }
        }
        Some("env" | "file" | "unix_socket" | "vault_kv2" | "fd" | "inline") => {
            Err(CryptoSetupError::MaterialSourceMismatch {
                material: material_name.to_string(),
            })
        }
        Some(source) => Err(CryptoSetupError::UnsupportedMaterialSource {
            material: material_name.to_string(),
            material_source: source.to_string(),
        }),
    }?;

    Ok(())
}

fn validate_material_fd_source(material_name: &str, fd: i32) -> Result<(), CryptoSetupError> {
    if fd < 0 {
        return Err(CryptoSetupError::InvalidMaterialFileSource {
            material: material_name.to_string(),
            path: format!("fd:{fd}"),
            reason: "fd must be non-negative".to_string(),
        });
    }

    #[cfg(unix)]
    {
        let result = unsafe { nix::libc::fcntl(fd, nix::libc::F_GETFD) };
        if result < 0 {
            return Err(CryptoSetupError::InvalidMaterialFileSource {
                material: material_name.to_string(),
                path: format!("fd:{fd}"),
                reason: "fd is not open".to_string(),
            });
        }
        if result & nix::libc::FD_CLOEXEC == 0 {
            let set_result =
                unsafe { nix::libc::fcntl(fd, nix::libc::F_SETFD, result | nix::libc::FD_CLOEXEC) };
            if set_result < 0 {
                return Err(CryptoSetupError::InvalidMaterialFileSource {
                    material: material_name.to_string(),
                    path: format!("fd:{fd}"),
                    reason: "fd close-on-exec flag could not be set".to_string(),
                });
            }
        }
    }

    #[cfg(not(unix))]
    {
        return Err(CryptoSetupError::InvalidMaterialFileSource {
            material: material_name.to_string(),
            path: format!("fd:{fd}"),
            reason: "fd source is only supported on Unix".to_string(),
        });
    }

    Ok(())
}

fn validate_material_file_source(material_name: &str, path: &str) -> Result<(), CryptoSetupError> {
    let material_path = Path::new(path);
    if !material_path.is_absolute() {
        return Err(CryptoSetupError::InvalidMaterialFileSource {
            material: material_name.to_string(),
            path: path.to_string(),
            reason: "path must be absolute".to_string(),
        });
    }

    let link_metadata = fs::symlink_metadata(material_path).map_err(|err| {
        CryptoSetupError::InvalidMaterialFileSource {
            material: material_name.to_string(),
            path: path.to_string(),
            reason: format!("failed to inspect file: {err}"),
        }
    })?;
    if link_metadata.file_type().is_symlink() || !link_metadata.is_file() {
        return Err(CryptoSetupError::InvalidMaterialFileSource {
            material: material_name.to_string(),
            path: path.to_string(),
            reason: "must be a regular non-symlink file".to_string(),
        });
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};

        let effective_uid = qdrant_effective_uid();
        let owner = link_metadata.uid();
        if owner != 0 && owner != effective_uid {
            return Err(CryptoSetupError::InvalidMaterialFileSource {
                material: material_name.to_string(),
                path: path.to_string(),
                reason: "must be owned by root or the qdrant process user".to_string(),
            });
        }

        if link_metadata.permissions().mode() & 0o077 != 0 {
            return Err(CryptoSetupError::InvalidMaterialFileSource {
                material: material_name.to_string(),
                path: path.to_string(),
                reason: "must not be group/world accessible".to_string(),
            });
        }

        validate_material_parent_directories(material_name, material_path, path, effective_uid)?;
    }

    Ok(())
}

fn validate_material_unix_socket_source(
    material_name: &str,
    path: &str,
) -> Result<(), CryptoSetupError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};

        let material_path = Path::new(path);
        if !material_path.is_absolute() {
            return Err(CryptoSetupError::InvalidMaterialFileSource {
                material: material_name.to_string(),
                path: path.to_string(),
                reason: "path must be absolute".to_string(),
            });
        }

        let link_metadata = fs::symlink_metadata(material_path).map_err(|err| {
            CryptoSetupError::InvalidMaterialFileSource {
                material: material_name.to_string(),
                path: path.to_string(),
                reason: format!("failed to inspect Unix socket: {err}"),
            }
        })?;
        let file_type = link_metadata.file_type();
        if file_type.is_symlink() || !file_type.is_socket() {
            return Err(CryptoSetupError::InvalidMaterialFileSource {
                material: material_name.to_string(),
                path: path.to_string(),
                reason: "must be a regular non-symlink Unix socket".to_string(),
            });
        }

        let effective_uid = qdrant_effective_uid();
        let owner = link_metadata.uid();
        if owner != 0 && owner != effective_uid {
            return Err(CryptoSetupError::InvalidMaterialFileSource {
                material: material_name.to_string(),
                path: path.to_string(),
                reason: "must be owned by root or the qdrant process user".to_string(),
            });
        }

        if link_metadata.permissions().mode() & 0o077 != 0 {
            return Err(CryptoSetupError::InvalidMaterialFileSource {
                material: material_name.to_string(),
                path: path.to_string(),
                reason: "must not be group/world accessible".to_string(),
            });
        }

        validate_material_parent_directories(material_name, material_path, path, effective_uid)?;
        Ok(())
    }

    #[cfg(not(unix))]
    {
        Err(CryptoSetupError::InvalidMaterialFileSource {
            material: material_name.to_string(),
            path: path.to_string(),
            reason: "unix_socket source is only supported on Unix".to_string(),
        })
    }
}

fn validate_material_vault_kv2_source(
    material_name: &str,
    url: &str,
    token_env: &str,
    vault_field: Option<&str>,
) -> Result<(), CryptoSetupError> {
    let parsed =
        reqwest::Url::parse(url).map_err(|err| CryptoSetupError::InvalidMaterialFileSource {
            material: material_name.to_string(),
            path: url.to_string(),
            reason: format!("Vault KV v2 URL is invalid: {err}"),
        })?;
    let is_loopback_http = parsed.scheme() == "http"
        && parsed.host_str().is_some_and(|host| {
            host.eq_ignore_ascii_case("localhost") || host == "127.0.0.1" || host == "::1"
        });
    if parsed.scheme() != "https" && !is_loopback_http {
        return Err(CryptoSetupError::InvalidMaterialFileSource {
            material: material_name.to_string(),
            path: url.to_string(),
            reason: "Vault KV v2 URL must use https, except loopback http for tests/dev"
                .to_string(),
        });
    }
    if parsed.path().is_empty() || parsed.path() == "/" {
        return Err(CryptoSetupError::InvalidMaterialFileSource {
            material: material_name.to_string(),
            path: url.to_string(),
            reason: "Vault KV v2 URL must include the secret data path".to_string(),
        });
    }
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err(CryptoSetupError::InvalidMaterialFileSource {
            material: material_name.to_string(),
            path: url.to_string(),
            reason: "Vault KV v2 URL must not include credentials".to_string(),
        });
    }
    if parsed.query().is_some() || parsed.fragment().is_some() {
        return Err(CryptoSetupError::InvalidMaterialFileSource {
            material: material_name.to_string(),
            path: url.to_string(),
            reason: "Vault KV v2 URL must not include query or fragment components".to_string(),
        });
    }
    if !is_material_env_name(token_env) {
        return Err(CryptoSetupError::InvalidMaterialFileSource {
            material: material_name.to_string(),
            path: url.to_string(),
            reason: "Vault token env name is invalid".to_string(),
        });
    }
    let Some(vault_field) = vault_field else {
        return Err(CryptoSetupError::InvalidMaterialFileSource {
            material: material_name.to_string(),
            path: url.to_string(),
            reason: "vault_field is required for Vault KV v2 material".to_string(),
        });
    };
    if vault_field.is_empty()
        || vault_field.len() > 128
        || !vault_field
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'-'))
    {
        return Err(CryptoSetupError::InvalidMaterialFileSource {
            material: material_name.to_string(),
            path: url.to_string(),
            reason: "vault_field is invalid".to_string(),
        });
    }

    Ok(())
}

fn is_material_env_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
}

#[cfg(unix)]
fn qdrant_effective_uid() -> u32 {
    unsafe extern "C" {
        fn geteuid() -> u32;
    }

    unsafe { geteuid() }
}

#[cfg(unix)]
fn validate_material_parent_directories(
    material_name: &str,
    material_path: &Path,
    path: &str,
    effective_uid: u32,
) -> Result<(), CryptoSetupError> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    let mut parent = material_path.parent();
    while let Some(directory) = parent {
        let directory_metadata = fs::symlink_metadata(directory).map_err(|err| {
            CryptoSetupError::InvalidMaterialFileSource {
                material: material_name.to_string(),
                path: path.to_string(),
                reason: format!(
                    "failed to inspect parent directory {}: {err}",
                    directory.display()
                ),
            }
        })?;
        if directory_metadata.file_type().is_symlink() || !directory_metadata.is_dir() {
            return Err(CryptoSetupError::InvalidMaterialFileSource {
                material: material_name.to_string(),
                path: path.to_string(),
                reason: format!(
                    "parent path must be a regular directory: {}",
                    directory.display()
                ),
            });
        }
        if directory_metadata.permissions().mode() & 0o022 != 0 {
            return Err(CryptoSetupError::InvalidMaterialFileSource {
                material: material_name.to_string(),
                path: path.to_string(),
                reason: format!(
                    "parent directory must not be group/world-writable: {}",
                    directory.display()
                ),
            });
        }
        let owner = directory_metadata.uid();
        if owner != 0 && owner != effective_uid {
            return Err(CryptoSetupError::InvalidMaterialFileSource {
                material: material_name.to_string(),
                path: path.to_string(),
                reason: format!(
                    "parent directory must be owned by root or the qdrant process user: {}",
                    directory.display()
                ),
            });
        }
        parent = directory.parent();
    }

    Ok(())
}

fn validate_wrapped_resource_key_material(
    material_name: &str,
    material: &CryptoMaterialConfig,
) -> Result<(), CryptoSetupError> {
    if material.source.is_some()
        || material.env.is_some()
        || material.path.is_some()
        || material.fd.is_some()
        || material.value_b64.is_some()
        || material.vault_field.is_some()
    {
        return Err(CryptoSetupError::InvalidWrappedMaterial {
            material: material_name.to_string(),
            reason: "wrapped resource keys must not configure direct source/env/path/fd/value_b64/vault_field".to_string(),
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

    if wrapped_resource_key_state(material) == RESOURCE_KEY_STATE_DESTROYED {
        if material.wrapped_by.is_some()
            || material.wrap_algorithm.is_some()
            || material.nonce.is_some()
            || material.wrapped_key_b64.is_some()
        {
            return Err(CryptoSetupError::InvalidWrappedMaterial {
                material: material_name.to_string(),
                reason: "destroyed resource keys must not retain wrapped key material".to_string(),
            });
        }
        return Ok(());
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
        _ => {
            return Err(CryptoSetupError::UnsupportedBackendKind {
                backend: backend_name.to_string(),
                kind: backend.kind.clone(),
            });
        }
    }

    let Some(program) = backend.program.as_deref() else {
        return Err(CryptoSetupError::MissingBackendProgram {
            backend: backend_name.to_string(),
            kind: backend.kind.clone(),
        });
    };
    let Some(expected_sha256_b64) = backend.sha256_b64.as_deref() else {
        return Err(CryptoSetupError::MissingBackendSha256Pin {
            backend: backend_name.to_string(),
        });
    };
    validate_backend_program_path_with_sha256(backend_name, program, Some(expected_sha256_b64))?;

    if backend.timeout_ms == Some(0) {
        return Err(CryptoSetupError::InvalidBackendTimeout {
            backend: backend_name.to_string(),
            reason: "timeout_ms must be at least 1".to_string(),
        });
    }

    Ok(())
}

fn validate_backend_program_path_with_sha256(
    backend_name: &str,
    program: &str,
    expected_sha256_b64: Option<&str>,
) -> Result<(), CryptoSetupError> {
    let invalid_program = || CryptoSetupError::InvalidBackendProgram {
        backend: backend_name.to_string(),
        program: program.to_string(),
    };
    let path_ref = Path::new(program);
    if !path_ref.is_absolute() {
        return Err(invalid_program());
    }

    let metadata = fs::symlink_metadata(program).map_err(|_| invalid_program())?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(invalid_program());
    }

    let metadata = fs::metadata(program).map_err(|_| invalid_program())?;
    if !metadata.is_file() {
        return Err(invalid_program());
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};

        if metadata.permissions().mode() & 0o111 == 0 {
            return Err(invalid_program());
        }
        if metadata.permissions().mode() & 0o022 != 0 {
            return Err(invalid_program());
        }

        let owner = metadata.uid();
        // SAFETY: geteuid has no preconditions and does not dereference pointers.
        let effective_uid = unsafe { nix::libc::geteuid() };
        if owner != 0 && owner != effective_uid {
            return Err(invalid_program());
        }

        let mut parent = path_ref.parent();
        while let Some(directory) = parent {
            let directory_metadata =
                fs::symlink_metadata(directory).map_err(|_| invalid_program())?;
            if directory_metadata.file_type().is_symlink() || !directory_metadata.is_dir() {
                return Err(invalid_program());
            }
            if directory_metadata.permissions().mode() & 0o022 != 0 {
                return Err(invalid_program());
            }

            let directory_owner = directory_metadata.uid();
            if directory_owner != 0 && directory_owner != effective_uid {
                return Err(invalid_program());
            }

            parent = directory.parent();
        }
    }

    if let Some(expected_sha256_b64) = expected_sha256_b64 {
        let expected = BASE64URL_NOPAD
            .decode(expected_sha256_b64.as_bytes())
            .map_err(|_| invalid_program())?;
        if expected.len() != 32 {
            return Err(invalid_program());
        }

        let bytes = read_backend_program_for_sha256(backend_name, program)?;
        let actual = Sha256::digest(&bytes);
        if actual[..] != expected[..] {
            return Err(invalid_program());
        }
    }

    Ok(())
}

#[cfg(unix)]
fn read_backend_program_for_sha256(
    backend_name: &str,
    program: &str,
) -> Result<Vec<u8>, CryptoSetupError> {
    use std::os::unix::fs::OpenOptionsExt;

    let invalid_program = || CryptoSetupError::InvalidBackendProgram {
        backend: backend_name.to_string(),
        program: program.to_string(),
    };

    let mut file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_CLOEXEC | nix::libc::O_NOFOLLOW)
        .open(program)
        .map_err(|_| invalid_program())?;
    if !file.metadata().map_err(|_| invalid_program())?.is_file() {
        return Err(invalid_program());
    }

    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)
        .map_err(|_| invalid_program())?;
    Ok(bytes)
}

#[cfg(not(unix))]
fn read_backend_program_for_sha256(
    backend_name: &str,
    program: &str,
) -> Result<Vec<u8>, CryptoSetupError> {
    fs::read(program).map_err(|_| CryptoSetupError::InvalidBackendProgram {
        backend: backend_name.to_string(),
        program: program.to_string(),
    })
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
                if let Some(option) =
                    unsupported_instance_option(&instance.options, PAYLOAD_AES_GCM_ALLOWED_OPTIONS)
                {
                    return Err(PayloadWriteSetupError::UnsupportedInstanceOption {
                        instance: rule.instance.clone(),
                        option,
                    });
                }
                if let Some(role) = unsupported_material_role(
                    &instance.materials,
                    PAYLOAD_AES_GCM_ALLOWED_MATERIAL_ROLES,
                ) {
                    return Err(PayloadWriteSetupError::UnsupportedInstanceOption {
                        instance: rule.instance.clone(),
                        option: format!("materials.{role}"),
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
                if let Some(option) =
                    unsupported_instance_option(&instance.options, CLIENT_AEAD_ALLOWED_OPTIONS)
                {
                    return Err(PayloadWriteSetupError::UnsupportedInstanceOption {
                        instance: rule.instance.clone(),
                        option,
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
                let signature_verifier =
                    client_payload_signature_verifier(instance, &rule.instance)?;
                rules.push(PayloadWriteRule::ClientEnvelope {
                    policy,
                    expected_key_id: expected_key_id.map(ToOwned::to_owned),
                    expected_rk_id,
                    min_rk_epoch,
                    max_rk_epoch,
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
) -> Result<ClientPayloadSignatureVerifier, PayloadWriteSetupError> {
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

        return Ok(ClientPayloadSignatureVerifier::Registry(public_keys));
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
            Ok(ClientPayloadSignatureVerifier::Single {
                key_id: key_id.to_string(),
                public_key,
            })
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
    params: &CollectionParams,
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
        let EncryptionSelector::MetadataKeys { keys } = &rule.selector else {
            continue;
        };

        if rule.binding.as_deref() != Some(METADATA_EXACT_MATCH_TOKEN_BINDING) {
            return Err(StorageError::bad_input(format!(
                "collection {collection_name} metadata rule {} must use binding {METADATA_EXACT_MATCH_TOKEN_BINDING}",
                rule.id
            )));
        }

        let Some(instance) = runtime_settings.instances.get(&rule.instance) else {
            return Err(StorageError::bad_input(format!(
                "collection {collection_name} references unknown crypto instance {}",
                rule.instance
            )));
        };
        if instance.provider != METADATA_BLIND_INDEX_PROVIDER {
            return Err(StorageError::bad_input(format!(
                "collection {collection_name} rule {} must use provider {METADATA_BLIND_INDEX_PROVIDER}, found {}",
                rule.id, instance.provider
            )));
        }
        if !instance.materials.is_empty() || instance.backend_ref.is_some() {
            return Err(StorageError::bad_input(format!(
                "collection {collection_name} metadata blind-index instance {} must not configure server materials or backend_ref",
                rule.instance
            )));
        }
        if let Some(option) =
            unsupported_instance_option(&instance.options, METADATA_BLIND_INDEX_ALLOWED_OPTIONS)
        {
            return Err(StorageError::bad_input(format!(
                "collection {collection_name} metadata blind-index instance {} uses unsupported option {option}",
                rule.instance
            )));
        }

        let instance_key_id = match instance.options.get("key_id") {
            None | Some(Value::Null) => None,
            Some(Value::String(key_id)) if is_crypto_identifier(key_id) => Some(key_id.as_str()),
            Some(_) => {
                return Err(StorageError::bad_input(format!(
                    "collection {collection_name} metadata blind-index instance {} key_id option must be a crypto identifier string",
                    rule.instance
                )));
            }
        };
        let key_id = match (encryption.key_id.as_deref(), instance_key_id) {
            (Some(collection_key_id), Some(runtime_key_id))
                if collection_key_id != runtime_key_id =>
            {
                return Err(StorageError::bad_input(format!(
                    "collection {collection_name} key id does not match metadata blind-index instance {} key id",
                    rule.instance
                )));
            }
            (Some(collection_key_id), _) => collection_key_id,
            (None, Some(runtime_key_id)) => runtime_key_id,
            (None, None) => {
                return Err(StorageError::bad_input(format!(
                    "collection {collection_name} metadata blind-index instance {} is missing a key id",
                    rule.instance
                )));
            }
        };

        let expected_rk_id = match instance.options.get(EXPECTED_RK_ID_OPTION) {
            Some(Value::String(value)) if is_crypto_identifier(value) => value.as_str(),
            Some(_) => {
                return Err(StorageError::bad_input(format!(
                    "collection {collection_name} metadata blind-index instance {} expected_rk_id option must be a crypto identifier string",
                    rule.instance
                )));
            }
            None => {
                return Err(StorageError::bad_input(format!(
                    "collection {collection_name} metadata blind-index instance {} must set expected_rk_id",
                    rule.instance
                )));
            }
        };
        if expected_rk_id != key_id {
            return Err(StorageError::bad_input(format!(
                "collection {collection_name} metadata blind-index instance {} expected_rk_id must match key id",
                rule.instance
            )));
        }

        let min_rk_epoch = match instance.options.get(MIN_RK_EPOCH_OPTION) {
            Some(Value::Number(value)) => value.as_u64(),
            Some(_) | None => None,
        };
        let max_rk_epoch = match instance.options.get(MAX_RK_EPOCH_OPTION) {
            Some(Value::Number(value)) => value.as_u64(),
            Some(_) | None => None,
        };
        let (Some(min_rk_epoch), Some(max_rk_epoch)) = (min_rk_epoch, max_rk_epoch) else {
            return Err(StorageError::bad_input(format!(
                "collection {collection_name} metadata blind-index instance {} must pin min_rk_epoch and max_rk_epoch",
                rule.instance
            )));
        };
        if min_rk_epoch != max_rk_epoch {
            return Err(StorageError::bad_input(format!(
                "collection {collection_name} metadata blind-index instance {} must pin one active rk_epoch",
                rule.instance
            )));
        }

        for key in keys {
            key.parse::<JsonPath>().map_err(|err| {
                StorageError::bad_input(format!(
                    "collection {collection_name} metadata blind-index key '{key}' is invalid: {err:?}",
                ))
            })?;
        }
    }

    for rule in &encryption.rules {
        let EncryptionSelector::VectorNames { names } = &rule.selector else {
            continue;
        };

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
        if let Some(role) = unsupported_material_role(
            &instance.materials,
            VECTOR_OPENFHE_CKKS_ALLOWED_MATERIAL_ROLES,
        ) {
            return Err(StorageError::bad_input(format!(
                "collection {collection_name} vector crypto instance {} uses unsupported material role {role}",
                rule.instance
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
        let crypto_context =
            required_base64url_option(instance, &rule.instance, CKKS_CRYPTO_CONTEXT_B64_OPTION)?;
        let public_key =
            required_base64url_option(instance, &rule.instance, CKKS_PUBLIC_KEY_B64_OPTION)?;
        CkksPublicMaterial::new(crypto_context, public_key).map_err(|err| {
            StorageError::bad_input(format!(
                "collection {collection_name} vector crypto instance {} public material is invalid: {err}",
                rule.instance
            ))
        })?;

        let instance_key_id = match instance.options.get("key_id") {
            None | Some(Value::Null) => None,
            Some(Value::String(key_id)) if is_crypto_identifier(key_id) => Some(key_id.as_str()),
            Some(_) => {
                return Err(StorageError::bad_input(format!(
                    "collection {collection_name} vector crypto instance {} key_id option must be a crypto identifier string",
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
        for vector_name in names {
            let _distance = ckks_vector_distance(params, collection_name, vector_name)?;
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

#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "reserved for the admin MK rotation operation that rewraps all active/retired resource keys for one wrapping key"
    )
)]
pub fn rewrap_runtime_resource_key_materials_by_master_key(
    runtime_settings: &CryptoSettings,
    old_wrapped_by: &str,
    new_wrapped_by: &str,
) -> Result<HashMap<String, CryptoMaterialConfig>, PayloadWriteSetupError> {
    if old_wrapped_by == new_wrapped_by {
        return Err(PayloadWriteSetupError::InvalidWrappedMaterial {
            material: old_wrapped_by.to_string(),
            reason: "old and new wrapping key material must differ".to_string(),
        });
    }

    let mut rewrapped = HashMap::new();
    for (material_name, material) in &runtime_settings.materials {
        if material.kind == WRAPPED_SYMMETRIC_KEY_32_KIND
            && material.wrapped_by.as_deref() == Some(old_wrapped_by)
            && matches!(
                wrapped_resource_key_state(material),
                RESOURCE_KEY_STATE_ACTIVE | RESOURCE_KEY_STATE_RETIRED
            )
        {
            rewrapped.insert(
                material_name.clone(),
                rewrap_runtime_resource_key_material(
                    runtime_settings,
                    material_name,
                    new_wrapped_by,
                )?,
            );
        }
    }

    if rewrapped.is_empty() {
        return Err(PayloadWriteSetupError::InvalidWrappedMaterial {
            material: old_wrapped_by.to_string(),
            reason:
                "no active or retired wrapped resource keys reference this wrapping key material"
                    .to_string(),
        });
    }

    Ok(rewrapped)
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
    if material.source.is_none() {
        return Err(PayloadWriteSetupError::MissingMaterialSource {
            material: material_name.to_string(),
        });
    }

    let source = material.source.as_deref().unwrap();
    let configured_sources = usize::from(material.env.is_some())
        + usize::from(material.path.is_some())
        + usize::from(material.fd.is_some())
        + usize::from(material.value_b64.is_some());
    let valid_source_shape = match source {
        "vault_kv2" => {
            material.env.is_some()
                && material.path.is_some()
                && material.vault_field.is_some()
                && material.fd.is_none()
                && material.value_b64.is_none()
        }
        "env" | "file" | "unix_socket" | "fd" | "inline" => {
            configured_sources == 1 && material.vault_field.is_none()
        }
        _ => true,
    };
    if !valid_source_shape {
        return Err(PayloadWriteSetupError::InvalidMaterialFileSource {
            material: material_name.to_string(),
            path: source.to_string(),
            reason: "material source fields do not match source".to_string(),
        });
    }

    let encoded = Zeroizing::new(match material.source.as_deref() {
        Some("env") => {
            let env = material.env.as_deref().ok_or_else(|| {
                PayloadWriteSetupError::MissingMaterialEnv {
                    material: material_name.to_string(),
                    env: "<missing>".to_string(),
                }
            })?;
            if !is_material_env_name(env) {
                return Err(PayloadWriteSetupError::InvalidMaterialFileSource {
                    material: material_name.to_string(),
                    path: env.to_string(),
                    reason: "environment variable name is invalid".to_string(),
                });
            }
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
            read_material_file_to_string(material_name, path)?
        }
        Some("unix_socket") => {
            let path = material.path.as_deref().ok_or_else(|| {
                PayloadWriteSetupError::MissingMaterialPath {
                    material: material_name.to_string(),
                }
            })?;
            read_material_unix_socket_to_string(material_name, path)?
        }
        Some("vault_kv2") => {
            let url = material.path.as_deref().ok_or_else(|| {
                PayloadWriteSetupError::MissingMaterialPath {
                    material: material_name.to_string(),
                }
            })?;
            let token_env = material.env.as_deref().ok_or_else(|| {
                PayloadWriteSetupError::MissingMaterialEnv {
                    material: material_name.to_string(),
                    env: "<missing>".to_string(),
                }
            })?;
            let vault_field = material.vault_field.as_deref().ok_or_else(|| {
                PayloadWriteSetupError::InvalidMaterialFileSource {
                    material: material_name.to_string(),
                    path: url.to_string(),
                    reason: "vault_field is required for Vault KV v2 material".to_string(),
                }
            })?;
            read_material_vault_kv2_to_string(material_name, url, token_env, vault_field)?
        }
        Some("fd") => {
            let fd = material
                .fd
                .ok_or_else(|| PayloadWriteSetupError::MissingMaterialFd {
                    material: material_name.to_string(),
                })?;
            read_material_fd_to_string(material_name, fd)?
        }
        Some("inline") => material.value_b64.clone().ok_or_else(|| {
            PayloadWriteSetupError::MissingInlineMaterial {
                material: material_name.to_string(),
            }
        })?,
        None => {
            return Err(PayloadWriteSetupError::MissingMaterialSource {
                material: material_name.to_string(),
            });
        }
        Some(source) => {
            return Err(PayloadWriteSetupError::UnsupportedMaterialSource {
                material: material_name.to_string(),
                material_source: source.to_string(),
            });
        }
    });

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

fn read_material_fd_to_string(
    material_name: &str,
    fd: i32,
) -> Result<String, PayloadWriteSetupError> {
    validate_material_fd_source(material_name, fd).map_err(|err| match err {
        CryptoSetupError::InvalidMaterialFileSource {
            material,
            path,
            reason,
        } => PayloadWriteSetupError::InvalidMaterialFileSource {
            material,
            path,
            reason,
        },
        other => PayloadWriteSetupError::InvalidMaterialFileSource {
            material: material_name.to_string(),
            path: format!("fd:{fd}"),
            reason: other.to_string(),
        },
    })?;

    #[cfg(unix)]
    {
        use std::fs::File;
        use std::os::fd::FromRawFd;

        let duplicated = unsafe { nix::libc::fcntl(fd, nix::libc::F_DUPFD_CLOEXEC, 0) };
        if duplicated < 0 {
            return Err(PayloadWriteSetupError::InvalidMaterialFileSource {
                material: material_name.to_string(),
                path: format!("fd:{fd}"),
                reason: "fd could not be duplicated".to_string(),
            });
        }
        let mut file = unsafe { File::from_raw_fd(duplicated) };
        let mut encoded = String::new();
        file.read_to_string(&mut encoded).map_err(|_| {
            PayloadWriteSetupError::UnreadableMaterialFile {
                material: material_name.to_string(),
                path: format!("fd:{fd}"),
            }
        })?;
        Ok(encoded)
    }

    #[cfg(not(unix))]
    {
        Err(PayloadWriteSetupError::InvalidMaterialFileSource {
            material: material_name.to_string(),
            path: format!("fd:{fd}"),
            reason: "fd source is only supported on Unix".to_string(),
        })
    }
}

fn read_material_vault_kv2_to_string(
    material_name: &str,
    url: &str,
    token_env: &str,
    vault_field: &str,
) -> Result<String, PayloadWriteSetupError> {
    validate_material_vault_kv2_source(material_name, url, token_env, Some(vault_field)).map_err(
        |err| match err {
            CryptoSetupError::InvalidMaterialFileSource {
                material,
                path,
                reason,
            } => PayloadWriteSetupError::InvalidMaterialFileSource {
                material,
                path,
                reason,
            },
            err => PayloadWriteSetupError::UnreadableMaterialFile {
                material: material_name.to_string(),
                path: format!("{url}: {err}"),
            },
        },
    )?;
    let token = Zeroizing::new(std::env::var(token_env).map_err(|_| {
        PayloadWriteSetupError::MissingMaterialEnv {
            material: material_name.to_string(),
            env: token_env.to_string(),
        }
    })?);
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(5))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|_| PayloadWriteSetupError::UnreadableMaterialFile {
            material: material_name.to_string(),
            path: url.to_string(),
        })?;
    let response = client
        .get(url)
        .header("X-Vault-Token", token.as_str())
        .send()
        .map_err(|_| PayloadWriteSetupError::UnreadableMaterialFile {
            material: material_name.to_string(),
            path: url.to_string(),
        })?;
    if !response.status().is_success() {
        return Err(PayloadWriteSetupError::UnreadableMaterialFile {
            material: material_name.to_string(),
            path: url.to_string(),
        });
    }
    let mut limited_response = response.take(VAULT_KV2_RESPONSE_MAX_BYTES + 1);
    let mut body_bytes = Vec::new();
    limited_response.read_to_end(&mut body_bytes).map_err(|_| {
        PayloadWriteSetupError::UnreadableMaterialFile {
            material: material_name.to_string(),
            path: url.to_string(),
        }
    })?;
    if body_bytes.len() as u64 > VAULT_KV2_RESPONSE_MAX_BYTES {
        return Err(PayloadWriteSetupError::InvalidMaterialFileSource {
            material: material_name.to_string(),
            path: url.to_string(),
            reason: "Vault KV v2 response exceeds maximum size".to_string(),
        });
    }
    let body = serde_json::from_slice::<Value>(&body_bytes).map_err(|_| {
        PayloadWriteSetupError::InvalidMaterialFileSource {
            material: material_name.to_string(),
            path: url.to_string(),
            reason: "Vault KV v2 response must be JSON".to_string(),
        }
    })?;
    body.pointer("/data/data")
        .and_then(Value::as_object)
        .and_then(|data| data.get(vault_field))
        .and_then(Value::as_str)
        .map(str::to_string)
        .ok_or_else(|| PayloadWriteSetupError::InvalidMaterialFileSource {
            material: material_name.to_string(),
            path: url.to_string(),
            reason: format!("Vault KV v2 response is missing data.data.{vault_field}"),
        })
}

fn read_material_unix_socket_to_string(
    material_name: &str,
    path: &str,
) -> Result<String, PayloadWriteSetupError> {
    validate_material_unix_socket_source(material_name, path).map_err(|err| match err {
        CryptoSetupError::InvalidMaterialFileSource {
            material,
            path,
            reason,
        } => PayloadWriteSetupError::InvalidMaterialFileSource {
            material,
            path,
            reason,
        },
        err => PayloadWriteSetupError::UnreadableMaterialFile {
            material: material_name.to_string(),
            path: format!("{path}: {err}"),
        },
    })?;

    #[cfg(unix)]
    {
        use std::os::unix::net::UnixStream;

        let mut stream = UnixStream::connect(path).map_err(|_| {
            PayloadWriteSetupError::UnreadableMaterialFile {
                material: material_name.to_string(),
                path: path.to_string(),
            }
        })?;
        let timeout = Some(Duration::from_secs(5));
        stream.set_read_timeout(timeout).map_err(|_| {
            PayloadWriteSetupError::UnreadableMaterialFile {
                material: material_name.to_string(),
                path: path.to_string(),
            }
        })?;

        let mut encoded = String::new();
        stream.read_to_string(&mut encoded).map_err(|_| {
            PayloadWriteSetupError::UnreadableMaterialFile {
                material: material_name.to_string(),
                path: path.to_string(),
            }
        })?;
        Ok(encoded)
    }

    #[cfg(not(unix))]
    {
        Err(PayloadWriteSetupError::InvalidMaterialFileSource {
            material: material_name.to_string(),
            path: path.to_string(),
            reason: "unix_socket source is only supported on Unix".to_string(),
        })
    }
}

fn read_material_file_to_string(
    material_name: &str,
    path: &str,
) -> Result<String, PayloadWriteSetupError> {
    validate_material_file_source_for_payload_read(material_name, path)?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};

        let mut file = fs::OpenOptions::new()
            .read(true)
            .custom_flags(nix::libc::O_CLOEXEC | nix::libc::O_NOFOLLOW)
            .open(path)
            .map_err(|_| PayloadWriteSetupError::UnreadableMaterialFile {
                material: material_name.to_string(),
                path: path.to_string(),
            })?;
        let metadata =
            file.metadata()
                .map_err(|_| PayloadWriteSetupError::UnreadableMaterialFile {
                    material: material_name.to_string(),
                    path: path.to_string(),
                })?;
        if !metadata.is_file() {
            return Err(PayloadWriteSetupError::InvalidMaterialFileSource {
                material: material_name.to_string(),
                path: path.to_string(),
                reason: "opened path must be a regular file".to_string(),
            });
        }

        unsafe extern "C" {
            fn geteuid() -> u32;
        }

        let effective_uid = unsafe { geteuid() };
        let owner = metadata.uid();
        if owner != 0 && owner != effective_uid {
            return Err(PayloadWriteSetupError::InvalidMaterialFileSource {
                material: material_name.to_string(),
                path: path.to_string(),
                reason: "opened file must be owned by root or the qdrant process user".to_string(),
            });
        }
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(PayloadWriteSetupError::InvalidMaterialFileSource {
                material: material_name.to_string(),
                path: path.to_string(),
                reason: "opened file must not be group/world accessible".to_string(),
            });
        }

        let mut encoded = String::new();
        file.read_to_string(&mut encoded).map_err(|_| {
            PayloadWriteSetupError::UnreadableMaterialFile {
                material: material_name.to_string(),
                path: path.to_string(),
            }
        })?;
        Ok(encoded)
    }

    #[cfg(not(unix))]
    {
        fs::read_to_string(path).map_err(|_| PayloadWriteSetupError::UnreadableMaterialFile {
            material: material_name.to_string(),
            path: path.to_string(),
        })
    }
}

fn validate_material_file_source_for_payload_read(
    material_name: &str,
    path: &str,
) -> Result<(), PayloadWriteSetupError> {
    validate_material_file_source(material_name, path).map_err(|err| match err {
        CryptoSetupError::InvalidMaterialFileSource {
            material,
            path,
            reason,
        } => PayloadWriteSetupError::InvalidMaterialFileSource {
            material,
            path,
            reason,
        },
        err => PayloadWriteSetupError::UnreadableMaterialFile {
            material: material_name.to_string(),
            path: format!("{path}: {err}"),
        },
    })
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, HashMap, HashSet};

    use collection::config::{
        CkksCollectionConfig, CollectionConfigInternal, CollectionEncryptionConfig,
        CollectionParams, CryptoMigrationState, EncryptionRuleRef, EncryptionSelector, WalConfig,
    };
    use collection::operations::vector_params_builder::VectorParamsBuilder;
    use collection::optimizers_builder::OptimizersConfig;
    use data_encoding::BASE64URL_NOPAD;
    use qdrant_sec::{
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

    fn with_embedding_vector(mut params: CollectionParams, distance: Distance) -> CollectionParams {
        params.vectors = collection::operations::types::VectorsConfig::Multi(BTreeMap::from([(
            "embedding".to_string(),
            VectorParamsBuilder::new(2, distance).build(),
        )]));
        params
    }

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

    fn create_collection_with_params(params: CollectionParams) -> CreateCollection {
        CreateCollection {
            vectors: params.vectors,
            sparse_vectors: params.sparse_vectors,
            hnsw_config: None,
            wal_config: None,
            optimizers_config: None,
            shard_number: None,
            on_disk_payload: None,
            replication_factor: None,
            write_consistency_factor: None,
            quantization_config: None,
            sharding_method: None,
            encryption: params.encryption,
            ckks: params.ckks,
            strict_mode_config: None,
            uuid: None,
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
                    "kdf_domain": "qdrant-sec/client-payload-text/v1",
                    "aad": {
                        "collection_id": collection_id,
                        "point_id": point_id,
                        "field_path": field_path,
                        "schema_version": 1
                    },
                    "nonce": "AAAAAAAAAAAAAAAA",
                    "ciphertext": "AAAAAAAAAAAAAAAAAAAAAA",
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
                    provider: VECTOR_OPENFHE_CKKS_PROVIDER.to_string(),
                    materials: HashMap::from([(
                        "sym_key".to_string(),
                        "tenant-a/payload-v1".to_string(),
                    )]),
                    backend_ref: Some("missing-backend".to_string()),
                    options: json!({
                        "key_id": "tenant-a:docs",
                        "material_fingerprint_id": "tenant-a/vector@v1",
                        "profile": CKKS_PROFILE_OPENFHE_128_N16384_D4_SCALE50,
                        "crypto_context_b64": BASE64URL_NOPAD.encode(b"openfhe context"),
                        "public_key_b64": BASE64URL_NOPAD.encode(b"openfhe public key"),
                    }),
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
    fn validate_crypto_settings_rejects_invalid_registry_names() {
        let invalid_material_settings = CryptoSettings {
            allow_inline_key_material: true,
            instances: HashMap::new(),
            materials: HashMap::from([(
                "tenant a/payload-v1".to_string(),
                CryptoMaterialConfig {
                    kind: SYMMETRIC_KEY_32_KIND.to_string(),
                    source: Some("inline".to_string()),
                    value_b64: Some(BASE64URL_NOPAD.encode(&[1_u8; 32])),
                    ..CryptoMaterialConfig::default()
                },
            )]),
            backends: HashMap::new(),
        };
        assert_eq!(
            validate_crypto_settings(&invalid_material_settings),
            Err(CryptoSetupError::InvalidMaterialName {
                material: "tenant a/payload-v1".to_string(),
            }),
        );

        let invalid_backend_settings = CryptoSettings {
            allow_inline_key_material: true,
            instances: HashMap::new(),
            materials: HashMap::new(),
            backends: HashMap::from([(
                "openfhe local".to_string(),
                CryptoBackendConfig {
                    kind: "process_pool".to_string(),
                    program: None,
                    sha256_b64: None,
                    size: Some(1),
                    timeout_ms: Some(5_000),
                },
            )]),
        };
        assert_eq!(
            validate_crypto_settings(&invalid_backend_settings),
            Err(CryptoSetupError::InvalidBackendName {
                backend: "openfhe local".to_string(),
            }),
        );

        let invalid_instance_settings = CryptoSettings {
            allow_inline_key_material: true,
            instances: HashMap::from([(
                "docs payload v1".to_string(),
                CryptoInstanceConfig {
                    provider: PAYLOAD_CLIENT_AEAD_PROVIDER.to_string(),
                    materials: HashMap::new(),
                    backend_ref: None,
                    options: json!({}),
                },
            )]),
            materials: HashMap::new(),
            backends: HashMap::new(),
        };
        assert_eq!(
            validate_crypto_settings(&invalid_instance_settings),
            Err(CryptoSetupError::InvalidInstanceName {
                instance: "docs payload v1".to_string(),
            }),
        );

        let invalid_provider_settings = CryptoSettings {
            allow_inline_key_material: true,
            instances: HashMap::from([(
                "docs_payload_v1".to_string(),
                CryptoInstanceConfig {
                    provider: "payload client-aead@v1".to_string(),
                    materials: HashMap::new(),
                    backend_ref: None,
                    options: json!({}),
                },
            )]),
            materials: HashMap::new(),
            backends: HashMap::new(),
        };
        assert!(matches!(
            validate_crypto_settings(&invalid_provider_settings),
            Err(CryptoSetupError::InvalidInstanceOption { .. })
        ));

        let unsupported_provider_settings = CryptoSettings {
            allow_inline_key_material: true,
            instances: HashMap::from([(
                "docs_payload_v1".to_string(),
                CryptoInstanceConfig {
                    provider: "payload/unknown@v1".to_string(),
                    materials: HashMap::new(),
                    backend_ref: None,
                    options: json!({}),
                },
            )]),
            materials: HashMap::new(),
            backends: HashMap::new(),
        };
        assert!(matches!(
            validate_crypto_settings(&unsupported_provider_settings),
            Err(CryptoSetupError::InvalidInstanceOption { .. })
        ));

        let client_provider_with_server_material_settings = CryptoSettings {
            allow_inline_key_material: true,
            instances: HashMap::from([(
                "docs_payload_client_v1".to_string(),
                CryptoInstanceConfig {
                    provider: PAYLOAD_CLIENT_AEAD_PROVIDER.to_string(),
                    materials: HashMap::from([(
                        PAYLOAD_SYM_KEY_ROLE.to_string(),
                        "tenant-a/payload-v1".to_string(),
                    )]),
                    backend_ref: None,
                    options: json!({}),
                },
            )]),
            materials: HashMap::from([(
                "tenant-a/payload-v1".to_string(),
                CryptoMaterialConfig {
                    kind: SYMMETRIC_KEY_32_KIND.to_string(),
                    source: Some("inline".to_string()),
                    value_b64: Some(BASE64URL_NOPAD.encode(&[1_u8; 32])),
                    ..CryptoMaterialConfig::default()
                },
            )]),
            backends: HashMap::new(),
        };
        assert!(matches!(
            validate_crypto_settings(&client_provider_with_server_material_settings),
            Err(CryptoSetupError::InvalidInstanceOption { .. })
        ));

        let payload_provider_with_backend_settings = CryptoSettings {
            allow_inline_key_material: true,
            instances: HashMap::from([(
                "docs_payload_v1".to_string(),
                CryptoInstanceConfig {
                    provider: PAYLOAD_AES_GCM_PROVIDER.to_string(),
                    materials: HashMap::from([(
                        PAYLOAD_SYM_KEY_ROLE.to_string(),
                        "tenant-a/payload-v1".to_string(),
                    )]),
                    backend_ref: Some("openfhe_local".to_string()),
                    options: json!({}),
                },
            )]),
            materials: HashMap::from([(
                "tenant-a/payload-v1".to_string(),
                CryptoMaterialConfig {
                    kind: SYMMETRIC_KEY_32_KIND.to_string(),
                    source: Some("inline".to_string()),
                    value_b64: Some(BASE64URL_NOPAD.encode(&[1_u8; 32])),
                    ..CryptoMaterialConfig::default()
                },
            )]),
            backends: HashMap::new(),
        };
        assert!(matches!(
            validate_crypto_settings(&payload_provider_with_backend_settings),
            Err(CryptoSetupError::InvalidInstanceOption { .. })
        ));

        let invalid_role_settings = CryptoSettings {
            allow_inline_key_material: true,
            instances: HashMap::from([(
                "docs_payload_v1".to_string(),
                CryptoInstanceConfig {
                    provider: PAYLOAD_AES_GCM_PROVIDER.to_string(),
                    materials: HashMap::from([(
                        "sym key".to_string(),
                        "tenant-a/payload-v1".to_string(),
                    )]),
                    backend_ref: None,
                    options: json!({}),
                },
            )]),
            materials: HashMap::from([(
                "tenant-a/payload-v1".to_string(),
                CryptoMaterialConfig {
                    kind: SYMMETRIC_KEY_32_KIND.to_string(),
                    source: Some("inline".to_string()),
                    value_b64: Some(BASE64URL_NOPAD.encode(&[1_u8; 32])),
                    ..CryptoMaterialConfig::default()
                },
            )]),
            backends: HashMap::new(),
        };
        assert!(matches!(
            validate_crypto_settings(&invalid_role_settings),
            Err(CryptoSetupError::InvalidInstanceOption { .. })
        ));
    }

    #[test]
    fn validate_crypto_settings_requires_provider_bindings() {
        let payload_without_sym_key = CryptoSettings {
            allow_inline_key_material: true,
            instances: HashMap::from([(
                "docs_payload_v1".to_string(),
                CryptoInstanceConfig {
                    provider: PAYLOAD_AES_GCM_PROVIDER.to_string(),
                    materials: HashMap::new(),
                    backend_ref: None,
                    options: json!({}),
                },
            )]),
            materials: HashMap::new(),
            backends: HashMap::new(),
        };
        assert!(matches!(
            validate_crypto_settings(&payload_without_sym_key),
            Err(CryptoSetupError::InvalidInstanceOption { .. })
        ));

        let payload_without_fingerprint = CryptoSettings {
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
                    options: json!({}),
                },
            )]),
            materials: HashMap::from([(
                "tenant-a/payload-v1".to_string(),
                CryptoMaterialConfig {
                    kind: SYMMETRIC_KEY_32_KIND.to_string(),
                    source: Some("inline".to_string()),
                    value_b64: Some(BASE64URL_NOPAD.encode(&[1_u8; 32])),
                    ..CryptoMaterialConfig::default()
                },
            )]),
            backends: HashMap::new(),
        };
        assert!(matches!(
            validate_crypto_settings(&payload_without_fingerprint),
            Err(CryptoSetupError::InvalidInstanceOption { .. })
        ));

        let payload_with_retired_active_key = CryptoSettings {
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
                        "material_fingerprint_id": "tenant-a/payload@v1",
                    }),
                },
            )]),
            materials: HashMap::from([
                (
                    "tenant-a/mk-v1".to_string(),
                    CryptoMaterialConfig {
                        kind: WRAPPING_KEY_32_KIND.to_string(),
                        source: Some("inline".to_string()),
                        value_b64: Some(BASE64URL_NOPAD.encode(&[9_u8; 32])),
                        ..CryptoMaterialConfig::default()
                    },
                ),
                (
                    "tenant-a/payload-v1".to_string(),
                    CryptoMaterialConfig {
                        kind: WRAPPED_SYMMETRIC_KEY_32_KIND.to_string(),
                        wrapped_by: Some("tenant-a/mk-v1".to_string()),
                        wrap_algorithm: Some(RESOURCE_KEY_WRAP_ALGORITHM.to_string()),
                        nonce: Some(BASE64URL_NOPAD.encode(&[3_u8; 12])),
                        wrapped_key_b64: Some(BASE64URL_NOPAD.encode(&[4_u8; 48])),
                        rk_epoch: Some(1),
                        state: Some(RESOURCE_KEY_STATE_RETIRED.to_string()),
                        scope: Some("collection:docs".to_string()),
                        ..CryptoMaterialConfig::default()
                    },
                ),
            ]),
            backends: HashMap::new(),
        };
        assert!(matches!(
            validate_crypto_settings(&payload_with_retired_active_key),
            Err(CryptoSetupError::InvalidInstanceOption { .. })
        ));

        let vector_without_backend = CryptoSettings {
            allow_inline_key_material: true,
            instances: HashMap::from([(
                "docs_vector_v1".to_string(),
                CryptoInstanceConfig {
                    provider: VECTOR_OPENFHE_CKKS_PROVIDER.to_string(),
                    materials: HashMap::from([(
                        PAYLOAD_SYM_KEY_ROLE.to_string(),
                        "tenant-a/vector-v1".to_string(),
                    )]),
                    backend_ref: None,
                    options: json!({}),
                },
            )]),
            materials: HashMap::from([(
                "tenant-a/vector-v1".to_string(),
                CryptoMaterialConfig {
                    kind: SYMMETRIC_KEY_32_KIND.to_string(),
                    source: Some("inline".to_string()),
                    value_b64: Some(BASE64URL_NOPAD.encode(&[1_u8; 32])),
                    ..CryptoMaterialConfig::default()
                },
            )]),
            backends: HashMap::new(),
        };
        assert!(matches!(
            validate_crypto_settings(&vector_without_backend),
            Err(CryptoSetupError::InvalidInstanceOption { .. })
        ));
    }

    #[test]
    fn validate_crypto_settings_requires_client_provider_policy() {
        let valid_client_options = json!({
            "key_id": "tenant-a/client-rk-v1",
            "key_id_required": true,
            "expected_rk_id": "tenant-a/client-rk-v1",
            "min_rk_epoch": 3,
            "max_rk_epoch": 3,
            "signature_public_keys": {
                "tenant-a/client-signing-v1": BASE64URL_NOPAD.encode(&[7_u8; 32]),
            },
        });
        let valid_client_settings = CryptoSettings {
            allow_inline_key_material: true,
            instances: HashMap::from([(
                "docs_payload_client_v1".to_string(),
                CryptoInstanceConfig {
                    provider: PAYLOAD_CLIENT_AEAD_PROVIDER.to_string(),
                    materials: HashMap::new(),
                    backend_ref: None,
                    options: valid_client_options.clone(),
                },
            )]),
            materials: HashMap::new(),
            backends: HashMap::new(),
        };
        validate_crypto_settings(&valid_client_settings).unwrap();

        let mut key_id_not_required = valid_client_settings.clone();
        key_id_not_required
            .instances
            .get_mut("docs_payload_client_v1")
            .unwrap()
            .options
            .as_object_mut()
            .unwrap()
            .insert(KEY_ID_REQUIRED_OPTION.to_string(), json!(false));
        assert!(matches!(
            validate_crypto_settings(&key_id_not_required),
            Err(CryptoSetupError::InvalidInstanceOption { .. })
        ));

        let mut missing_rk_id = valid_client_settings.clone();
        missing_rk_id
            .instances
            .get_mut("docs_payload_client_v1")
            .unwrap()
            .options
            .as_object_mut()
            .unwrap()
            .remove(EXPECTED_RK_ID_OPTION);
        assert!(matches!(
            validate_crypto_settings(&missing_rk_id),
            Err(CryptoSetupError::InvalidInstanceOption { .. })
        ));

        let mut mismatched_rk_id = valid_client_settings.clone();
        mismatched_rk_id
            .instances
            .get_mut("docs_payload_client_v1")
            .unwrap()
            .options
            .as_object_mut()
            .unwrap()
            .insert(
                EXPECTED_RK_ID_OPTION.to_string(),
                json!("tenant-a/client-rk-v2"),
            );
        assert!(matches!(
            validate_crypto_settings(&mismatched_rk_id),
            Err(CryptoSetupError::InvalidInstanceOption { .. })
        ));

        let mut broad_epoch = valid_client_settings.clone();
        broad_epoch
            .instances
            .get_mut("docs_payload_client_v1")
            .unwrap()
            .options
            .as_object_mut()
            .unwrap()
            .insert(MAX_RK_EPOCH_OPTION.to_string(), json!(4));
        assert!(matches!(
            validate_crypto_settings(&broad_epoch),
            Err(CryptoSetupError::InvalidInstanceOption { .. })
        ));

        let mut unsupported_client_option = valid_client_settings.clone();
        unsupported_client_option
            .instances
            .get_mut("docs_payload_client_v1")
            .unwrap()
            .options
            .as_object_mut()
            .unwrap()
            .insert(RETIRED_MATERIALS_OPTION.to_string(), json!([]));
        assert!(matches!(
            validate_crypto_settings(&unsupported_client_option),
            Err(CryptoSetupError::InvalidInstanceOption { option, .. })
                if option == RETIRED_MATERIALS_OPTION
        ));

        let mut missing_signature = valid_client_settings;
        missing_signature
            .instances
            .get_mut("docs_payload_client_v1")
            .unwrap()
            .options
            .as_object_mut()
            .unwrap()
            .remove(SIGNATURE_PUBLIC_KEYS_OPTION);
        assert!(matches!(
            validate_crypto_settings(&missing_signature),
            Err(CryptoSetupError::InvalidInstanceOption { .. })
        ));
    }

    #[test]
    fn validate_crypto_settings_rejects_unsupported_provider_options() {
        let payload_with_client_option = CryptoSettings {
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
                        "material_fingerprint_id": "tenant-a/payload@v1",
                        "expected_rk_id": "tenant-a/client-rk-v1",
                    }),
                },
            )]),
            materials: HashMap::from([(
                "tenant-a/payload-v1".to_string(),
                CryptoMaterialConfig {
                    kind: SYMMETRIC_KEY_32_KIND.to_string(),
                    source: Some("inline".to_string()),
                    value_b64: Some(BASE64URL_NOPAD.encode(&[1_u8; 32])),
                    ..CryptoMaterialConfig::default()
                },
            )]),
            backends: HashMap::new(),
        };
        assert!(matches!(
            validate_crypto_settings(&payload_with_client_option),
            Err(CryptoSetupError::InvalidInstanceOption { option, .. })
                if option == EXPECTED_RK_ID_OPTION
        ));

        let mut payload_with_extra_material_role = payload_with_client_option.clone();
        payload_with_extra_material_role
            .instances
            .get_mut("docs_payload_v1")
            .unwrap()
            .options
            .as_object_mut()
            .unwrap()
            .remove(EXPECTED_RK_ID_OPTION);
        payload_with_extra_material_role
            .instances
            .get_mut("docs_payload_v1")
            .unwrap()
            .materials
            .insert("client_key".to_string(), "tenant-a/payload-v1".to_string());
        assert!(matches!(
            validate_crypto_settings(&payload_with_extra_material_role),
            Err(CryptoSetupError::InvalidInstanceOption { option, .. })
                if option == "materials.client_key"
        ));

        let bridge_program = std::env::current_exe().unwrap().display().to_string();
        let vector_with_payload_option = CryptoSettings {
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
                        "material_fingerprint_id": "tenant-a/vector@v1",
                        "profile": CKKS_PROFILE_OPENFHE_128_N16384_D4_SCALE50,
                        "crypto_context_b64": BASE64URL_NOPAD.encode(b"openfhe context"),
                        "public_key_b64": BASE64URL_NOPAD.encode(b"openfhe public key"),
                        "retired_materials": [],
                    }),
                },
            )]),
            materials: HashMap::from([(
                "tenant-a/vector-v1".to_string(),
                CryptoMaterialConfig {
                    kind: SYMMETRIC_KEY_32_KIND.to_string(),
                    source: Some("inline".to_string()),
                    value_b64: Some(BASE64URL_NOPAD.encode(&[2_u8; 32])),
                    ..CryptoMaterialConfig::default()
                },
            )]),
            backends: HashMap::from([(
                "openfhe_local".to_string(),
                CryptoBackendConfig {
                    kind: "process".to_string(),
                    program: Some(bridge_program),
                    sha256_b64: Some(current_exe_sha256_b64()),
                    size: None,
                    timeout_ms: Some(1000),
                },
            )]),
        };
        assert!(matches!(
            validate_crypto_settings(&vector_with_payload_option),
            Err(CryptoSetupError::InvalidInstanceOption { option, .. })
                if option == RETIRED_MATERIALS_OPTION
        ));

        let mut vector_with_extra_material_role = vector_with_payload_option;
        vector_with_extra_material_role
            .instances
            .get_mut("docs_vector_v1")
            .unwrap()
            .options
            .as_object_mut()
            .unwrap()
            .remove(RETIRED_MATERIALS_OPTION);
        vector_with_extra_material_role
            .instances
            .get_mut("docs_vector_v1")
            .unwrap()
            .materials
            .insert("payload_key".to_string(), "tenant-a/vector-v1".to_string());
        assert!(matches!(
            validate_crypto_settings(&vector_with_extra_material_role),
            Err(CryptoSetupError::InvalidInstanceOption { option, .. })
                if option == "materials.payload_key"
        ));
    }

    #[test]
    fn validate_crypto_settings_rejects_invalid_server_provider_key_id_options() {
        let payload_with_invalid_key_id = CryptoSettings {
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
                        "key_id": "not valid",
                        "material_fingerprint_id": "tenant-a/payload@v1",
                    }),
                },
            )]),
            materials: HashMap::from([(
                "tenant-a/payload-v1".to_string(),
                CryptoMaterialConfig {
                    kind: SYMMETRIC_KEY_32_KIND.to_string(),
                    source: Some("inline".to_string()),
                    value_b64: Some(BASE64URL_NOPAD.encode(&[1_u8; 32])),
                    ..CryptoMaterialConfig::default()
                },
            )]),
            backends: HashMap::new(),
        };
        assert!(matches!(
            validate_crypto_settings(&payload_with_invalid_key_id),
            Err(CryptoSetupError::InvalidInstanceOption { option, .. })
                if option == "key_id"
        ));

        let bridge_program = std::env::current_exe().unwrap().display().to_string();
        let vector_with_invalid_key_id = CryptoSettings {
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
                        "key_id": "not valid",
                        "material_fingerprint_id": "tenant-a/vector@v1",
                        "profile": CKKS_PROFILE_OPENFHE_128_N16384_D4_SCALE50,
                        "crypto_context_b64": BASE64URL_NOPAD.encode(b"openfhe context"),
                        "public_key_b64": BASE64URL_NOPAD.encode(b"openfhe public key"),
                    }),
                },
            )]),
            materials: HashMap::from([(
                "tenant-a/vector-v1".to_string(),
                CryptoMaterialConfig {
                    kind: SYMMETRIC_KEY_32_KIND.to_string(),
                    source: Some("inline".to_string()),
                    value_b64: Some(BASE64URL_NOPAD.encode(&[2_u8; 32])),
                    ..CryptoMaterialConfig::default()
                },
            )]),
            backends: HashMap::from([(
                "openfhe_local".to_string(),
                CryptoBackendConfig {
                    kind: "process".to_string(),
                    program: Some(bridge_program),
                    sha256_b64: Some(current_exe_sha256_b64()),
                    size: None,
                    timeout_ms: Some(1000),
                },
            )]),
        };
        assert!(matches!(
            validate_crypto_settings(&vector_with_invalid_key_id),
            Err(CryptoSetupError::InvalidInstanceOption { option, .. })
                if option == "key_id"
        ));
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

        settings
            .instances
            .get_mut("docs_payload_v1")
            .unwrap()
            .options
            .as_object_mut()
            .unwrap()
            .insert(
                MATERIAL_FINGERPRINT_ID_OPTION.to_string(),
                json!("tenant a/payload@v2"),
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
            .insert(
                MATERIAL_FINGERPRINT_ID_OPTION.to_string(),
                json!("tenant-a/payload@v2"),
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
                            fd: None,
                            value_b64: Some(BASE64URL_NOPAD.encode(&[1_u8; 32])),
                            vault_field: None,
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
                            fd: None,
                            value_b64: None,
                            vault_field: None,
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

        let state_fingerprint = crypto_runtime_capability_fingerprint(&settings);
        settings.crypto.materials.insert(
            "tenant-a/docs-rk-v0".to_string(),
            CryptoMaterialConfig {
                kind: WRAPPED_SYMMETRIC_KEY_32_KIND.to_string(),
                source: Some("wrapped".to_string()),
                env: None,
                path: None,
                fd: None,
                value_b64: None,
                vault_field: None,
                wrapped_by: Some("tenant-a/mk".to_string()),
                wrap_algorithm: Some(RESOURCE_KEY_WRAP_ALGORITHM.to_string()),
                nonce: Some(BASE64URL_NOPAD.encode(&[4_u8; 12])),
                wrapped_key_b64: Some(BASE64URL_NOPAD.encode(&[5_u8; 48])),
                rk_epoch: Some(2),
                state: Some(RESOURCE_KEY_STATE_RETIRED.to_string()),
                scope: Some("collection:docs".to_string()),
            },
        );
        settings
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
                    "material": "tenant-a/docs-rk-v0",
                    "material_fingerprint_id": "tenant-a/docs-rk@v0",
                }]),
            );

        assert_ne!(
            state_fingerprint,
            crypto_runtime_capability_fingerprint(&settings),
            "fingerprint must change when retired payload key policy changes",
        );
    }

    #[test]
    fn crypto_runtime_capability_fingerprint_ignores_unsupported_legacy_ckks() {
        let baseline = Settings::new(None).unwrap();
        let with_legacy = Settings {
            ckks: CkksConfig {
                enabled: true,
                key_id: Some("tenant-a:legacy".to_string()),
                resource_key_b64: Some(BASE64URL_NOPAD.encode(&[7_u8; 32])),
                ..CkksConfig::default()
            },
            ..Settings::new(None).unwrap()
        };

        assert_eq!(
            crypto_runtime_capability_fingerprint(&baseline),
            crypto_runtime_capability_fingerprint(&with_legacy),
            "unsupported legacy ckks runtime settings must not influence canonical crypto parity",
        );
        assert!(matches!(
            validate_runtime_config(&with_legacy),
            Err(CryptoSetupError::LegacyCkksRuntimeUnsupported),
        ));
    }

    #[test]
    fn validate_runtime_config_accepts_metadata_blind_index_provider() {
        let settings = Settings {
            crypto: CryptoSettings {
                instances: HashMap::from([(
                    "docs_body_blind_v1".to_string(),
                    CryptoInstanceConfig {
                        provider: METADATA_BLIND_INDEX_PROVIDER.to_string(),
                        options: json!({
                            "key_id": "tenant-a:docs",
                            "expected_rk_id": "tenant-a:docs",
                            "min_rk_epoch": 3,
                            "max_rk_epoch": 3,
                        }),
                        ..CryptoInstanceConfig::default()
                    },
                )]),
                ..CryptoSettings::default()
            },
            ..Settings::new(None).unwrap()
        };

        validate_runtime_config(&settings).unwrap();

        let mut with_server_material = settings;
        with_server_material
            .crypto
            .instances
            .get_mut("docs_body_blind_v1")
            .unwrap()
            .materials
            .insert("sym_key".to_string(), "tenant-a/blind-v1".to_string());
        let err = validate_runtime_config(&with_server_material)
            .expect_err("metadata blind-index provider must be server blind");
        assert!(matches!(
            err,
            CryptoSetupError::InvalidInstanceOption { reason, .. }
                if reason.contains("must not configure server materials")
        ));
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
    fn crypto_runtime_capability_fingerprint_tracks_client_verifier_policy() {
        let settings = Settings {
            crypto: CryptoSettings {
                instances: HashMap::from([(
                    "docs_client_payload_v1".to_string(),
                    CryptoInstanceConfig {
                        provider: PAYLOAD_CLIENT_AEAD_PROVIDER.to_string(),
                        materials: HashMap::new(),
                        backend_ref: None,
                        options: json!({
                            "key_id": "tenant-a:docs",
                            EXPECTED_RK_ID_OPTION: "tenant-a:docs",
                            MIN_RK_EPOCH_OPTION: 3,
                            MAX_RK_EPOCH_OPTION: 3,
                            SIGNATURE_KEY_ID_OPTION: "tenant-a:signing-v1",
                            SIGNATURE_PUBLIC_KEY_B64_OPTION: BASE64URL_NOPAD.encode(&[11_u8; 32]),
                        }),
                    },
                )]),
                ..CryptoSettings::default()
            },
            ..Settings::new(None).unwrap()
        };
        let fingerprint = crypto_runtime_capability_fingerprint(&settings);

        let mut peer_with_different_verifier = settings.clone();
        peer_with_different_verifier
            .crypto
            .instances
            .get_mut("docs_client_payload_v1")
            .unwrap()
            .options
            .as_object_mut()
            .unwrap()
            .insert(
                SIGNATURE_PUBLIC_KEY_B64_OPTION.to_string(),
                json!(BASE64URL_NOPAD.encode(&[12_u8; 32])),
            );
        assert_ne!(
            fingerprint,
            crypto_runtime_capability_fingerprint(&peer_with_different_verifier),
            "client verifier public key drift must change the parity fingerprint",
        );

        let mut peer_with_different_epoch = settings.clone();
        peer_with_different_epoch
            .crypto
            .instances
            .get_mut("docs_client_payload_v1")
            .unwrap()
            .options
            .as_object_mut()
            .unwrap()
            .insert(MAX_RK_EPOCH_OPTION.to_string(), json!(4));
        assert_ne!(
            fingerprint,
            crypto_runtime_capability_fingerprint(&peer_with_different_epoch),
            "client RK epoch policy drift must change the parity fingerprint",
        );

        let mut peer_with_different_rk = settings.clone();
        peer_with_different_rk
            .crypto
            .instances
            .get_mut("docs_client_payload_v1")
            .unwrap()
            .options
            .as_object_mut()
            .unwrap()
            .insert(EXPECTED_RK_ID_OPTION.to_string(), json!("tenant-a:docs-v2"));
        assert_ne!(
            fingerprint,
            crypto_runtime_capability_fingerprint(&peer_with_different_rk),
            "client expected RK id drift must change the parity fingerprint",
        );
    }

    #[test]
    fn crypto_runtime_capability_fingerprint_tracks_vault_material_field() {
        let settings = Settings {
            crypto: CryptoSettings {
                materials: HashMap::from([(
                    "tenant-a/mk".to_string(),
                    CryptoMaterialConfig {
                        kind: WRAPPING_KEY_32_KIND.to_string(),
                        source: Some("vault_kv2".to_string()),
                        env: Some("QDRANT_VAULT_TOKEN".to_string()),
                        path: Some("https://vault.example.com/v1/secret/data/docs".to_string()),
                        vault_field: Some("mk_v1".to_string()),
                        ..CryptoMaterialConfig::default()
                    },
                )]),
                ..CryptoSettings::default()
            },
            ..Settings::new(None).unwrap()
        };
        let fingerprint = crypto_runtime_capability_fingerprint(&settings);
        let mut peer_with_different_field = settings.clone();
        peer_with_different_field
            .crypto
            .materials
            .get_mut("tenant-a/mk")
            .unwrap()
            .vault_field = Some("mk_v2".to_string());

        assert_ne!(
            fingerprint,
            crypto_runtime_capability_fingerprint(&peer_with_different_field),
            "Vault field drift must change the non-secret runtime parity fingerprint",
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

        assert_eq!(
            validate_material(
                "tenant-a/payload-v1",
                &CryptoMaterialConfig {
                    kind: "kms_key".to_string(),
                    source: Some("inline".to_string()),
                    env: None,
                    path: None,
                    value_b64: Some("AQID".to_string()),
                    ..CryptoMaterialConfig::default()
                },
                true,
            ),
            Err(CryptoSetupError::UnsupportedMaterialKind {
                material: "tenant-a/payload-v1".to_string(),
                kind: "kms_key".to_string(),
            }),
        );

        assert_eq!(
            validate_material(
                "tenant-a/payload-v1",
                &CryptoMaterialConfig {
                    kind: "symmetric_key_32".to_string(),
                    source: Some("fd".to_string()),
                    env: Some("QDRANT_PAYLOAD_KEY".to_string()),
                    fd: Some(3),
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
                    value_b64: Some("AQID".to_string()),
                    ..CryptoMaterialConfig::default()
                },
                true,
            ),
            Err(CryptoSetupError::MissingMaterialSource {
                material: "tenant-a/payload-v1".to_string(),
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
    fn validate_material_inline_source_checks_encoding_and_length() {
        let invalid_encoding = CryptoMaterialConfig {
            kind: "symmetric_key_32".to_string(),
            source: Some("inline".to_string()),
            value_b64: Some("not valid base64".to_string()),
            ..CryptoMaterialConfig::default()
        };
        assert!(matches!(
            validate_material("tenant-a/payload-v1", &invalid_encoding, true),
            Err(CryptoSetupError::InvalidMaterialFileSource { reason, .. })
                if reason.contains("base64url")
        ));

        let invalid_length = CryptoMaterialConfig {
            kind: "symmetric_key_32".to_string(),
            source: Some("inline".to_string()),
            value_b64: Some(BASE64URL_NOPAD.encode(&[7u8; 31])),
            ..CryptoMaterialConfig::default()
        };
        assert!(matches!(
            validate_material("tenant-a/payload-v1", &invalid_length, true),
            Err(CryptoSetupError::InvalidMaterialFileSource { reason, .. })
                if reason.contains("exactly 32 bytes")
        ));

        let valid = CryptoMaterialConfig {
            kind: "symmetric_key_32".to_string(),
            source: Some("inline".to_string()),
            value_b64: Some(BASE64URL_NOPAD.encode(&[7u8; 32])),
            ..CryptoMaterialConfig::default()
        };
        assert_eq!(
            validate_material("tenant-a/payload-v1", &valid, true),
            Ok(())
        );
    }

    #[test]
    fn validate_material_env_source_rejects_invalid_name() {
        let env_material = CryptoMaterialConfig {
            kind: "symmetric_key_32".to_string(),
            source: Some("env".to_string()),
            env: Some("QDRANT/PAYLOAD_KEY".to_string()),
            ..CryptoMaterialConfig::default()
        };

        assert!(matches!(
            validate_material("tenant-a/payload-v1", &env_material, false),
            Err(CryptoSetupError::InvalidMaterialFileSource { reason, .. })
                if reason.contains("environment variable")
        ));

        let empty_env_material = CryptoMaterialConfig {
            kind: "symmetric_key_32".to_string(),
            source: Some("env".to_string()),
            env: Some(String::new()),
            ..CryptoMaterialConfig::default()
        };

        assert!(matches!(
            validate_material("tenant-a/payload-v1", &empty_env_material, false),
            Err(CryptoSetupError::InvalidMaterialFileSource { reason, .. })
                if reason.contains("environment variable")
        ));
    }

    #[test]
    fn decode_direct_material_key_revalidates_env_source_name() {
        let env_material = CryptoMaterialConfig {
            kind: "symmetric_key_32".to_string(),
            source: Some("env".to_string()),
            env: Some("QDRANT/PAYLOAD_KEY".to_string()),
            ..CryptoMaterialConfig::default()
        };

        assert!(matches!(
            decode_direct_material_key("tenant-a/payload-v1", &env_material),
            Err(PayloadWriteSetupError::InvalidMaterialFileSource { reason, .. })
                if reason.contains("environment variable")
        ));
    }

    #[test]
    fn decode_direct_material_key_revalidates_source_shape() {
        let inline_with_path = CryptoMaterialConfig {
            kind: "symmetric_key_32".to_string(),
            source: Some("inline".to_string()),
            path: Some("/tmp/payload.key".to_string()),
            value_b64: Some(BASE64URL_NOPAD.encode(&[7u8; 32])),
            ..CryptoMaterialConfig::default()
        };
        assert!(matches!(
            decode_direct_material_key("tenant-a/payload-v1", &inline_with_path),
            Err(PayloadWriteSetupError::InvalidMaterialFileSource { reason, .. })
                if reason.contains("source fields")
        ));

        let vault_missing_field = CryptoMaterialConfig {
            kind: "symmetric_key_32".to_string(),
            source: Some("vault_kv2".to_string()),
            env: Some("QDRANT_TEST_VAULT_TOKEN".to_string()),
            path: Some("https://vault.example.com/v1/secret/data/docs".to_string()),
            ..CryptoMaterialConfig::default()
        };
        assert!(matches!(
            decode_direct_material_key("tenant-a/payload-v1", &vault_missing_field),
            Err(PayloadWriteSetupError::InvalidMaterialFileSource { reason, .. })
                if reason.contains("source fields")
        ));
    }

    #[test]
    fn validate_crypto_settings_validates_material_file_source() {
        let dir = tempfile::Builder::new()
            .prefix("qdrant-sec-material-")
            .tempdir_in(std::env::current_dir().unwrap())
            .unwrap();
        let key_path = dir.path().join("payload.key");
        std::fs::write(&key_path, BASE64URL_NOPAD.encode(&[7u8; 32])).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            let mut dir_permissions = std::fs::metadata(dir.path()).unwrap().permissions();
            dir_permissions.set_mode(0o700);
            std::fs::set_permissions(dir.path(), dir_permissions).unwrap();

            let mut permissions = std::fs::metadata(&key_path).unwrap().permissions();
            permissions.set_mode(0o600);
            std::fs::set_permissions(&key_path, permissions).unwrap();
        }

        let file_material = CryptoMaterialConfig {
            kind: "symmetric_key_32".to_string(),
            source: Some("file".to_string()),
            path: Some(key_path.to_string_lossy().to_string()),
            ..CryptoMaterialConfig::default()
        };
        assert_eq!(
            validate_material("tenant-a/payload-v1", &file_material, false),
            Ok(())
        );

        let relative_material = CryptoMaterialConfig {
            kind: "symmetric_key_32".to_string(),
            source: Some("file".to_string()),
            path: Some("payload.key".to_string()),
            ..CryptoMaterialConfig::default()
        };
        assert!(matches!(
            validate_material("tenant-a/payload-v1", &relative_material, false),
            Err(CryptoSetupError::InvalidMaterialFileSource { reason, .. })
                if reason.contains("absolute")
        ));

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            let mut permissions = std::fs::metadata(&key_path).unwrap().permissions();
            permissions.set_mode(0o644);
            std::fs::set_permissions(&key_path, permissions).unwrap();
            assert!(matches!(
                validate_material("tenant-a/payload-v1", &file_material, false),
                Err(CryptoSetupError::InvalidMaterialFileSource { reason, .. })
                    if reason.contains("group/world")
            ));

            let mut permissions = std::fs::metadata(&key_path).unwrap().permissions();
            permissions.set_mode(0o600);
            std::fs::set_permissions(&key_path, permissions).unwrap();
            let mut dir_permissions = std::fs::metadata(dir.path()).unwrap().permissions();
            dir_permissions.set_mode(0o722);
            std::fs::set_permissions(dir.path(), dir_permissions).unwrap();
            assert!(matches!(
                validate_material("tenant-a/payload-v1", &file_material, false),
                Err(CryptoSetupError::InvalidMaterialFileSource { reason, .. })
                    if reason.contains("parent directory")
            ));
        }
    }

    #[test]
    fn decode_direct_material_key_revalidates_file_source() {
        let dir = tempfile::Builder::new()
            .prefix("qdrant-sec-material-read-")
            .tempdir_in(std::env::current_dir().unwrap())
            .unwrap();
        let key_path = dir.path().join("payload.key");
        std::fs::write(&key_path, BASE64URL_NOPAD.encode(&[9u8; 32])).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            let mut dir_permissions = std::fs::metadata(dir.path()).unwrap().permissions();
            dir_permissions.set_mode(0o700);
            std::fs::set_permissions(dir.path(), dir_permissions).unwrap();

            let mut permissions = std::fs::metadata(&key_path).unwrap().permissions();
            permissions.set_mode(0o600);
            std::fs::set_permissions(&key_path, permissions).unwrap();
        }

        let file_material = CryptoMaterialConfig {
            kind: "symmetric_key_32".to_string(),
            source: Some("file".to_string()),
            path: Some(key_path.to_string_lossy().to_string()),
            ..CryptoMaterialConfig::default()
        };

        decode_direct_material_key("tenant-a/payload-v1", &file_material).unwrap();

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            let mut permissions = std::fs::metadata(&key_path).unwrap().permissions();
            permissions.set_mode(0o644);
            std::fs::set_permissions(&key_path, permissions).unwrap();

            assert!(matches!(
                decode_direct_material_key("tenant-a/payload-v1", &file_material),
                Err(PayloadWriteSetupError::InvalidMaterialFileSource { reason, .. })
                    if reason.contains("group/world")
            ));
        }
    }

    #[cfg(unix)]
    #[test]
    fn decode_direct_material_key_reads_fd_source() {
        use std::os::fd::AsRawFd;

        let dir = tempfile::Builder::new()
            .prefix("qdrant-sec-material-fd-")
            .tempdir_in(std::env::current_dir().unwrap())
            .unwrap();
        let key_path = dir.path().join("payload.key");
        std::fs::write(&key_path, BASE64URL_NOPAD.encode(&[11u8; 32])).unwrap();
        let file = std::fs::File::open(&key_path).unwrap();
        let fd_material = CryptoMaterialConfig {
            kind: "symmetric_key_32".to_string(),
            source: Some("fd".to_string()),
            fd: Some(file.as_raw_fd()),
            ..CryptoMaterialConfig::default()
        };

        assert_eq!(
            validate_material("tenant-a/payload-v1", &fd_material, false),
            Ok(())
        );
        let decoded = decode_direct_material_key("tenant-a/payload-v1", &fd_material).unwrap();
        let encryptor = PayloadTextEncryptor::new_from_resource_key_with_metadata(
            "docs-crypto-id",
            "tenant-a:payload",
            &decoded,
            "tenant-a/payload@v1",
            "tenant-a/payload-rk",
            3,
        )
        .unwrap();
        let policy = PayloadEncryptionPolicy::new(vec!["body".to_string()]).unwrap();
        let mut payload = json!({ "body": "fd-backed secret" })
            .as_object()
            .unwrap()
            .clone();
        encryptor
            .encrypt_selected_fields("1", &mut payload, &policy)
            .unwrap();
        encryptor
            .decrypt_selected_fields("1", &mut payload, &policy)
            .unwrap();
        assert_eq!(
            payload.get("body").and_then(Value::as_str),
            Some("fd-backed secret"),
        );
    }

    #[cfg(unix)]
    #[test]
    fn validate_material_fd_source_sets_close_on_exec() {
        use std::ffi::CString;
        use std::os::fd::{AsRawFd, FromRawFd};
        use std::os::unix::ffi::OsStrExt;

        let dir = tempfile::Builder::new()
            .prefix("qdrant-sec-material-fd-cloexec-")
            .tempdir_in(std::env::current_dir().unwrap())
            .unwrap();
        let key_path = dir.path().join("payload.key");
        std::fs::write(&key_path, BASE64URL_NOPAD.encode(&[13u8; 32])).unwrap();
        let path = CString::new(key_path.as_os_str().as_bytes()).unwrap();
        let raw_fd = unsafe { nix::libc::open(path.as_ptr(), nix::libc::O_RDONLY) };
        assert!(raw_fd >= 0);
        let file = unsafe { std::fs::File::from_raw_fd(raw_fd) };
        assert_eq!(
            unsafe { nix::libc::fcntl(file.as_raw_fd(), nix::libc::F_GETFD) }
                & nix::libc::FD_CLOEXEC,
            0,
        );

        let fd_material = CryptoMaterialConfig {
            kind: "symmetric_key_32".to_string(),
            source: Some("fd".to_string()),
            fd: Some(file.as_raw_fd()),
            ..CryptoMaterialConfig::default()
        };

        assert_eq!(
            validate_material("tenant-a/payload-v1", &fd_material, false),
            Ok(())
        );
        assert_ne!(
            unsafe { nix::libc::fcntl(file.as_raw_fd(), nix::libc::F_GETFD) }
                & nix::libc::FD_CLOEXEC,
            0,
        );
        let decoded = decode_direct_material_key("tenant-a/payload-v1", &fd_material).unwrap();
        PayloadTextEncryptor::new_from_resource_key_with_metadata(
            "docs-crypto-id",
            "tenant-a:payload",
            &decoded,
            "tenant-a/payload@v1",
            "tenant-a/payload-rk",
            3,
        )
        .unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn decode_direct_material_key_reads_unix_socket_source() {
        use std::io::Write;
        use std::os::unix::fs::PermissionsExt;
        use std::os::unix::net::UnixListener;

        let dir = tempfile::Builder::new()
            .prefix("qdrant-sec-material-socket-")
            .tempdir_in(std::env::current_dir().unwrap())
            .unwrap();
        let mut dir_permissions = std::fs::metadata(dir.path()).unwrap().permissions();
        dir_permissions.set_mode(0o700);
        std::fs::set_permissions(dir.path(), dir_permissions).unwrap();

        let socket_path = dir.path().join("payload.key.sock");
        let listener = UnixListener::bind(&socket_path).unwrap();
        let mut socket_permissions = std::fs::symlink_metadata(&socket_path)
            .unwrap()
            .permissions();
        socket_permissions.set_mode(0o600);
        std::fs::set_permissions(&socket_path, socket_permissions).unwrap();

        let encoded = BASE64URL_NOPAD.encode(&[17u8; 32]);
        let writer = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream.write_all(encoded.as_bytes()).unwrap();
        });

        let socket_material = CryptoMaterialConfig {
            kind: "symmetric_key_32".to_string(),
            source: Some("unix_socket".to_string()),
            path: Some(socket_path.to_string_lossy().to_string()),
            ..CryptoMaterialConfig::default()
        };

        assert_eq!(
            validate_material("tenant-a/payload-v1", &socket_material, false),
            Ok(())
        );
        let decoded = decode_direct_material_key("tenant-a/payload-v1", &socket_material).unwrap();
        writer.join().unwrap();

        let encryptor = PayloadTextEncryptor::new_from_resource_key_with_metadata(
            "docs-crypto-id",
            "tenant-a:payload",
            &decoded,
            "tenant-a/payload@v1",
            "tenant-a/payload-rk",
            3,
        )
        .unwrap();
        let policy = PayloadEncryptionPolicy::new(vec!["body".to_string()]).unwrap();
        let mut payload = json!({ "body": "socket-backed secret" })
            .as_object()
            .unwrap()
            .clone();
        encryptor
            .encrypt_selected_fields("1", &mut payload, &policy)
            .unwrap();
        encryptor
            .decrypt_selected_fields("1", &mut payload, &policy)
            .unwrap();
        assert_eq!(
            payload.get("body").and_then(Value::as_str),
            Some("socket-backed secret"),
        );
    }

    #[cfg(unix)]
    #[test]
    fn validate_material_unix_socket_source_rejects_relative_path() {
        let socket_material = CryptoMaterialConfig {
            kind: "symmetric_key_32".to_string(),
            source: Some("unix_socket".to_string()),
            path: Some("payload.key.sock".to_string()),
            ..CryptoMaterialConfig::default()
        };

        assert!(matches!(
            validate_material("tenant-a/payload-v1", &socket_material, false),
            Err(CryptoSetupError::InvalidMaterialFileSource { reason, .. })
                if reason.contains("absolute")
        ));
    }

    #[cfg(unix)]
    #[test]
    fn validate_material_unix_socket_source_rejects_symlink() {
        use std::os::unix::fs::{PermissionsExt, symlink};
        use std::os::unix::net::UnixListener;

        let dir = tempfile::Builder::new()
            .prefix("qdrant-sec-material-socket-symlink-")
            .tempdir_in(std::env::current_dir().unwrap())
            .unwrap();
        let mut dir_permissions = std::fs::metadata(dir.path()).unwrap().permissions();
        dir_permissions.set_mode(0o700);
        std::fs::set_permissions(dir.path(), dir_permissions).unwrap();

        let socket_path = dir.path().join("payload.key.sock.target");
        let symlink_path = dir.path().join("payload.key.sock");
        let _listener = UnixListener::bind(&socket_path).unwrap();
        let mut socket_permissions = std::fs::symlink_metadata(&socket_path)
            .unwrap()
            .permissions();
        socket_permissions.set_mode(0o600);
        std::fs::set_permissions(&socket_path, socket_permissions).unwrap();
        symlink(&socket_path, &symlink_path).unwrap();

        let socket_material = CryptoMaterialConfig {
            kind: "symmetric_key_32".to_string(),
            source: Some("unix_socket".to_string()),
            path: Some(symlink_path.to_string_lossy().to_string()),
            ..CryptoMaterialConfig::default()
        };

        assert!(matches!(
            validate_material("tenant-a/payload-v1", &socket_material, false),
            Err(CryptoSetupError::InvalidMaterialFileSource { reason, .. })
                if reason.contains("non-symlink Unix socket")
        ));
    }

    #[test]
    fn validate_material_vault_kv2_source_rejects_insecure_remote_http() {
        let vault_material = CryptoMaterialConfig {
            kind: "symmetric_key_32".to_string(),
            source: Some("vault_kv2".to_string()),
            env: Some("QDRANT_TEST_VAULT_TOKEN".to_string()),
            path: Some("http://vault.example.com/v1/secret/data/docs".to_string()),
            vault_field: Some("material".to_string()),
            ..CryptoMaterialConfig::default()
        };

        assert!(matches!(
            validate_material("tenant-a/payload-v1", &vault_material, false),
            Err(CryptoSetupError::InvalidMaterialFileSource { reason, .. })
                if reason.contains("https")
        ));
    }

    #[test]
    fn validate_material_vault_kv2_source_requires_field() {
        let vault_material = CryptoMaterialConfig {
            kind: "symmetric_key_32".to_string(),
            source: Some("vault_kv2".to_string()),
            env: Some("QDRANT_TEST_VAULT_TOKEN".to_string()),
            path: Some("https://vault.example.com/v1/secret/data/docs".to_string()),
            ..CryptoMaterialConfig::default()
        };

        assert_eq!(
            validate_material("tenant-a/payload-v1", &vault_material, false),
            Err(CryptoSetupError::MaterialSourceMismatch {
                material: "tenant-a/payload-v1".to_string(),
            }),
        );
    }

    #[test]
    fn validate_material_vault_kv2_source_rejects_query_and_fragment() {
        let query_material = CryptoMaterialConfig {
            kind: "symmetric_key_32".to_string(),
            source: Some("vault_kv2".to_string()),
            env: Some("QDRANT_TEST_VAULT_TOKEN".to_string()),
            path: Some("https://vault.example.com/v1/secret/data/docs?version=1".to_string()),
            vault_field: Some("material".to_string()),
            ..CryptoMaterialConfig::default()
        };
        assert!(matches!(
            validate_material("tenant-a/payload-v1", &query_material, false),
            Err(CryptoSetupError::InvalidMaterialFileSource { reason, .. })
                if reason.contains("query or fragment")
        ));

        let fragment_material = CryptoMaterialConfig {
            kind: "symmetric_key_32".to_string(),
            source: Some("vault_kv2".to_string()),
            env: Some("QDRANT_TEST_VAULT_TOKEN".to_string()),
            path: Some("https://vault.example.com/v1/secret/data/docs#material".to_string()),
            vault_field: Some("material".to_string()),
            ..CryptoMaterialConfig::default()
        };
        assert!(matches!(
            validate_material("tenant-a/payload-v1", &fragment_material, false),
            Err(CryptoSetupError::InvalidMaterialFileSource { reason, .. })
                if reason.contains("query or fragment")
        ));
    }

    #[test]
    fn validate_material_vault_kv2_source_rejects_url_credentials() {
        let credential_material = CryptoMaterialConfig {
            kind: "symmetric_key_32".to_string(),
            source: Some("vault_kv2".to_string()),
            env: Some("QDRANT_TEST_VAULT_TOKEN".to_string()),
            path: Some("https://user:pass@vault.example.com/v1/secret/data/docs".to_string()),
            vault_field: Some("material".to_string()),
            ..CryptoMaterialConfig::default()
        };

        assert!(matches!(
            validate_material("tenant-a/payload-v1", &credential_material, false),
            Err(CryptoSetupError::InvalidMaterialFileSource { reason, .. })
                if reason.contains("credentials")
        ));
    }

    #[test]
    fn decode_direct_material_key_reads_vault_kv2_source() {
        let mut server = mockito::Server::new();
        let encoded = BASE64URL_NOPAD.encode(&[19u8; 32]);
        let _mock = server
            .mock("GET", "/v1/secret/data/docs")
            .match_header("x-vault-token", "test-token")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(json!({ "data": { "data": { "material": encoded } } }).to_string())
            .create();
        unsafe {
            std::env::set_var("QDRANT_TEST_VAULT_TOKEN", "test-token");
        }

        let vault_material = CryptoMaterialConfig {
            kind: "symmetric_key_32".to_string(),
            source: Some("vault_kv2".to_string()),
            env: Some("QDRANT_TEST_VAULT_TOKEN".to_string()),
            path: Some(format!("{}/v1/secret/data/docs", server.url())),
            vault_field: Some("material".to_string()),
            ..CryptoMaterialConfig::default()
        };

        assert_eq!(
            validate_material("tenant-a/payload-v1", &vault_material, false),
            Ok(())
        );
        let decoded = decode_direct_material_key("tenant-a/payload-v1", &vault_material).unwrap();
        unsafe {
            std::env::remove_var("QDRANT_TEST_VAULT_TOKEN");
        }

        let encryptor = PayloadTextEncryptor::new_from_resource_key_with_metadata(
            "docs-crypto-id",
            "tenant-a:payload",
            &decoded,
            "tenant-a/payload@v1",
            "tenant-a/payload-rk",
            3,
        )
        .unwrap();
        let policy = PayloadEncryptionPolicy::new(vec!["body".to_string()]).unwrap();
        let mut payload = json!({ "body": "vault-backed secret" })
            .as_object()
            .unwrap()
            .clone();
        encryptor
            .encrypt_selected_fields("1", &mut payload, &policy)
            .unwrap();
        encryptor
            .decrypt_selected_fields("1", &mut payload, &policy)
            .unwrap();
        assert_eq!(
            payload.get("body").and_then(Value::as_str),
            Some("vault-backed secret"),
        );
    }

    #[test]
    fn decode_direct_material_key_rejects_oversized_vault_kv2_response() {
        let mut server = mockito::Server::new();
        let _mock = server
            .mock("GET", "/v1/secret/data/docs")
            .match_header("x-vault-token", "test-token")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body("x".repeat(VAULT_KV2_RESPONSE_MAX_BYTES as usize + 1))
            .create();
        unsafe {
            std::env::set_var("QDRANT_TEST_VAULT_TOKEN_OVERSIZED", "test-token");
        }

        let vault_material = CryptoMaterialConfig {
            kind: "symmetric_key_32".to_string(),
            source: Some("vault_kv2".to_string()),
            env: Some("QDRANT_TEST_VAULT_TOKEN_OVERSIZED".to_string()),
            path: Some(format!("{}/v1/secret/data/docs", server.url())),
            vault_field: Some("material".to_string()),
            ..CryptoMaterialConfig::default()
        };

        assert!(matches!(
            decode_direct_material_key("tenant-a/payload-v1", &vault_material),
            Err(PayloadWriteSetupError::InvalidMaterialFileSource { reason, .. })
                if reason.contains("maximum size")
        ));
        unsafe {
            std::env::remove_var("QDRANT_TEST_VAULT_TOKEN_OVERSIZED");
        }
    }

    #[test]
    fn decode_direct_material_key_rejects_vault_kv2_redirect() {
        let mut server = mockito::Server::new();
        let encoded = BASE64URL_NOPAD.encode(&[23u8; 32]);
        let _redirect = server
            .mock("GET", "/v1/secret/data/redirect")
            .match_header("x-vault-token", "test-token")
            .with_status(302)
            .with_header("location", &format!("{}/v1/secret/data/docs", server.url()))
            .create();
        let _target = server
            .mock("GET", "/v1/secret/data/docs")
            .match_header("x-vault-token", "test-token")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(json!({ "data": { "data": { "material": encoded } } }).to_string())
            .create();
        unsafe {
            std::env::set_var("QDRANT_TEST_VAULT_TOKEN_REDIRECT", "test-token");
        }

        let vault_material = CryptoMaterialConfig {
            kind: "symmetric_key_32".to_string(),
            source: Some("vault_kv2".to_string()),
            env: Some("QDRANT_TEST_VAULT_TOKEN_REDIRECT".to_string()),
            path: Some(format!("{}/v1/secret/data/redirect", server.url())),
            vault_field: Some("material".to_string()),
            ..CryptoMaterialConfig::default()
        };

        assert!(matches!(
            decode_direct_material_key("tenant-a/payload-v1", &vault_material),
            Err(PayloadWriteSetupError::UnreadableMaterialFile { .. })
        ));
        unsafe {
            std::env::remove_var("QDRANT_TEST_VAULT_TOKEN_REDIRECT");
        }
    }

    #[cfg(unix)]
    #[test]
    fn decode_direct_material_key_rejects_symlink_file_source() {
        use std::os::unix::fs::{PermissionsExt, symlink};

        let dir = tempfile::Builder::new()
            .prefix("qdrant-sec-material-symlink-")
            .tempdir_in(std::env::current_dir().unwrap())
            .unwrap();
        let target_path = dir.path().join("payload.key.target");
        let symlink_path = dir.path().join("payload.key");
        std::fs::write(&target_path, BASE64URL_NOPAD.encode(&[9u8; 32])).unwrap();
        symlink(&target_path, &symlink_path).unwrap();

        let mut dir_permissions = std::fs::metadata(dir.path()).unwrap().permissions();
        dir_permissions.set_mode(0o700);
        std::fs::set_permissions(dir.path(), dir_permissions).unwrap();

        let mut permissions = std::fs::metadata(&target_path).unwrap().permissions();
        permissions.set_mode(0o600);
        std::fs::set_permissions(&target_path, permissions).unwrap();

        let file_material = CryptoMaterialConfig {
            kind: "symmetric_key_32".to_string(),
            source: Some("file".to_string()),
            path: Some(symlink_path.to_string_lossy().to_string()),
            ..CryptoMaterialConfig::default()
        };

        assert!(matches!(
            decode_direct_material_key("tenant-a/payload-v1", &file_material),
            Err(PayloadWriteSetupError::InvalidMaterialFileSource { reason, .. })
                if reason.contains("non-symlink")
        ));
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
    fn validate_crypto_settings_enforces_destroyed_resource_key_shredding() {
        let destroyed = CryptoSettings {
            materials: HashMap::from([(
                "tenant-a/payload-rk-v1".to_string(),
                CryptoMaterialConfig {
                    kind: WRAPPED_SYMMETRIC_KEY_32_KIND.to_string(),
                    rk_epoch: Some(3),
                    state: Some(RESOURCE_KEY_STATE_DESTROYED.to_string()),
                    scope: Some("collection:docs".to_string()),
                    ..CryptoMaterialConfig::default()
                },
            )]),
            ..CryptoSettings::default()
        };
        validate_crypto_settings(&destroyed).unwrap();

        let retained_key_material = CryptoSettings {
            materials: HashMap::from([(
                "tenant-a/payload-rk-v1".to_string(),
                CryptoMaterialConfig {
                    kind: WRAPPED_SYMMETRIC_KEY_32_KIND.to_string(),
                    wrapped_by: Some("tenant-a/mk-v1".to_string()),
                    wrap_algorithm: Some(RESOURCE_KEY_WRAP_ALGORITHM.to_string()),
                    nonce: Some("nonce".to_string()),
                    wrapped_key_b64: Some("wrapped".to_string()),
                    rk_epoch: Some(3),
                    state: Some(RESOURCE_KEY_STATE_DESTROYED.to_string()),
                    scope: Some("collection:docs".to_string()),
                    ..CryptoMaterialConfig::default()
                },
            )]),
            ..CryptoSettings::default()
        };
        assert_eq!(
            validate_crypto_settings(&retained_key_material),
            Err(CryptoSetupError::InvalidWrappedMaterial {
                material: "tenant-a/payload-rk-v1".to_string(),
                reason: "destroyed resource keys must not retain wrapped key material".to_string(),
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
                    sha256_b64: Some(BASE64URL_NOPAD.encode(&[0_u8; 32])),
                    size: Some(4),
                    timeout_ms: Some(5_000),
                },
            ),
            Err(CryptoSetupError::InvalidBackendProgram {
                backend: "openfhe_local".to_string(),
                program: "relative-openfhe-bridge".to_string(),
            }),
        );

        assert_eq!(
            validate_backend(
                "openfhe_local",
                &CryptoBackendConfig {
                    kind: "shell".to_string(),
                    program: Some("/usr/local/bin/openfhe-bridge".to_string()),
                    sha256_b64: None,
                    size: None,
                    timeout_ms: Some(5_000),
                },
            ),
            Err(CryptoSetupError::UnsupportedBackendKind {
                backend: "openfhe_local".to_string(),
                kind: "shell".to_string(),
            }),
        );
    }

    fn current_exe_sha256_b64() -> String {
        let program = std::env::current_exe().unwrap();
        BASE64URL_NOPAD.encode(&Sha256::digest(std::fs::read(program).unwrap()))
    }

    #[test]
    fn validate_backend_verifies_bridge_sha256_pin() {
        let dir = tempfile::Builder::new()
            .prefix("qdrant-sec-bridge-")
            .tempdir_in(std::env::current_dir().unwrap())
            .unwrap();
        let bridge_path = dir.path().join("openfhe-bridge");
        std::fs::write(&bridge_path, b"#!/bin/sh\nexit 0\n").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            let mut dir_permissions = std::fs::metadata(dir.path()).unwrap().permissions();
            dir_permissions.set_mode(0o700);
            std::fs::set_permissions(dir.path(), dir_permissions).unwrap();

            let mut permissions = std::fs::metadata(&bridge_path).unwrap().permissions();
            permissions.set_mode(0o700);
            std::fs::set_permissions(&bridge_path, permissions).unwrap();
        }

        let expected_digest = BASE64URL_NOPAD.encode(&Sha256::digest(b"#!/bin/sh\nexit 0\n"));
        assert_eq!(
            validate_backend(
                "openfhe_local",
                &CryptoBackendConfig {
                    kind: "process_pool".to_string(),
                    program: Some(bridge_path.to_string_lossy().to_string()),
                    sha256_b64: Some(expected_digest),
                    size: Some(1),
                    timeout_ms: Some(5_000),
                },
            ),
            Ok(()),
        );

        assert_eq!(
            validate_backend(
                "openfhe_local",
                &CryptoBackendConfig {
                    kind: "process_pool".to_string(),
                    program: Some(bridge_path.to_string_lossy().to_string()),
                    sha256_b64: None,
                    size: Some(1),
                    timeout_ms: Some(5_000),
                },
            ),
            Err(CryptoSetupError::MissingBackendSha256Pin {
                backend: "openfhe_local".to_string(),
            }),
        );

        assert!(matches!(
            validate_backend(
                "openfhe_local",
                &CryptoBackendConfig {
                    kind: "process_pool".to_string(),
                    program: Some(bridge_path.to_string_lossy().to_string()),
                    sha256_b64: Some(BASE64URL_NOPAD.encode(&[0_u8; 32])),
                    size: Some(1),
                    timeout_ms: Some(5_000),
                },
            ),
            Err(CryptoSetupError::InvalidBackendProgram { .. }),
        ));
    }

    #[test]
    fn openfhe_backend_factory_requires_bridge_sha256_pin() {
        let program = std::env::current_exe().unwrap();
        let err = openfhe_backend_from_config(
            "openfhe_local",
            &CryptoBackendConfig {
                kind: "process".to_string(),
                program: Some(program.to_string_lossy().to_string()),
                sha256_b64: None,
                size: None,
                timeout_ms: Some(5_000),
            },
        )
        .expect_err("backend construction must reject missing bridge sha256 pin");

        assert!(matches!(
            err,
            StorageError::BadInput { description }
                if description.contains("requires sha256_b64 program pin")
        ));
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
    fn validate_backend_rejects_zero_timeout() {
        let program = std::env::current_exe()
            .unwrap()
            .to_string_lossy()
            .into_owned();

        assert_eq!(
            validate_backend(
                "openfhe_local",
                &CryptoBackendConfig {
                    kind: "process".to_string(),
                    program: Some(program),
                    sha256_b64: Some(current_exe_sha256_b64()),
                    size: None,
                    timeout_ms: Some(0),
                },
            ),
            Err(CryptoSetupError::InvalidBackendTimeout {
                backend: "openfhe_local".to_string(),
                reason: "timeout_ms must be at least 1".to_string(),
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

        let mut settings_with_unsupported_option = settings.clone();
        settings_with_unsupported_option
            .crypto
            .instances
            .get_mut("docs_payload_v1")
            .unwrap()
            .options
            .as_object_mut()
            .unwrap()
            .insert(
                EXPECTED_RK_ID_OPTION.to_string(),
                json!("tenant-a/client-rk-v1"),
            );
        assert!(matches!(
            payload_write_plan_for_collection(&settings_with_unsupported_option, "docs", &params),
            Err(PayloadWriteSetupError::UnsupportedInstanceOption { instance, option })
                if instance == "docs_payload_v1" && option == EXPECTED_RK_ID_OPTION
        ));

        let mut settings_with_unsupported_material_role = settings.clone();
        settings_with_unsupported_material_role
            .crypto
            .instances
            .get_mut("docs_payload_v1")
            .unwrap()
            .materials
            .insert("client_key".to_string(), "tenant-a/payload-v1".to_string());
        assert!(matches!(
            payload_write_plan_for_collection(
                &settings_with_unsupported_material_role,
                "docs",
                &params
            ),
            Err(PayloadWriteSetupError::UnsupportedInstanceOption { instance, option })
                if instance == "docs_payload_v1" && option == "materials.client_key"
        ));

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
            body.get("$qdrant_sec")
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
                .and_then(|body| body.get("$qdrant_sec"))
                .and_then(|marker| marker.get("encryption_epoch"))
                .and_then(|epoch| epoch.as_u64()),
            Some(6),
        );
        assert_eq!(
            payload
                .0
                .get("body")
                .and_then(|body| body.get("$qdrant_sec"))
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
    fn validate_collection_crypto_runtime_rejects_client_envelopes_in_clustered_mode() {
        let (_, public_key) =
            signed_client_envelope("docs", "point-1", "body", "tenant-a/client-signing-v1");
        let mut settings = Settings {
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
        settings.cluster.enabled = true;
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

        let err = validate_collection_crypto_runtime_inner(&settings, "docs", &params)
            .expect_err("clustered client-side envelope collection must fail closed");
        assert!(matches!(
            err,
            StorageError::BadInput { description }
                if description.contains("cluster-wide nonce replay ledger")
                    && description.contains(PAYLOAD_CLIENT_AEAD_PROVIDER)
        ));
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
            json!({ "body": { "$qdrant_sec": { "kind": "payload_text" } } })
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
                        "kdf_domain": "qdrant-sec/client-payload-text/v1",
                        "aad": {
                            "collection_id": "docs",
                            "point_id": "point-2",
                            "field_path": "body",
                            "schema_version": 1
                        },
                        "nonce": "AAAAAAAAAAAAAAAA",
                        "ciphertext": "AAAAAAAAAAAAAAAAAAAAAA"
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
                &settings_with_options(json!({
                    "key_id": "tenant-a/client-rk-2026-04",
                    "signature_key_id": "tenant-a/client-signing-v1",
                    "signature_public_key_b64": BASE64URL_NOPAD.encode(&[11u8; 32]),
                    "retired_materials": [],
                })),
                "docs",
                &params,
            ),
            Err(PayloadWriteSetupError::UnsupportedInstanceOption { instance, option })
                if instance == "docs_payload_client_v1" && option == RETIRED_MATERIALS_OPTION
        ));

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
                    "kdf_domain": "qdrant-sec/client-payload-text/v1",
                    "aad": {
                        "collection_id": "docs",
                        "point_id": "point-1",
                        "field_path": "body",
                        "schema_version": 1
                    },
                    "nonce": "AAAAAAAAAAAAAAAA",
                    "ciphertext": "AAAAAAAAAAAAAAAAAAAAAA",
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
            .insert(
                "ciphertext".to_string(),
                Value::String("AQEBAQEBAQEBAQEBAQEBAQ".to_string()),
            );
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
                    "kdf_domain": "qdrant-sec/client-payload-text/v1",
                    "aad": {
                        "collection_id": "docs",
                        "point_id": "point-1",
                        "field_path": "body",
                        "schema_version": 1
                    },
                    "nonce": "AAAAAAAAAAAAAAAA",
                    "ciphertext": "AAAAAAAAAAAAAAAAAAAAAA",
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
            body.get("$qdrant_sec")
                .and_then(|marker| marker.get("envelope"))
                .and_then(|envelope| envelope.get("material_fingerprint"))
                .and_then(|fingerprint| fingerprint.as_str()),
            Some("tenant-a/payload-rk@v3"),
        );
        assert_eq!(
            body.get("$qdrant_sec")
                .and_then(|marker| marker.get("envelope"))
                .and_then(|envelope| envelope.get("rk_id"))
                .and_then(|rk_id| rk_id.as_str()),
            Some(rk_material),
        );
        assert_eq!(
            body.get("$qdrant_sec")
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
    fn runtime_resource_key_batch_rewrap_updates_active_and_retired_keys_only() {
        let old_mk_material = "tenant-a/mk-v1";
        let new_mk_material = "tenant-a/mk-v2";
        let other_mk_material = "tenant-a/mk-v3";
        let active_rk_material = "tenant-a/payload-rk-v3";
        let retired_rk_material = "tenant-a/payload-rk-v2";
        let unrelated_rk_material = "tenant-a/other-rk-v1";
        let destroyed_rk_material = "tenant-a/destroyed-rk-v1";
        let wrap_resource_key_config =
            |rk_material: &str,
             rk_secret: [u8; 32],
             rk_epoch: u64,
             scope: &str,
             wrapped_by: &str,
             mk_secret: [u8; 32],
             state: Option<&str>| {
                let mut config = CryptoMaterialConfig {
                    kind: WRAPPED_SYMMETRIC_KEY_32_KIND.to_string(),
                    wrapped_by: Some(wrapped_by.to_string()),
                    wrap_algorithm: Some(RESOURCE_KEY_WRAP_ALGORITHM.to_string()),
                    rk_epoch: Some(rk_epoch),
                    scope: Some(scope.to_string()),
                    state: state.map(ToString::to_string),
                    ..CryptoMaterialConfig::default()
                };
                let aad = resource_key_wrap_aad(
                    rk_material,
                    &config,
                    wrapped_by,
                    RESOURCE_KEY_WRAP_ALGORITHM,
                );
                let wrapped =
                    LocalMasterKeyProvider::new(wrapped_by, SecretKey::from_bytes(mk_secret))
                        .unwrap()
                        .wrap_resource_key(&SecretKey::from_bytes(rk_secret), &aad)
                        .unwrap();
                config.nonce = Some(wrapped.nonce);
                config.wrapped_key_b64 = Some(wrapped.wrapped_key);
                config
            };
        let active_rk_config = wrap_resource_key_config(
            active_rk_material,
            [92u8; 32],
            3,
            "collection:docs",
            old_mk_material,
            [91u8; 32],
            None,
        );
        let retired_rk_config = wrap_resource_key_config(
            retired_rk_material,
            [94u8; 32],
            2,
            "collection:docs",
            old_mk_material,
            [91u8; 32],
            Some(RESOURCE_KEY_STATE_RETIRED),
        );
        let unrelated_rk_config = wrap_resource_key_config(
            unrelated_rk_material,
            [96u8; 32],
            1,
            "collection:other",
            other_mk_material,
            [95u8; 32],
            None,
        );
        let destroyed_rk_config = CryptoMaterialConfig {
            kind: WRAPPED_SYMMETRIC_KEY_32_KIND.to_string(),
            rk_epoch: Some(1),
            scope: Some("collection:docs".to_string()),
            state: Some(RESOURCE_KEY_STATE_DESTROYED.to_string()),
            ..CryptoMaterialConfig::default()
        };
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
                (
                    other_mk_material.to_string(),
                    CryptoMaterialConfig {
                        kind: WRAPPING_KEY_32_KIND.to_string(),
                        source: Some("inline".to_string()),
                        value_b64: Some(BASE64URL_NOPAD.encode(&[95u8; 32])),
                        ..CryptoMaterialConfig::default()
                    },
                ),
                (active_rk_material.to_string(), active_rk_config),
                (retired_rk_material.to_string(), retired_rk_config),
                (unrelated_rk_material.to_string(), unrelated_rk_config),
                (destroyed_rk_material.to_string(), destroyed_rk_config),
            ]),
            backends: HashMap::new(),
        };
        let old_active_resource_key = decode_wrapped_resource_key(
            &runtime_settings,
            active_rk_material,
            runtime_settings.materials.get(active_rk_material).unwrap(),
        )
        .unwrap();
        let old_retired_resource_key = decode_wrapped_resource_key_for_state(
            &runtime_settings,
            retired_rk_material,
            runtime_settings.materials.get(retired_rk_material).unwrap(),
            RESOURCE_KEY_STATE_RETIRED,
        )
        .unwrap();
        let policy = PayloadEncryptionPolicy::new(["body"]).unwrap();
        let mut active_payload = segment::types::Payload(
            json!({ "body": "active mk rotation batch" })
                .as_object()
                .unwrap()
                .clone(),
        );
        PayloadTextEncryptor::new_from_resource_key_with_metadata(
            "docs",
            "tenant-a:docs",
            &old_active_resource_key,
            "tenant-a/payload-rk@v3",
            active_rk_material,
            3,
        )
        .unwrap()
        .encrypt_selected_fields("point-1", &mut active_payload.0, &policy)
        .unwrap();
        let mut retired_payload = segment::types::Payload(
            json!({ "body": "retired mk rotation batch" })
                .as_object()
                .unwrap()
                .clone(),
        );
        PayloadTextEncryptor::new_from_resource_key_with_metadata(
            "docs",
            "tenant-a:docs",
            &old_retired_resource_key,
            "tenant-a/payload-rk@v2",
            retired_rk_material,
            2,
        )
        .unwrap()
        .encrypt_selected_fields("point-2", &mut retired_payload.0, &policy)
        .unwrap();

        let rewrapped = rewrap_runtime_resource_key_materials_by_master_key(
            &runtime_settings,
            old_mk_material,
            new_mk_material,
        )
        .unwrap();

        assert_eq!(rewrapped.len(), 2);
        assert!(rewrapped.contains_key(active_rk_material));
        assert!(rewrapped.contains_key(retired_rk_material));
        assert!(!rewrapped.contains_key(unrelated_rk_material));
        assert!(!rewrapped.contains_key(destroyed_rk_material));
        assert_eq!(
            rewrapped
                .get(active_rk_material)
                .unwrap()
                .wrapped_by
                .as_deref(),
            Some(new_mk_material),
        );
        assert_eq!(
            rewrapped
                .get(retired_rk_material)
                .unwrap()
                .wrapped_by
                .as_deref(),
            Some(new_mk_material),
        );
        assert_eq!(
            rewrapped.get(retired_rk_material).unwrap().state.as_deref(),
            Some(RESOURCE_KEY_STATE_RETIRED),
        );
        assert_eq!(rewrapped.get(active_rk_material).unwrap().rk_epoch, Some(3));
        assert_eq!(
            rewrapped.get(retired_rk_material).unwrap().rk_epoch,
            Some(2),
        );

        let mut rewrapped_settings = runtime_settings.clone();
        for (material_name, material) in rewrapped {
            rewrapped_settings.materials.insert(material_name, material);
        }
        let new_active_resource_key = decode_wrapped_resource_key(
            &rewrapped_settings,
            active_rk_material,
            rewrapped_settings
                .materials
                .get(active_rk_material)
                .unwrap(),
        )
        .unwrap();
        let new_retired_resource_key = decode_wrapped_resource_key_for_state(
            &rewrapped_settings,
            retired_rk_material,
            rewrapped_settings
                .materials
                .get(retired_rk_material)
                .unwrap(),
            RESOURCE_KEY_STATE_RETIRED,
        )
        .unwrap();
        assert_eq!(
            PayloadTextEncryptor::new_from_resource_key_with_metadata(
                "docs",
                "tenant-a:docs",
                &new_active_resource_key,
                "tenant-a/payload-rk@v3",
                active_rk_material,
                3,
            )
            .unwrap()
            .decrypt_selected_fields("point-1", &mut active_payload.0, &policy)
            .unwrap(),
            1,
        );
        assert_eq!(
            PayloadTextEncryptor::new_from_resource_key_with_metadata(
                "docs",
                "tenant-a:docs",
                &new_retired_resource_key,
                "tenant-a/payload-rk@v2",
                retired_rk_material,
                2,
            )
            .unwrap()
            .decrypt_selected_fields("point-2", &mut retired_payload.0, &policy)
            .unwrap(),
            1,
        );
        assert_eq!(
            active_payload.0.get("body").and_then(Value::as_str),
            Some("active mk rotation batch"),
        );
        assert_eq!(
            retired_payload.0.get("body").and_then(Value::as_str),
            Some("retired mk rotation batch"),
        );
    }

    #[test]
    fn payload_write_plan_rejects_legacy_collection_and_runtime_ckks() {
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

        assert!(matches!(
            payload_write_plan_for_collection(&settings, "docs", &params),
            Err(PayloadWriteSetupError::LegacyCkksUnsupported)
        ));
    }

    #[test]
    fn legacy_payload_write_plan_rejects_explicit_crypto_collection_id() {
        let settings = Settings {
            ckks: CkksConfig {
                enabled: true,
                allow_inline_key_material: true,
                key_id: Some("tenant-a:docs".to_string()),
                resource_key_b64: Some(BASE64URL_NOPAD.encode(&[5u8; 32])),
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

        assert!(matches!(
            payload_write_plan_for_collection_with_crypto_id(
                &settings,
                "docs",
                "crypto-docs-uuid",
                &params,
            ),
            Err(PayloadWriteSetupError::LegacyCkksUnsupported)
        ));
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
                                "crypto_context_b64": BASE64URL_NOPAD.encode(b"openfhe context"),
                                "public_key_b64": BASE64URL_NOPAD.encode(b"openfhe public key"),
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
        let params = with_embedding_vector(
            CollectionParams {
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
            },
            Distance::Dot,
        );

        validate_collection_crypto_runtime_inner(&settings, "docs", &params).unwrap();

        for distance in [Distance::Cosine, Distance::Euclid, Distance::Manhattan] {
            let params = with_embedding_vector(
                CollectionParams {
                    encryption: params.encryption.clone(),
                    ..CollectionParams::empty()
                },
                distance,
            );
            validate_collection_crypto_runtime_inner(&settings, "docs", &params).unwrap();
        }

        let mut settings_with_extra_vector_role = settings.clone();
        settings_with_extra_vector_role
            .crypto
            .instances
            .get_mut("docs_vector_v1")
            .unwrap()
            .materials
            .insert("payload_key".to_string(), "tenant-a/vector-v1".to_string());
        let err = validate_collection_crypto_runtime_inner(
            &settings_with_extra_vector_role,
            "docs",
            &params,
        )
        .unwrap_err();
        assert!(
            matches!(err, StorageError::BadInput { description } if description.contains("unsupported material role payload_key"))
        );
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

        let err = validate_collection_crypto_runtime_inner(&settings, "docs", &params).unwrap_err();
        assert!(
            matches!(err, StorageError::BadInput { ref description } if description.contains("unknown payload crypto instance docs_payload_v1")),
            "unexpected error: {err:?}",
        );
    }

    #[test]
    fn validate_create_collection_crypto_runtime_rejects_invalid_crypto_selectors() {
        let settings = Settings::new(None).unwrap();
        let params = CollectionParams {
            encryption: Some(CollectionEncryptionConfig {
                version: 1,
                key_id: Some("tenant-a:docs".to_string()),
                crypto_schema_version: 1,
                encryption_epoch: 0,
                migration_state: CryptoMigrationState::Active,
                rules: vec![EncryptionRuleRef {
                    id: "metadata_conf".to_string(),
                    selector: EncryptionSelector::MetadataKeys {
                        keys: vec!["embedding".to_string()],
                    },
                    instance: "docs_metadata_v1".to_string(),
                    binding: Some("metadata-value/v1".to_string()),
                }],
            }),
            ..CollectionParams::empty()
        };

        let err = validate_create_collection_crypto_runtime(
            &settings,
            "docs",
            &create_collection_with_params(params),
        )
        .expect_err("create-time metadata value selector must fail schema validation");
        assert!(
            matches!(err, StorageError::BadInput { ref description }
                if description.contains("collection docs crypto config is invalid")
                    && description.contains("unsupported_metadata_encryption_binding")),
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
        let err = validate_create_collection_crypto_runtime(
            &settings,
            "docs",
            &create_collection_with_params(legacy_params),
        )
        .expect_err("create-time legacy vector selector must fail schema validation");
        assert!(
            matches!(err, StorageError::BadInput { ref description }
                if description.contains("collection docs crypto config is invalid")
                    && description.contains("unsupported_ckks_vector_selector")),
            "unexpected error: {err:?}",
        );
    }

    #[test]
    fn validate_collection_crypto_runtime_accepts_metadata_blind_index_selectors() {
        let settings = Settings {
            crypto: CryptoSettings {
                instances: HashMap::from([(
                    "docs_metadata_v1".to_string(),
                    CryptoInstanceConfig {
                        provider: METADATA_BLIND_INDEX_PROVIDER.to_string(),
                        options: json!({
                            "key_id": "tenant-a:docs",
                            "expected_rk_id": "tenant-a:docs",
                            "min_rk_epoch": 3,
                            "max_rk_epoch": 3,
                        }),
                        ..CryptoInstanceConfig::default()
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
                    id: "body_blind_eq".to_string(),
                    selector: EncryptionSelector::MetadataKeys {
                        keys: vec!["body__blind_eq".to_string()],
                    },
                    instance: "docs_metadata_v1".to_string(),
                    binding: Some("metadata-exact-match-token/v1".to_string()),
                }],
            }),
            ..CollectionParams::empty()
        };

        validate_collection_crypto_runtime(&settings, "docs", &params).unwrap();

        let mut settings_with_material = settings.clone();
        settings_with_material
            .crypto
            .instances
            .get_mut("docs_metadata_v1")
            .unwrap()
            .materials
            .insert("sym_key".to_string(), "tenant-a/blind-v1".to_string());
        let err = validate_collection_crypto_runtime(&settings_with_material, "docs", &params)
            .expect_err("metadata blind-index provider must stay server blind");
        assert!(
            matches!(err, StorageError::BadInput { ref description }
                if description.contains("metadata blind-index instance docs_metadata_v1 must not configure server materials")),
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
                    id: "metadata_conf".to_string(),
                    selector: EncryptionSelector::MetadataKeys {
                        keys: vec!["embedding".to_string()],
                    },
                    instance: "docs_metadata_v1".to_string(),
                    binding: Some("metadata-value/v1".to_string()),
                }],
            }),
            ..CollectionParams::empty()
        };

        let err = validate_recovered_collection_crypto_runtime(&settings, "docs", &params)
            .expect_err("recovered metadata value selector must fail schema validation");
        assert!(
            matches!(err, StorageError::BadInput { ref description }
                if description.contains("recovered collection docs encryption config is invalid")
                    && description.contains("unsupported_metadata_encryption_binding")),
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
    fn validate_recovered_collection_crypto_config_rejects_wrong_wrapped_rk_key() {
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
                            value_b64: Some(BASE64URL_NOPAD.encode(&[90u8; 32])),
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

        let err = validate_recovered_collection_crypto_config(
            &settings,
            "docs",
            &recovered_config(params, Some(Uuid::new_v4())),
        )
        .expect_err("wrong wrapped RK key must fail restore preflight");
        assert!(
            matches!(err, StorageError::BadInput { ref description }
                if description.contains("payload crypto runtime validation failed")),
            "unexpected error: {err:?}",
        );
    }

    #[test]
    fn validate_recovered_collection_crypto_config_rejects_payload_key_id_mismatch() {
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
                            "key_id": "tenant-a:other",
                            "material_fingerprint_id": "tenant-a/payload@v1",
                        }),
                    },
                )]),
                materials: HashMap::from([(
                    "tenant-a/payload-v1".to_string(),
                    CryptoMaterialConfig {
                        kind: SYMMETRIC_KEY_32_KIND.to_string(),
                        source: Some("inline".to_string()),
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
            &recovered_config(params, Some(Uuid::new_v4())),
        )
        .expect_err("payload key-id mismatch must fail restore preflight");
        assert!(
            matches!(err, StorageError::BadInput { ref description }
                if description.contains("payload crypto runtime validation failed")
                    && description.contains("key id does not match")),
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

        let err = validate_collection_crypto_runtime_inner(&settings, "docs", &params).unwrap_err();
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

        let err = validate_collection_crypto_runtime_inner(&settings, "docs", &params).unwrap_err();
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
                            "crypto_context_b64": BASE64URL_NOPAD.encode(b"openfhe context"),
                            "public_key_b64": BASE64URL_NOPAD.encode(b"openfhe public key"),
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
        let params = with_embedding_vector(
            CollectionParams {
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
            },
            Distance::Dot,
        );

        validate_collection_crypto_runtime_inner(&settings, "docs", &params).unwrap();
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

        let err = validate_collection_crypto_runtime_inner(&settings, "docs", &params).unwrap_err();
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

        let err = validate_collection_crypto_runtime_inner(&settings, "docs", &params).unwrap_err();
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

        let err = validate_collection_crypto_runtime_inner(&settings, "docs", &params).unwrap_err();
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
                            "crypto_context_b64": BASE64URL_NOPAD.encode(b"openfhe context"),
                            "public_key_b64": BASE64URL_NOPAD.encode(b"openfhe public key"),
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

        let err = validate_collection_crypto_runtime_inner(&settings, "docs", &params).unwrap_err();
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
                        options: json!({
                            "key_id": "tenant-a:docs",
                            "profile": CKKS_PROFILE_OPENFHE_128_N16384_D4_SCALE50,
                            "crypto_context_b64": BASE64URL_NOPAD.encode(b"openfhe context"),
                            "public_key_b64": BASE64URL_NOPAD.encode(b"openfhe public key"),
                        }),
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

        let err = validate_collection_crypto_runtime_inner(&settings, "docs", &params).unwrap_err();
        assert!(
            matches!(err, StorageError::BadInput { description } if description.contains("metadata key material binding"))
        );
    }
}
