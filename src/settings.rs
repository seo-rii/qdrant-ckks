use std::borrow::Cow;
use std::collections::HashMap;
use std::{env, fmt, io};

use api::grpc::transport_channel_pool::{
    DEFAULT_CONNECT_TIMEOUT, DEFAULT_GRPC_TIMEOUT, DEFAULT_POOL_SIZE,
};
use collection::operations::validation;
use collection::shards::shard::PeerId;
use common::flags::FeatureFlags;
use config::{Config, ConfigError, Environment, File, FileFormat, Source};
use serde::Deserialize;
use storage::types::StorageConfig;
use validator::{Validate, ValidationError, ValidationErrors};

use crate::common::audit::AuditConfig;
use crate::common::debugger::DebuggerConfig;
use crate::common::inference::config::InferenceConfig;
use crate::tracing;

const MAX_PEER_ID: u64 = (1 << 53) - 1;

const DEFAULT_CONFIG: &str = include_str!("../config/config.yaml");

#[derive(Debug, Deserialize, Validate, Clone)]
pub struct ServiceConfig {
    #[validate(length(min = 1))]
    pub host: String,
    pub http_port: u16,
    pub grpc_port: Option<u16>, // None means that gRPC is disabled

    /// If specified, qdrant will serve a separate service for `/metrics` on this port.
    /// Separate port is not protected by API keys and dedicated for internal monitoring systems.
    /// This port should not be exposed to untrusted networks.
    #[serde(default)]
    pub metrics_port: Option<u16>,

    pub max_request_size_mb: usize,
    pub max_workers: Option<usize>,
    /// Keep-alive timeout for incoming HTTP connections in seconds.
    #[serde(default = "default_http_keep_alive_timeout_sec")]
    #[validate(range(min = 1))]
    pub http_keep_alive_timeout_sec: u64,
    /// Timeout for reading HTTP request data from clients in seconds.
    #[serde(default = "default_http_client_request_timeout_sec")]
    #[validate(range(min = 1))]
    pub http_client_request_timeout_sec: u64,
    /// Timeout for client disconnect handling in seconds.
    #[serde(default = "default_http_client_disconnect_timeout_sec")]
    #[validate(range(min = 1))]
    pub http_client_disconnect_timeout_sec: u64,
    #[serde(default = "default_cors")]
    pub enable_cors: bool,
    #[serde(default)]
    pub enable_tls: bool,
    #[serde(default)]
    pub verify_https_client_certificate: bool,
    pub api_key: Option<String>,

    /// Same as `api_key`, can be used for rolling key rotation.
    pub alt_api_key: Option<String>,

    pub read_only_api_key: Option<String>,
    #[serde(default)]
    pub jwt_rbac: Option<bool>,

    #[serde(default)]
    pub hide_jwt_dashboard: Option<bool>,

    /// Directory where static files are served from.
    /// For example, the Web-UI should be placed here.
    #[serde(default)]
    pub static_content_dir: Option<String>,

    /// If serving of the static content is enabled.
    /// This includes the Web-UI. True by default.
    #[serde(default)]
    pub enable_static_content: Option<bool>,

    /// How much time is considered too long for a query to execute.
    pub slow_query_secs: Option<f32>,

    /// Whether to enable reporting of measured hardware utilization in API responses.
    #[serde(default)]
    pub hardware_reporting: Option<bool>,

    /// Global prefix for metrics.
    #[serde(default)]
    #[validate(custom(function = validate_metrics_prefix))]
    pub metrics_prefix: Option<String>,
}

impl ServiceConfig {
    pub fn hardware_reporting(&self) -> bool {
        self.hardware_reporting.unwrap_or_default()
    }
}

#[derive(Debug, Deserialize, Clone, Default, Validate)]
pub struct ClusterConfig {
    pub enabled: bool, // disabled by default
    #[serde(default)]
    #[validate(range(min = 1, max = MAX_PEER_ID))]
    pub peer_id: Option<PeerId>,
    #[serde(default = "default_timeout_ms")]
    #[validate(range(min = 1))]
    pub grpc_timeout_ms: u64,
    #[serde(default = "default_connection_timeout_ms")]
    #[validate(range(min = 1))]
    pub connection_timeout_ms: u64,
    #[serde(default)]
    #[validate(nested)]
    pub p2p: P2pConfig,
    #[serde(default)]
    #[validate(nested)]
    pub consensus: ConsensusConfig,
    #[serde(default)]
    pub resharding_enabled: bool, // disabled by default
}

#[derive(Debug, Deserialize, Clone, Validate)]
pub struct P2pConfig {
    #[serde(default)]
    pub port: Option<u16>,
    #[serde(default = "default_connection_pool_size")]
    #[validate(range(min = 1))]
    pub connection_pool_size: usize,
    #[serde(default)]
    pub enable_tls: bool,
}

impl Default for P2pConfig {
    fn default() -> Self {
        P2pConfig {
            port: None,
            connection_pool_size: default_connection_pool_size(),
            enable_tls: false,
        }
    }
}

#[derive(Debug, Deserialize, Clone, Validate)]
pub struct ConsensusConfig {
    #[serde(default = "default_max_message_queue_size")]
    pub max_message_queue_size: usize, // controls the back-pressure at the Raft level
    #[serde(default = "default_tick_period_ms")]
    #[validate(range(min = 1))]
    pub tick_period_ms: u64,
    #[serde(default = "default_bootstrap_timeout_sec")]
    #[validate(range(min = 1))]
    pub bootstrap_timeout_sec: u64,
    #[validate(range(min = 1))]
    #[serde(default = "default_message_timeout_tics")]
    pub message_timeout_ticks: u64,
    /// Compact WAL when it grows to enough applied entries
    #[serde(default = "default_compact_wal_entries")]
    pub compact_wal_entries: u64,
}

impl Default for ConsensusConfig {
    fn default() -> Self {
        ConsensusConfig {
            max_message_queue_size: default_max_message_queue_size(),
            tick_period_ms: default_tick_period_ms(),
            bootstrap_timeout_sec: default_bootstrap_timeout_sec(),
            message_timeout_ticks: default_message_timeout_tics(),
            compact_wal_entries: default_compact_wal_entries(),
        }
    }
}

#[derive(Debug, Deserialize, Clone, Validate)]
pub struct TlsConfig {
    pub cert: String,
    pub key: String,
    pub ca_cert: Option<String>,
    #[serde(default = "default_tls_cert_ttl")]
    #[validate(range(min = 1))]
    pub cert_ttl: Option<u64>,
}

#[allow(dead_code)]
#[derive(Clone, Debug, Deserialize, Validate)]
pub struct GpuConfig {
    /// Enable GPU indexing.
    #[serde(default)]
    pub indexing: bool,
    /// Force half precision for `f32` values while indexing.
    /// `f16` conversion will take place only inside GPU memory and won't affect storage type.
    #[serde(default)]
    pub force_half_precision: bool,
    /// Used vulkan "groups" of GPU. In other words, how many parallel points can be indexed by GPU.
    /// Optimal value might depend on the GPU model.
    /// Proportional, but doesn't necessary equal to the physical number of warps.
    /// Do not change this value unless you know what you are doing.
    /// Default: 512
    #[serde(default)]
    #[validate(range(min = 1))]
    pub groups_count: Option<usize>,
    /// Filter for GPU devices by hardware name. Case insensitive.
    /// Comma-separated list of substrings to match against the gpu device name.
    /// Example: "nvidia"
    /// Default: "" - all devices are accepted.
    #[serde(default)]
    pub device_filter: String,
    /// List of explicit GPU devices to use.
    /// If host has multiple GPUs, this option allows to select specific devices
    /// by their index in the list of found devices.
    /// If `device_filter` is set, indexes are applied after filtering.
    /// By default, all devices are accepted.
    #[serde(default)]
    pub devices: Option<Vec<usize>>,
    /// How many parallel indexing processes are allowed to run.
    /// Default: 1
    #[serde(default)]
    pub parallel_indexes: Option<usize>,
    /// Allow to use integrated GPUs.
    /// Default: false
    #[serde(default)]
    pub allow_integrated: bool,
    /// Allow to use emulated GPUs like LLVMpipe. Useful for CI.
    /// Default: false
    #[serde(default)]
    pub allow_emulated: bool,
}

fn validate_crypto_runtime_identifier(value: &str) -> Result<(), ValidationError> {
    if value.is_empty()
        || value.len() > 128
        || !value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'-' | b'/' | b'@')
        })
    {
        return Err(ValidationError::new("invalid_crypto_runtime_identifier"));
    }

    Ok(())
}

fn validate_optional_crypto_runtime_identifier(
    value: &Option<String>,
) -> Result<(), ValidationError> {
    if let Some(value) = value {
        validate_crypto_runtime_identifier(value)?;
    }

    Ok(())
}

fn validate_crypto_material_bindings(
    bindings: &HashMap<String, String>,
) -> Result<(), ValidationError> {
    for (role, reference) in bindings {
        validate_crypto_runtime_identifier(role)?;
        validate_crypto_runtime_identifier(reference)?;
    }

    Ok(())
}

fn default_crypto_options() -> serde_json::Value {
    serde_json::Value::Object(Default::default())
}

#[derive(Deserialize, Clone, Default, Validate)]
pub struct CryptoMaterialConfig {
    #[validate(custom(function = "validate_crypto_runtime_identifier"))]
    pub kind: String,
    #[serde(default)]
    pub source: Option<String>,
    #[serde(default)]
    pub env: Option<String>,
    #[serde(default)]
    pub path: Option<String>,
    #[serde(default)]
    pub value_b64: Option<String>,
    #[serde(default)]
    #[validate(custom(function = "validate_crypto_runtime_identifier"))]
    pub wrapped_by: Option<String>,
    #[serde(default)]
    pub wrap_algorithm: Option<String>,
    #[serde(default)]
    pub nonce: Option<String>,
    #[serde(default)]
    pub wrapped_key_b64: Option<String>,
    #[serde(default)]
    pub rk_epoch: Option<u64>,
    #[serde(default)]
    pub scope: Option<String>,
}

impl fmt::Debug for CryptoMaterialConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CryptoMaterialConfig")
            .field("kind", &self.kind)
            .field("source", &self.source)
            .field("env", &self.env)
            .field("path", &self.path)
            .field("value_b64", &self.value_b64.as_ref().map(|_| "[redacted]"))
            .field("wrapped_by", &self.wrapped_by)
            .field("wrap_algorithm", &self.wrap_algorithm)
            .field("nonce", &self.nonce.as_ref().map(|_| "[redacted]"))
            .field(
                "wrapped_key_b64",
                &self.wrapped_key_b64.as_ref().map(|_| "[redacted]"),
            )
            .field("rk_epoch", &self.rk_epoch)
            .field("scope", &self.scope)
            .finish()
    }
}

#[derive(Debug, Deserialize, Clone, Default, Validate)]
pub struct CryptoBackendConfig {
    #[validate(custom(function = "validate_crypto_runtime_identifier"))]
    pub kind: String,
    #[serde(default)]
    pub program: Option<String>,
    #[serde(default)]
    pub sha256_b64: Option<String>,
    #[serde(default)]
    pub size: Option<usize>,
    #[serde(default)]
    pub timeout_ms: Option<u64>,
}

#[derive(Debug, Deserialize, Clone, Default)]
pub struct CryptoInstanceConfig {
    pub provider: String,
    #[serde(default)]
    pub materials: HashMap<String, String>,
    #[serde(default)]
    pub backend_ref: Option<String>,
    #[serde(default = "default_crypto_options")]
    pub options: serde_json::Value,
}

impl Validate for CryptoInstanceConfig {
    fn validate(&self) -> Result<(), ValidationErrors> {
        let mut errors = ValidationErrors::new();

        if let Err(error) = validate_crypto_runtime_identifier(&self.provider) {
            errors.add("provider", error);
        }
        if let Err(error) = validate_crypto_material_bindings(&self.materials) {
            errors.add("materials", error);
        }
        if let Err(error) = validate_optional_crypto_runtime_identifier(&self.backend_ref) {
            errors.add("backend_ref", error);
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }
}

const fn default_allow_inline_key_material() -> bool {
    false
}

#[derive(Debug, Deserialize, Clone, Validate)]
pub struct CryptoSettings {
    #[serde(default = "default_allow_inline_key_material")]
    pub allow_inline_key_material: bool,
    #[serde(default)]
    #[validate(nested)]
    pub instances: HashMap<String, CryptoInstanceConfig>,
    #[serde(default)]
    #[validate(nested)]
    pub materials: HashMap<String, CryptoMaterialConfig>,
    #[serde(default)]
    #[validate(nested)]
    pub backends: HashMap<String, CryptoBackendConfig>,
}

impl Default for CryptoSettings {
    fn default() -> Self {
        Self {
            allow_inline_key_material: default_allow_inline_key_material(),
            instances: HashMap::new(),
            materials: HashMap::new(),
            backends: HashMap::new(),
        }
    }
}

impl CryptoSettings {
    pub const LEGACY_CKKS_PAYLOAD_INSTANCE: &str = "legacy_ckks_payload";
    pub const LEGACY_CKKS_VECTOR_INSTANCE: &str = "legacy_ckks_vector";

    pub fn is_configured(&self) -> bool {
        !self.instances.is_empty() || !self.materials.is_empty() || !self.backends.is_empty()
    }

    pub fn legacy_ckks_payload_instance_for_collection(collection: &str) -> String {
        format!("{}/{}", Self::LEGACY_CKKS_PAYLOAD_INSTANCE, collection)
    }

    pub fn legacy_ckks_vector_instance_for_collection(collection: &str) -> String {
        format!("{}/{}", Self::LEGACY_CKKS_VECTOR_INSTANCE, collection)
    }

    pub fn from_legacy_ckks(ckks: &CkksConfig) -> Self {
        let mut settings = Self::default();
        settings.allow_inline_key_material = ckks.allow_inline_key_material;

        let insert_payload_instance =
            |settings: &mut Self,
             instance_name: String,
             key_id: Option<String>,
             material_ref: Option<String>| {
                let materials = material_ref
                    .into_iter()
                    .map(|reference| ("sym_key".to_string(), reference))
                    .collect();
                settings.instances.insert(
                    instance_name,
                    CryptoInstanceConfig {
                        provider: "payload/aes-256-gcm@v1".to_string(),
                        materials,
                        backend_ref: None,
                        options: serde_json::json!({ "key_id": key_id }),
                    },
                );
            };
        let insert_vector_instance =
            |settings: &mut Self,
             instance_name: String,
             key_id: Option<String>,
             material_ref: Option<String>,
             backend_ref: Option<String>| {
                let materials = material_ref
                    .into_iter()
                    .map(|reference| ("sym_key".to_string(), reference))
                    .collect();
                settings.instances.insert(
                    instance_name,
                    CryptoInstanceConfig {
                        provider: "vector/openfhe-ckks@v1".to_string(),
                        materials,
                        backend_ref,
                        options: serde_json::json!({ "key_id": key_id }),
                    },
                );
            };

        let default_material_ref = ckks
            .master_key_b64
            .as_ref()
            .map(|_| "legacy_ckks/default/master_key".to_string());
        if let Some(master_key_b64) = &ckks.master_key_b64 {
            settings.materials.insert(
                "legacy_ckks/default/master_key".to_string(),
                CryptoMaterialConfig {
                    kind: "symmetric_key_32".to_string(),
                    source: Some("inline".to_string()),
                    env: None,
                    path: None,
                    value_b64: Some(master_key_b64.clone()),
                    ..CryptoMaterialConfig::default()
                },
            );
        }

        let default_backend_ref = ckks
            .openfhe_bridge_path
            .as_ref()
            .map(|_| "legacy_ckks/default/backend".to_string());
        if let Some(path) = &ckks.openfhe_bridge_path {
            settings.backends.insert(
                "legacy_ckks/default/backend".to_string(),
                CryptoBackendConfig {
                    kind: "process_pool".to_string(),
                    program: Some(path.clone()),
                    sha256_b64: ckks.openfhe_bridge_sha256_b64.clone(),
                    size: Some(1),
                    timeout_ms: None,
                },
            );
        }

        if ckks.enabled || ckks.key_id.is_some() || default_material_ref.is_some() {
            insert_payload_instance(
                &mut settings,
                Self::LEGACY_CKKS_PAYLOAD_INSTANCE.to_string(),
                ckks.key_id.clone(),
                default_material_ref.clone(),
            );
        }

        if ckks.enabled || ckks.key_id.is_some() || default_backend_ref.is_some() {
            insert_vector_instance(
                &mut settings,
                Self::LEGACY_CKKS_VECTOR_INSTANCE.to_string(),
                ckks.key_id.clone(),
                default_material_ref.clone(),
                default_backend_ref.clone(),
            );
        }

        for (collection, config) in &ckks.collections {
            if !config.is_configured() {
                continue;
            }

            let material_ref = config
                .master_key_b64
                .as_ref()
                .map(|_| format!("legacy_ckks/{collection}/master_key"));
            if let Some(master_key_b64) = &config.master_key_b64 {
                settings.materials.insert(
                    format!("legacy_ckks/{collection}/master_key"),
                    CryptoMaterialConfig {
                        kind: "symmetric_key_32".to_string(),
                        source: Some("inline".to_string()),
                        env: None,
                        path: None,
                        value_b64: Some(master_key_b64.clone()),
                        ..CryptoMaterialConfig::default()
                    },
                );
            }

            let backend_ref = config
                .openfhe_bridge_path
                .as_ref()
                .map(|_| format!("legacy_ckks/{collection}/backend"));
            if let Some(path) = &config.openfhe_bridge_path {
                settings.backends.insert(
                    format!("legacy_ckks/{collection}/backend"),
                    CryptoBackendConfig {
                        kind: "process_pool".to_string(),
                        program: Some(path.clone()),
                        sha256_b64: config.openfhe_bridge_sha256_b64.clone(),
                        size: Some(1),
                        timeout_ms: None,
                    },
                );
            }

            insert_payload_instance(
                &mut settings,
                Self::legacy_ckks_payload_instance_for_collection(collection),
                config.key_id.clone().or_else(|| ckks.key_id.clone()),
                material_ref
                    .clone()
                    .or_else(|| default_material_ref.clone()),
            );
            insert_vector_instance(
                &mut settings,
                Self::legacy_ckks_vector_instance_for_collection(collection),
                config.key_id.clone().or_else(|| ckks.key_id.clone()),
                material_ref.or_else(|| default_material_ref.clone()),
                backend_ref.or_else(|| default_backend_ref.clone()),
            );
        }

        settings
    }
}

#[derive(Deserialize, Clone, Default, Validate)]
pub struct CkksCollectionKeyConfig {
    /// Runtime key id for one collection. If omitted, collection params or default key id are used.
    #[serde(default)]
    pub key_id: Option<String>,
    /// Base64url-no-padding encoded 32-byte AES key for this collection.
    #[serde(default)]
    pub master_key_b64: Option<String>,
    /// External OpenFHE bridge executable for this collection.
    #[serde(default)]
    pub openfhe_bridge_path: Option<String>,
    /// Optional base64url-no-padding SHA-256 digest for this collection's OpenFHE bridge executable.
    #[serde(default)]
    pub openfhe_bridge_sha256_b64: Option<String>,
}

impl fmt::Debug for CkksCollectionKeyConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CkksCollectionKeyConfig")
            .field("key_id", &self.key_id)
            .field(
                "master_key_b64",
                &self.master_key_b64.as_ref().map(|_| "[redacted]"),
            )
            .field("openfhe_bridge_path", &self.openfhe_bridge_path)
            .field("openfhe_bridge_sha256_b64", &self.openfhe_bridge_sha256_b64)
            .finish()
    }
}

impl CkksCollectionKeyConfig {
    pub fn is_configured(&self) -> bool {
        self.key_id.is_some()
            || self.master_key_b64.is_some()
            || self.openfhe_bridge_path.is_some()
            || self.openfhe_bridge_sha256_b64.is_some()
    }
}

#[derive(Deserialize, Clone, Validate)]
pub struct CkksConfig {
    /// Global CKKS master switch. Collections still need `params.ckks.enabled: true`.
    #[serde(default)]
    pub enabled: bool,
    /// Allow inline key material in runtime config. Disabled by default; enable only for local development.
    #[serde(default = "default_allow_inline_key_material")]
    pub allow_inline_key_material: bool,
    /// Default key id used when neither collection params nor collection runtime config set one.
    #[serde(default)]
    pub key_id: Option<String>,
    /// Default base64url-no-padding encoded 32-byte AES key.
    #[serde(default)]
    pub master_key_b64: Option<String>,
    /// Default external OpenFHE bridge executable for CKKS vector encryption.
    #[serde(default)]
    pub openfhe_bridge_path: Option<String>,
    /// Optional base64url-no-padding SHA-256 digest for the default OpenFHE bridge executable.
    #[serde(default)]
    pub openfhe_bridge_sha256_b64: Option<String>,
    /// Collection-specific key material. Prefer this over default key material.
    #[serde(default)]
    #[validate(nested)]
    pub collections: HashMap<String, CkksCollectionKeyConfig>,
}

impl Default for CkksConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            allow_inline_key_material: default_allow_inline_key_material(),
            key_id: None,
            master_key_b64: None,
            openfhe_bridge_path: None,
            openfhe_bridge_sha256_b64: None,
            collections: HashMap::new(),
        }
    }
}

impl fmt::Debug for CkksConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CkksConfig")
            .field("enabled", &self.enabled)
            .field("allow_inline_key_material", &self.allow_inline_key_material)
            .field("key_id", &self.key_id)
            .field(
                "master_key_b64",
                &self.master_key_b64.as_ref().map(|_| "[redacted]"),
            )
            .field("openfhe_bridge_path", &self.openfhe_bridge_path)
            .field("openfhe_bridge_sha256_b64", &self.openfhe_bridge_sha256_b64)
            .field("collections", &self.collections)
            .finish()
    }
}

impl CkksConfig {
    pub fn is_configured(&self) -> bool {
        self.enabled
            || self.key_id.is_some()
            || self.master_key_b64.is_some()
            || self.openfhe_bridge_path.is_some()
            || self.openfhe_bridge_sha256_b64.is_some()
            || self
                .collections
                .values()
                .any(CkksCollectionKeyConfig::is_configured)
    }
}

fn validate_settings_crypto_sections(settings: &Settings) -> Result<(), ValidationError> {
    if settings.crypto.is_configured() && settings.ckks.is_configured() {
        return Err(ValidationError::new("conflicting_runtime_crypto_sections"));
    }

    Ok(())
}

#[derive(Debug, Deserialize, Clone, Validate)]
#[validate(schema(function = "validate_settings_crypto_sections"))]
pub struct Settings {
    #[serde(default)]
    pub log_level: Option<String>,
    #[serde(default)]
    pub logger: tracing::LoggerConfig,
    #[validate(nested)]
    pub storage: StorageConfig,
    #[validate(nested)]
    pub service: ServiceConfig,
    #[serde(default)]
    #[validate(nested)]
    pub cluster: ClusterConfig,
    #[serde(default = "default_telemetry_disabled")]
    pub telemetry_disabled: bool,
    #[validate(nested)]
    pub tls: Option<TlsConfig>,
    #[serde(default)]
    pub debugger: DebuggerConfig,
    /// A list of messages for errors that happened during loading the configuration. We collect
    /// them and store them here while loading because then our logger is not configured yet.
    /// We therefore need to log these messages later, after the logger is ready.
    #[serde(default, skip)]
    pub load_errors: Vec<LogMsg>,
    #[serde(default)]
    pub inference: Option<InferenceConfig>,
    #[serde(default)]
    #[validate(nested)]
    pub gpu: Option<GpuConfig>,
    #[serde(default)]
    pub feature_flags: FeatureFlags,
    /// Audit logging configuration.
    #[serde(default)]
    pub audit: Option<AuditConfig>,
    #[serde(default)]
    #[validate(nested)]
    pub crypto: CryptoSettings,
    #[serde(default)]
    #[validate(nested)]
    pub ckks: CkksConfig,
}

impl Settings {
    pub fn new(custom_config_path: Option<String>) -> Result<Self, ConfigError> {
        let mut load_errors = vec![];
        let config_exists = |path| File::with_name(path).collect().is_ok();

        // Check if custom config file exists, report error if not
        if let Some(path) = &custom_config_path
            && !config_exists(path)
        {
            load_errors.push(LogMsg::Error(format!(
                "Config file via --config-path is not found: {path}"
            )));
        }

        let env = env::var("RUN_MODE").unwrap_or_else(|_| "development".into());
        let config_path_env = format!("config/{env}");

        // Report error if main or env config files exist, report warning if not
        // Check if main and env configuration file
        load_errors.extend(
            ["config/config", &config_path_env]
                .into_iter()
                .filter(|path| !config_exists(path))
                .map(|path| LogMsg::Warn(format!("Config file not found: {path}"))),
        );

        // Configuration builder: define different levels of configuration files
        let mut config = Config::builder()
            // Start with compile-time base config
            .add_source(File::from_str(DEFAULT_CONFIG, FileFormat::Yaml))
            // Merge main config: config/config
            .add_source(File::with_name("config/config").required(false))
            // Merge env config: config/{env}
            // Uses RUN_MODE, defaults to 'development'
            .add_source(File::with_name(&config_path_env).required(false))
            // Merge local config, not tracked in git: config/local
            .add_source(File::with_name("config/local").required(false));

        #[cfg(feature = "deb")]
        {
            // Read config, installed with deb package
            config = config.add_source(File::with_name("/etc/qdrant/config").required(false));
        }

        // Merge user provided config with --config-path
        if let Some(path) = custom_config_path {
            config = config.add_source(File::with_name(&path).required(false));
        }

        // Merge environment settings
        // E.g.: `QDRANT_DEBUG=1 ./target/app` would set `debug=true`
        config = config.add_source(Environment::with_prefix("QDRANT").separator("__"));

        // Build and merge config and deserialize into Settings, attach any load errors we had
        let mut settings: Settings = config.build()?.try_deserialize()?;
        settings.load_errors.extend(load_errors);
        Ok(settings)
    }

    pub fn tls(&self) -> io::Result<&TlsConfig> {
        self.tls
            .as_ref()
            .ok_or_else(Self::tls_config_is_undefined_error)
    }

    pub fn tls_config_is_undefined_error() -> io::Error {
        io::Error::other("TLS config is not defined in the Qdrant config file")
    }

    pub fn validate_and_warn(&self) {
        //
        // JWT RBAC
        //
        // Using HMAC-SHA256, recommended secret size is 32 bytes
        const JWT_RECOMMENDED_SECRET_LENGTH: usize = 256 / 8;

        let all_keys_are_empty = self
            .service
            .api_key
            .as_deref()
            .unwrap_or_default()
            .is_empty()
            && self
                .service
                .alt_api_key
                .as_deref()
                .unwrap_or_default()
                .is_empty();

        let min_length = [
            self.service.api_key.as_ref(),
            self.service.alt_api_key.as_ref(),
        ]
        .into_iter()
        .flatten()
        .map(|key| key.len())
        .min()
        .unwrap_or_default();

        let any_api_key_is_short = min_length < JWT_RECOMMENDED_SECRET_LENGTH;

        // Log if JWT RBAC is enabled but no API key is set
        if self.service.jwt_rbac.unwrap_or_default() {
            if all_keys_are_empty {
                log::warn!("JWT RBAC configured but no API key set, JWT RBAC is not enabled")
            // Log if JWT RAC is enabled, API key is set but smaller than recommended size for JWT secret
            } else if any_api_key_is_short {
                log::warn!(
                    "It is highly recommended to use an API key of {JWT_RECOMMENDED_SECRET_LENGTH} bytes when JWT RBAC is enabled",
                )
            }
        }

        // Print any load error messages we had
        self.load_errors.iter().for_each(LogMsg::log);

        if let Err(ref errs) = self.validate() {
            validation::warn_validation_errors("Settings configuration file", errs);
        }
    }
}

/// Returns the number of maximum actix workers.
pub fn max_web_workers(settings: &Settings) -> usize {
    match settings.service.max_workers {
        Some(0) => {
            let num_cpu = common::cpu::get_num_cpus();
            std::cmp::max(1, num_cpu - 1)
        }
        Some(max_workers) => max_workers,
        None => settings.storage.performance.max_search_threads,
    }
}

#[derive(Clone, Debug)]
pub enum LogMsg {
    Warn(String),
    Error(String),
}

impl LogMsg {
    fn log(&self) {
        match self {
            Self::Warn(msg) => log::warn!("{msg}"),
            Self::Error(msg) => log::error!("{msg}"),
        }
    }
}

const fn default_telemetry_disabled() -> bool {
    false
}

const fn default_cors() -> bool {
    true
}

const fn default_http_keep_alive_timeout_sec() -> u64 {
    5
}

const fn default_http_client_request_timeout_sec() -> u64 {
    5
}

const fn default_http_client_disconnect_timeout_sec() -> u64 {
    5
}

const fn default_timeout_ms() -> u64 {
    DEFAULT_GRPC_TIMEOUT.as_millis() as u64
}

const fn default_connection_timeout_ms() -> u64 {
    DEFAULT_CONNECT_TIMEOUT.as_millis() as u64
}

const fn default_tick_period_ms() -> u64 {
    100
}

// Should not be less than `DEFAULT_META_OP_WAIT` as bootstrapping perform sync. consensus meta operations.
const fn default_bootstrap_timeout_sec() -> u64 {
    15
}

const fn default_max_message_queue_size() -> usize {
    100
}

const fn default_connection_pool_size() -> usize {
    DEFAULT_POOL_SIZE
}

const fn default_message_timeout_tics() -> u64 {
    10
}

const fn default_compact_wal_entries() -> u64 {
    128
}

#[allow(clippy::unnecessary_wraps)] // Used as serde default
const fn default_tls_cert_ttl() -> Option<u64> {
    // Default one hour
    Some(3600)
}

/// Custom validation function for metrics prefixes.
fn validate_metrics_prefix(prefix: &str) -> Result<(), ValidationError> {
    // Prefix is not required
    if prefix.is_empty() {
        return Ok(());
    }

    // Only allow alphanumeric characters or '_'
    if !prefix
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_')
    {
        return Err(
            ValidationError::new("invalid_metrics_prefix").with_message(Cow::Borrowed(
                "Metrics prefix must be of all alphanumeric characters, with an exception for '_'",
            )),
        );
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use fs_err as fs;
    use sealed_test::prelude::*;

    use super::*;

    /// Ensure we can successfully deserialize into [`Settings`] with just the default configuration.
    #[test]
    fn test_default_config() {
        let config = Config::builder()
            .add_source(File::from_str(DEFAULT_CONFIG, FileFormat::Yaml))
            .build()
            .expect("failed to build default config")
            .try_deserialize::<Settings>()
            .expect("failed to deserialize default config");

        assert_eq!(
            config.service.http_keep_alive_timeout_sec,
            default_http_keep_alive_timeout_sec()
        );
        assert_eq!(
            config.service.http_client_request_timeout_sec,
            default_http_client_request_timeout_sec()
        );
        assert_eq!(
            config.service.http_client_disconnect_timeout_sec,
            default_http_client_disconnect_timeout_sec()
        );
        assert!(!config.crypto.is_configured());
        assert!(!config.ckks.enabled);
        assert!(config.ckks.collections.is_empty());

        config
            .validate()
            .expect("failed to validate default config");
    }

    #[expect(
        clippy::disallowed_methods,
        reason = "#[sealed_test] uses std::fs::copy"
    )]
    #[expect(clippy::disallowed_types, reason = "#[sealed_test] uses std::fs::File")]
    #[sealed_test(files = ["config/config.yaml", "config/development.yaml"])]
    fn test_runtime_development_config() {
        unsafe { env::set_var("RUN_MODE", "development") };

        // `sealed_test` copies files into the same directory as the test runs in.
        // We need them in a subdirectory.
        fs::create_dir("config").expect("failed to create `config` subdirectory.");
        fs::copy("config.yaml", "config/config.yaml").expect("failed to copy `config.yaml`.");
        fs::copy("development.yaml", "config/development.yaml")
            .expect("failed to copy `development.yaml`.");

        // Read config
        let config = Settings::new(None).expect("failed to load development config at runtime");

        // Validate
        config
            .validate()
            .expect("failed to validate development config at runtime");
        assert!(config.load_errors.is_empty(), "must not have load errors")
    }

    #[expect(clippy::disallowed_types, reason = "#[sealed_test] uses std::fs::File")]
    #[sealed_test]
    fn test_no_config_files() {
        let non_existing_config_path = "config/non_existing_config".to_string();

        // Read config
        let config = Settings::new(Some(non_existing_config_path))
            .expect("failed to load with non-existing runtime config");

        // Validate
        config
            .validate()
            .expect("failed to validate with non-existing runtime config");
        assert!(!config.load_errors.is_empty(), "must have load errors")
    }

    #[expect(clippy::disallowed_types, reason = "#[sealed_test] uses std::fs::File")]
    #[sealed_test]
    fn test_custom_config() {
        let path = "config/custom.yaml";

        // Create custom config file
        {
            fs::create_dir("config").unwrap();
            let mut custom = fs::File::create(path).unwrap();
            write!(&mut custom, "service:\n    http_port: 9999").unwrap();
            custom.flush().unwrap();
        }

        // Load settings with custom config
        let config = Settings::new(Some(path.into())).unwrap();

        // Ensure our custom config is the most important
        assert_eq!(config.service.http_port, 9999);
        assert_eq!(
            config.service.http_keep_alive_timeout_sec,
            default_http_keep_alive_timeout_sec()
        );
        assert_eq!(
            config.service.http_client_request_timeout_sec,
            default_http_client_request_timeout_sec()
        );
        assert_eq!(
            config.service.http_client_disconnect_timeout_sec,
            default_http_client_disconnect_timeout_sec()
        );
    }

    #[expect(clippy::disallowed_types, reason = "#[sealed_test] uses std::fs::File")]
    #[sealed_test]
    fn test_custom_http_transport_config() {
        let path = "config/custom_http_transport.yaml";

        {
            fs::create_dir("config").unwrap();
            let mut custom = fs::File::create(path).unwrap();
            write!(
                &mut custom,
                "service:\n    http_keep_alive_timeout_sec: 120\n    http_client_request_timeout_sec: 45\n    http_client_disconnect_timeout_sec: 60"
            )
            .unwrap();
            custom.flush().unwrap();
        }

        let config = Settings::new(Some(path.into())).unwrap();
        config
            .validate()
            .expect("custom HTTP transport timeouts must pass validation");

        assert_eq!(config.service.http_keep_alive_timeout_sec, 120);
        assert_eq!(config.service.http_client_request_timeout_sec, 45);
        assert_eq!(config.service.http_client_disconnect_timeout_sec, 60);
    }

    #[test]
    fn test_crypto_and_ckks_sections_conflict() {
        let config = Config::builder()
            .add_source(File::from_str(DEFAULT_CONFIG, FileFormat::Yaml))
            .add_source(File::from_str(
                r#"
crypto:
  instances:
    docs_payload_v1:
      provider: payload/aes-256-gcm@v1
      materials:
        sym_key: tenant-a/payload-v1
  materials:
    tenant-a/payload-v1:
      kind: symmetric_key_32
      source: inline
      value_b64: AQID
ckks:
  enabled: true
"#,
                FileFormat::Yaml,
            ))
            .build()
            .expect("failed to build config")
            .try_deserialize::<Settings>()
            .expect("failed to deserialize config");

        assert!(config.validate().is_err());
    }

    #[test]
    fn test_crypto_settings_from_legacy_ckks() {
        let crypto = CryptoSettings::from_legacy_ckks(&CkksConfig {
            enabled: true,
            allow_inline_key_material: true,
            key_id: Some("tenant-a:docs".to_string()),
            master_key_b64: Some("AQID".to_string()),
            openfhe_bridge_path: Some("/usr/local/bin/openfhe-bridge".to_string()),
            openfhe_bridge_sha256_b64: None,
            collections: HashMap::from([(
                "docs".to_string(),
                CkksCollectionKeyConfig {
                    key_id: Some("tenant-a:docs-override".to_string()),
                    master_key_b64: Some("BAUG".to_string()),
                    openfhe_bridge_path: Some("/usr/local/bin/openfhe-bridge-docs".to_string()),
                    openfhe_bridge_sha256_b64: None,
                },
            )]),
        });

        assert!(crypto.is_configured());
        assert!(
            crypto
                .instances
                .contains_key(CryptoSettings::LEGACY_CKKS_PAYLOAD_INSTANCE)
        );
        assert!(
            crypto
                .instances
                .contains_key(&CryptoSettings::legacy_ckks_payload_instance_for_collection("docs"))
        );
        assert_eq!(
            crypto.instances[CryptoSettings::LEGACY_CKKS_VECTOR_INSTANCE].materials["sym_key"],
            "legacy_ckks/default/master_key"
        );
        assert_eq!(
            crypto.instances[&CryptoSettings::legacy_ckks_vector_instance_for_collection("docs")]
                .materials["sym_key"],
            "legacy_ckks/docs/master_key"
        );
        assert!(
            crypto
                .materials
                .contains_key("legacy_ckks/default/master_key")
        );
        assert!(crypto.materials.contains_key("legacy_ckks/docs/master_key"));
        assert!(crypto.backends.contains_key("legacy_ckks/default/backend"));
        assert!(crypto.backends.contains_key("legacy_ckks/docs/backend"));
    }

    #[test]
    fn test_inline_key_material_defaults_to_disabled() {
        assert!(!CryptoSettings::default().allow_inline_key_material);
        assert!(!CkksConfig::default().allow_inline_key_material);
    }

    #[expect(clippy::disallowed_types, reason = "#[sealed_test] uses std::fs::File")]
    #[sealed_test]
    fn test_invalid_http_transport_config() {
        let path = "config/invalid_http_transport.yaml";

        {
            fs::create_dir("config").unwrap();
            let mut custom = fs::File::create(path).unwrap();
            write!(
                &mut custom,
                "service:\n    http_keep_alive_timeout_sec: 0\n    http_client_request_timeout_sec: 0\n    http_client_disconnect_timeout_sec: 0"
            )
            .unwrap();
            custom.flush().unwrap();
        }

        let config = Settings::new(Some(path.into())).unwrap();
        assert!(
            config.validate().is_err(),
            "zero timeout values must fail validation"
        );
    }
}
