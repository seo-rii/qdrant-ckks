use std::fs;
use std::path::Path;

use collection::config::CkksCollectionConfig;
use data_encoding::BASE64URL_NOPAD;
use qdrant_ckks::{
    AeadCipher, PAYLOAD_TEXT_KEY_DOMAIN, PayloadEncryptionError, PayloadEncryptionPolicy,
    PayloadTextEncryptor, SecretKey,
};
use thiserror::Error;
use zeroize::Zeroizing;

use crate::settings::CkksConfig;

#[derive(Error, Debug, PartialEq, Eq)]
pub enum CkksSetupError {
    #[error("ckks payload encryption fields are configured but ckks.key_id is missing")]
    MissingKeyId,
    #[error("ckks payload encryption fields are configured but ckks.master_key_b64 is missing")]
    MissingMasterKey,
    #[error("ckks.master_key_b64 must be base64url without padding")]
    InvalidMasterKeyEncoding,
    #[error("ckks.master_key_b64 must decode to exactly 32 bytes")]
    InvalidMasterKeyLength,
    #[error("ckks key id is invalid for {scope}")]
    InvalidRuntimeKeyId { scope: String },
    #[error("ckks OpenFHE bridge path is invalid: {path}")]
    InvalidOpenFheBridgePath { path: String },
    #[error(
        "collection ckks key id does not match runtime key id for collection {collection_name}"
    )]
    CollectionKeyMismatch { collection_name: String },
    #[error(transparent)]
    Payload(#[from] PayloadEncryptionError),
}

pub fn payload_text_encryptor_for_collection(
    runtime_config: &CkksConfig,
    collection: &str,
    collection_config: Option<&CkksCollectionConfig>,
) -> Result<Option<(PayloadTextEncryptor, PayloadEncryptionPolicy)>, CkksSetupError> {
    if !runtime_config.enabled {
        return Ok(None);
    }

    let Some(collection_config) = collection_config else {
        return Ok(None);
    };
    if !collection_config.enabled || collection_config.payload_text_fields.is_empty() {
        return Ok(None);
    }

    let collection_runtime = runtime_config.collections.get(collection);
    let collection_runtime_key_id =
        collection_runtime.and_then(|runtime| runtime.key_id.as_deref());
    let key_id = match (
        collection_config.key_id.as_deref(),
        collection_runtime_key_id,
    ) {
        (Some(collection_key_id), Some(runtime_key_id)) if collection_key_id != runtime_key_id => {
            return Err(CkksSetupError::CollectionKeyMismatch {
                collection_name: collection.to_string(),
            });
        }
        (Some(collection_key_id), _) => Some(collection_key_id),
        (None, runtime_key_id) => runtime_key_id.or(runtime_config.key_id.as_deref()),
    }
    .ok_or(CkksSetupError::MissingKeyId)?;

    let master_key_b64 = collection_runtime
        .and_then(|runtime| runtime.master_key_b64.as_deref())
        .or(runtime_config.master_key_b64.as_deref())
        .ok_or(CkksSetupError::MissingMasterKey)?;
    let master_key = decode_master_key(master_key_b64)?;
    let payload_key = master_key
        .derive_subkey(PAYLOAD_TEXT_KEY_DOMAIN)
        .map_err(|err| CkksSetupError::Payload(PayloadEncryptionError::Crypto(err)))?;
    let cipher = AeadCipher::new(key_id, payload_key)
        .map_err(|err| CkksSetupError::Payload(PayloadEncryptionError::Crypto(err)))?;
    let policy = PayloadEncryptionPolicy::new(collection_config.payload_text_fields.clone())?;
    let encryptor = PayloadTextEncryptor::new(collection, cipher)?;

    Ok(Some((encryptor, policy)))
}

pub fn validate_runtime_config(runtime_config: &CkksConfig) -> Result<(), CkksSetupError> {
    if !runtime_config.enabled {
        return Ok(());
    }

    if let Some(key_id) = runtime_config.key_id.as_deref() {
        validate_runtime_key_id(key_id, "ckks.key_id")?;
    }
    if let Some(master_key_b64) = runtime_config.master_key_b64.as_deref() {
        let _ = decode_master_key(master_key_b64)?;
    }
    if let Some(path) = runtime_config.openfhe_bridge_path.as_deref() {
        validate_bridge_path(path)?;
    }

    for (collection_name, collection_config) in &runtime_config.collections {
        if let Some(key_id) = collection_config.key_id.as_deref() {
            validate_runtime_key_id(
                key_id,
                &format!("ckks.collections.{collection_name}.key_id"),
            )?;
        }
        if let Some(master_key_b64) = collection_config.master_key_b64.as_deref() {
            let _ = decode_master_key(master_key_b64)?;
        }
        if let Some(path) = collection_config.openfhe_bridge_path.as_deref() {
            validate_bridge_path(path)?;
        }
    }

    Ok(())
}

pub fn openfhe_bridge_for_collection<'a>(
    runtime_config: &'a CkksConfig,
    collection: &str,
    collection_config: Option<&CkksCollectionConfig>,
) -> Option<&'a str> {
    if !runtime_config.enabled
        || !collection_config.is_some_and(|collection_config| {
            collection_config.enabled && !collection_config.vector_names.is_empty()
        })
    {
        return None;
    }

    runtime_config
        .collections
        .get(collection)
        .and_then(|runtime| runtime.openfhe_bridge_path.as_deref())
        .or(runtime_config.openfhe_bridge_path.as_deref())
}

fn decode_master_key(master_key_b64: &str) -> Result<SecretKey, CkksSetupError> {
    let master_key = Zeroizing::new(
        BASE64URL_NOPAD
            .decode(master_key_b64.as_bytes())
            .map_err(|_| CkksSetupError::InvalidMasterKeyEncoding)?,
    );
    SecretKey::try_from_slice(master_key.as_slice())
        .map_err(|_| CkksSetupError::InvalidMasterKeyLength)
}

fn validate_runtime_key_id(key_id: &str, scope: &str) -> Result<(), CkksSetupError> {
    if key_id.is_empty()
        || key_id.len() > 128
        || !key_id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b':' | b'-'))
    {
        return Err(CkksSetupError::InvalidRuntimeKeyId {
            scope: scope.to_string(),
        });
    }

    Ok(())
}

fn validate_bridge_path(path: &str) -> Result<(), CkksSetupError> {
    let path_ref = Path::new(path);
    if !path_ref.is_absolute() {
        return Err(CkksSetupError::InvalidOpenFheBridgePath {
            path: path.to_string(),
        });
    }

    let metadata =
        fs::symlink_metadata(path).map_err(|_| CkksSetupError::InvalidOpenFheBridgePath {
            path: path.to_string(),
        })?;
    if metadata.file_type().is_symlink() {
        return Err(CkksSetupError::InvalidOpenFheBridgePath {
            path: path.to_string(),
        });
    }
    if !metadata.is_file() {
        return Err(CkksSetupError::InvalidOpenFheBridgePath {
            path: path.to_string(),
        });
    }

    let metadata = fs::metadata(path).map_err(|_| CkksSetupError::InvalidOpenFheBridgePath {
        path: path.to_string(),
    })?;
    if !metadata.is_file() {
        return Err(CkksSetupError::InvalidOpenFheBridgePath {
            path: path.to_string(),
        });
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};

        if metadata.permissions().mode() & 0o111 == 0 {
            return Err(CkksSetupError::InvalidOpenFheBridgePath {
                path: path.to_string(),
            });
        }
        if metadata.permissions().mode() & 0o002 != 0 {
            return Err(CkksSetupError::InvalidOpenFheBridgePath {
                path: path.to_string(),
            });
        }

        let owner = metadata.uid();
        // SAFETY: geteuid has no preconditions and does not dereference pointers.
        let effective_uid = unsafe { nix::libc::geteuid() };
        if owner != 0 && owner != effective_uid {
            return Err(CkksSetupError::InvalidOpenFheBridgePath {
                path: path.to_string(),
            });
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use data_encoding::BASE64URL_NOPAD;
    use serde_json::{Value, json};

    use super::*;
    use crate::settings::CkksCollectionKeyConfig;

    fn setup_err(config: &CkksConfig, collection_config: &CkksCollectionConfig) -> CkksSetupError {
        match payload_text_encryptor_for_collection(config, "docs", Some(collection_config)) {
            Ok(_) => panic!("expected ckks setup to fail"),
            Err(err) => err,
        }
    }

    fn enabled_collection_config() -> CkksCollectionConfig {
        CkksCollectionConfig {
            enabled: true,
            key_id: Some("tenant-a:payload".to_string()),
            payload_text_fields: vec!["body".to_string()],
            vector_names: vec!["embedding".to_string()],
        }
    }

    #[test]
    fn disabled_global_or_collection_config_builds_no_encryptor() {
        assert!(
            payload_text_encryptor_for_collection(
                &CkksConfig::default(),
                "docs",
                Some(&enabled_collection_config()),
            )
            .unwrap()
            .is_none(),
        );

        let config = CkksConfig {
            enabled: true,
            ..CkksConfig::default()
        };
        assert!(
            payload_text_encryptor_for_collection(&config, "docs", None)
                .unwrap()
                .is_none(),
        );
        assert!(
            payload_text_encryptor_for_collection(
                &config,
                "docs",
                Some(&CkksCollectionConfig::default()),
            )
            .unwrap()
            .is_none(),
        );
    }

    #[test]
    fn payload_config_fails_closed_when_key_material_is_missing_or_invalid() {
        let collection_config = enabled_collection_config();
        let mut config = CkksConfig {
            enabled: true,
            ..CkksConfig::default()
        };

        assert_eq!(
            setup_err(&config, &collection_config),
            CkksSetupError::MissingMasterKey,
        );

        let collection_config_without_key = CkksCollectionConfig {
            key_id: None,
            ..collection_config.clone()
        };
        config.master_key_b64 = Some(BASE64URL_NOPAD.encode(&[1u8; 32]));
        assert_eq!(
            setup_err(&config, &collection_config_without_key),
            CkksSetupError::MissingKeyId,
        );
        config.master_key_b64 = None;

        config.collections.insert(
            "docs".to_string(),
            CkksCollectionKeyConfig {
                key_id: Some("tenant-b:payload".to_string()),
                master_key_b64: Some(BASE64URL_NOPAD.encode(&[1u8; 32])),
                openfhe_bridge_path: None,
            },
        );
        assert_eq!(
            setup_err(&config, &collection_config),
            CkksSetupError::CollectionKeyMismatch {
                collection_name: "docs".to_string(),
            },
        );

        config.collections.insert(
            "docs".to_string(),
            CkksCollectionKeyConfig {
                key_id: Some("tenant-a:payload".to_string()),
                master_key_b64: Some("not base64!".to_string()),
                openfhe_bridge_path: None,
            },
        );
        assert_eq!(
            setup_err(&config, &collection_config),
            CkksSetupError::InvalidMasterKeyEncoding,
        );

        config.collections.insert(
            "docs".to_string(),
            CkksCollectionKeyConfig {
                key_id: Some("tenant-a:payload".to_string()),
                master_key_b64: Some(BASE64URL_NOPAD.encode(b"too short")),
                openfhe_bridge_path: None,
            },
        );
        assert_eq!(
            setup_err(&config, &collection_config),
            CkksSetupError::InvalidMasterKeyLength,
        );
    }

    #[test]
    fn payload_config_uses_collection_specific_key_material() {
        let encoded_key = BASE64URL_NOPAD.encode(&[31u8; 32]);
        let collection_config = enabled_collection_config();
        let mut config = CkksConfig {
            enabled: true,
            key_id: Some("default:payload".to_string()),
            master_key_b64: Some(BASE64URL_NOPAD.encode(&[9u8; 32])),
            ..CkksConfig::default()
        };
        config.collections.insert(
            "docs".to_string(),
            CkksCollectionKeyConfig {
                key_id: None,
                master_key_b64: Some(encoded_key.clone()),
                openfhe_bridge_path: Some("/usr/local/bin/openfhe-docs".to_string()),
            },
        );

        let debug = format!("{config:?}");
        assert!(!debug.contains(&encoded_key));
        assert!(debug.contains("redacted"));

        let Some((encryptor, policy)) =
            payload_text_encryptor_for_collection(&config, "docs", Some(&collection_config))
                .unwrap()
        else {
            panic!("enabled collection config must build an encryptor");
        };
        let mut payload = match json!({ "body": "secret body" }) {
            Value::Object(object) => object,
            _ => unreachable!(),
        };

        encryptor
            .encrypt_selected_fields("point-1", &mut payload, &policy)
            .unwrap();

        let serialized = serde_json::to_string(&payload).unwrap();
        assert!(!serialized.contains("secret body"));
    }

    #[test]
    fn runtime_config_validation_checks_provided_keys_and_bridge_paths() {
        let mut config = CkksConfig {
            enabled: true,
            master_key_b64: Some("not base64!".to_string()),
            ..CkksConfig::default()
        };
        assert_eq!(
            validate_runtime_config(&config),
            Err(CkksSetupError::InvalidMasterKeyEncoding),
        );

        config.master_key_b64 = Some(BASE64URL_NOPAD.encode(b"too short"));
        assert_eq!(
            validate_runtime_config(&config),
            Err(CkksSetupError::InvalidMasterKeyLength),
        );

        config.master_key_b64 = Some(BASE64URL_NOPAD.encode(&[9u8; 32]));
        config.key_id = Some("tenant/key".to_string());
        assert_eq!(
            validate_runtime_config(&config),
            Err(CkksSetupError::InvalidRuntimeKeyId {
                scope: "ckks.key_id".to_string(),
            }),
        );

        config.key_id = Some("tenant-a:payload".to_string());
        config.openfhe_bridge_path = Some("relative-openfhe-bridge".to_string());
        assert_eq!(
            validate_runtime_config(&config),
            Err(CkksSetupError::InvalidOpenFheBridgePath {
                path: "relative-openfhe-bridge".to_string(),
            }),
        );

        config.openfhe_bridge_path = Some("/definitely/not/a/qdrant-ckks-bridge".to_string());
        assert_eq!(
            validate_runtime_config(&config),
            Err(CkksSetupError::InvalidOpenFheBridgePath {
                path: "/definitely/not/a/qdrant-ckks-bridge".to_string(),
            }),
        );

        let bridge = tempfile::NamedTempFile::new().unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            let mut permissions = bridge.as_file().metadata().unwrap().permissions();
            permissions.set_mode(0o777);
            bridge.as_file().set_permissions(permissions).unwrap();
            config.openfhe_bridge_path = Some(bridge.path().display().to_string());
            assert_eq!(
                validate_runtime_config(&config),
                Err(CkksSetupError::InvalidOpenFheBridgePath {
                    path: bridge.path().display().to_string(),
                }),
            );

            let mut permissions = bridge.as_file().metadata().unwrap().permissions();
            permissions.set_mode(0o700);
            bridge.as_file().set_permissions(permissions).unwrap();

            let symlink_path = bridge.path().with_extension("link");
            std::os::unix::fs::symlink(bridge.path(), &symlink_path).unwrap();
            config.openfhe_bridge_path = Some(symlink_path.display().to_string());
            assert_eq!(
                validate_runtime_config(&config),
                Err(CkksSetupError::InvalidOpenFheBridgePath {
                    path: symlink_path.display().to_string(),
                }),
            );
        }
        config.openfhe_bridge_path = Some(bridge.path().display().to_string());
        validate_runtime_config(&config).unwrap();
    }

    #[test]
    fn openfhe_bridge_is_collection_specific_and_requires_vector_names() {
        let mut config = CkksConfig {
            enabled: true,
            openfhe_bridge_path: Some("/usr/local/bin/openfhe-default".to_string()),
            ..CkksConfig::default()
        };
        config.collections.insert(
            "docs".to_string(),
            CkksCollectionKeyConfig {
                key_id: None,
                master_key_b64: None,
                openfhe_bridge_path: Some("/usr/local/bin/openfhe-docs".to_string()),
            },
        );

        assert_eq!(
            openfhe_bridge_for_collection(&config, "docs", Some(&enabled_collection_config())),
            Some("/usr/local/bin/openfhe-docs"),
        );
        assert_eq!(
            openfhe_bridge_for_collection(&config, "other", Some(&enabled_collection_config()),),
            Some("/usr/local/bin/openfhe-default"),
        );

        let mut no_vectors = enabled_collection_config();
        no_vectors.vector_names.clear();
        assert_eq!(
            openfhe_bridge_for_collection(&config, "docs", Some(&no_vectors)),
            None,
        );
    }
}
