use collection::config::CkksCollectionConfig;
use data_encoding::BASE64URL_NOPAD;
use qdrant_ckks::{
    AeadCipher, PayloadEncryptionError, PayloadEncryptionPolicy, PayloadTextEncryptor, SecretKey,
};
use thiserror::Error;

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
    let master_key = BASE64URL_NOPAD
        .decode(master_key_b64.as_bytes())
        .map_err(|_| CkksSetupError::InvalidMasterKeyEncoding)?;
    let master_key = SecretKey::try_from_slice(&master_key)
        .map_err(|_| CkksSetupError::InvalidMasterKeyLength)?;
    let cipher = AeadCipher::new(key_id, master_key)
        .map_err(|err| CkksSetupError::Payload(PayloadEncryptionError::Crypto(err)))?;
    let policy = PayloadEncryptionPolicy::new(collection_config.payload_text_fields.clone())?;
    let encryptor = PayloadTextEncryptor::new(collection, cipher)?;

    Ok(Some((encryptor, policy)))
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
