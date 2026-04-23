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
    #[error(transparent)]
    Payload(#[from] PayloadEncryptionError),
}

pub fn payload_text_encryptor_for_collection(
    config: &CkksConfig,
    collection: &str,
) -> Result<Option<(PayloadTextEncryptor, PayloadEncryptionPolicy)>, CkksSetupError> {
    if !config.enabled || config.payload_text_fields.is_empty() {
        return Ok(None);
    }

    let key_id = config
        .key_id
        .as_deref()
        .ok_or(CkksSetupError::MissingKeyId)?;
    let master_key_b64 = config
        .master_key_b64
        .as_deref()
        .ok_or(CkksSetupError::MissingMasterKey)?;
    let master_key = BASE64URL_NOPAD
        .decode(master_key_b64.as_bytes())
        .map_err(|_| CkksSetupError::InvalidMasterKeyEncoding)?;
    let master_key = SecretKey::try_from_slice(&master_key)
        .map_err(|_| CkksSetupError::InvalidMasterKeyLength)?;
    let cipher = AeadCipher::new(key_id, master_key)
        .map_err(|err| CkksSetupError::Payload(PayloadEncryptionError::Crypto(err)))?;
    let policy = PayloadEncryptionPolicy::new(config.payload_text_fields.clone())?;
    let encryptor = PayloadTextEncryptor::new(collection, cipher)?;

    Ok(Some((encryptor, policy)))
}

#[cfg(test)]
mod tests {
    use data_encoding::BASE64URL_NOPAD;
    use serde_json::{Value, json};

    use super::*;

    fn setup_err(config: &CkksConfig) -> CkksSetupError {
        match payload_text_encryptor_for_collection(config, "docs") {
            Ok(_) => panic!("expected ckks setup to fail"),
            Err(err) => err,
        }
    }

    #[test]
    fn disabled_or_empty_payload_config_builds_no_encryptor() {
        assert!(
            payload_text_encryptor_for_collection(&CkksConfig::default(), "docs")
                .unwrap()
                .is_none(),
        );

        let config = CkksConfig {
            enabled: true,
            ..CkksConfig::default()
        };
        assert!(
            payload_text_encryptor_for_collection(&config, "docs")
                .unwrap()
                .is_none(),
        );
    }

    #[test]
    fn payload_config_fails_closed_when_key_material_is_missing_or_invalid() {
        let mut config = CkksConfig {
            enabled: true,
            payload_text_fields: vec!["body".to_string()],
            ..CkksConfig::default()
        };

        assert_eq!(setup_err(&config), CkksSetupError::MissingKeyId);

        config.key_id = Some("tenant-a:payload".to_string());
        assert_eq!(setup_err(&config), CkksSetupError::MissingMasterKey);

        config.master_key_b64 = Some("not base64!".to_string());
        assert_eq!(setup_err(&config), CkksSetupError::InvalidMasterKeyEncoding,);

        config.master_key_b64 = Some(BASE64URL_NOPAD.encode(b"too short"));
        assert_eq!(setup_err(&config), CkksSetupError::InvalidMasterKeyLength);
    }

    #[test]
    fn payload_config_builds_encryptor_that_removes_plaintext_body() {
        let encoded_key = BASE64URL_NOPAD.encode(&[31u8; 32]);
        let config = CkksConfig {
            enabled: true,
            key_id: Some("tenant-a:payload".to_string()),
            master_key_b64: Some(encoded_key.clone()),
            payload_text_fields: vec!["body".to_string()],
            openfhe_bridge_path: None,
        };
        let debug = format!("{config:?}");
        assert!(!debug.contains(&encoded_key));
        assert!(debug.contains("redacted"));

        let Some((encryptor, policy)) =
            payload_text_encryptor_for_collection(&config, "docs").unwrap()
        else {
            panic!("enabled payload config must build an encryptor");
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
}
