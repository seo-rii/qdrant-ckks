use std::fs;

use data_encoding::BASE64URL_NOPAD;
use qdrant_ckks::{
    AeadCipher, CkksEncryptionInput, CkksError, CkksParameters, CkksPublicMaterial,
    CkksVectorBackend, CkksVectorEncryptor, CommandOpenFheBackend, EncryptionContext, SecretKey,
};
use serde_json::json;

#[derive(Clone, Copy, Debug)]
struct SealedTestBackend;

impl CkksVectorBackend for SealedTestBackend {
    fn encrypt(&self, input: CkksEncryptionInput<'_>) -> Result<Vec<u8>, CkksError> {
        let cipher = AeadCipher::new("test-vector", SecretKey::from_bytes([23u8; 32])).unwrap();
        let plaintext = serde_json::to_vec(input.values)
            .map_err(|err| CkksError::Backend(format!("test serialization failed: {err}")))?;
        let envelope = cipher
            .encrypt(
                &plaintext,
                EncryptionContext::ckks_vector(input.collection, input.point_id, input.vector_name),
            )
            .map_err(|err| CkksError::Backend(format!("test sealing failed: {err}")))?;

        serde_json::to_vec(&envelope)
            .map_err(|err| CkksError::Backend(format!("test envelope failed: {err}")))
    }
}

fn public_material() -> CkksPublicMaterial {
    CkksPublicMaterial::new(
        b"openfhe crypto context".to_vec(),
        b"openfhe public key".to_vec(),
    )
    .unwrap()
}

fn encryptor() -> CkksVectorEncryptor<SealedTestBackend> {
    CkksVectorEncryptor::new(
        "tenant-a:ckks",
        "embedding",
        CkksParameters::openfhe_default_128_bit(),
        SealedTestBackend,
    )
    .unwrap()
}

#[test]
fn ckks_vector_envelope_does_not_serialize_plain_embedding() {
    let encrypted = encryptor()
        .encrypt("docs", "point-1", &public_material(), &[0.125, -42.5, 9.75])
        .unwrap();

    assert_eq!(encrypted.scheme, "openfhe-ckks");
    assert_eq!(encrypted.key_id, "tenant-a:ckks");
    assert_eq!(encrypted.vector_name, "embedding");
    assert_eq!(encrypted.slots, 3);

    let serialized = serde_json::to_string(&encrypted).unwrap();
    assert!(!serialized.contains("0.125"));
    assert!(!serialized.contains("-42.5"));
    assert!(!serialized.contains("9.75"));

    let debug = format!("{encrypted:?}");
    assert!(debug.contains("ciphertext_len"));
    assert!(!debug.contains(&encrypted.ciphertext));
}

#[test]
fn context_digest_changes_with_public_material_and_parameters() {
    let base = public_material();
    let other_key =
        CkksPublicMaterial::new(b"openfhe crypto context".to_vec(), b"other key".to_vec()).unwrap();
    let mut other_params = CkksParameters::openfhe_default_128_bit();
    other_params.multiplicative_depth += 1;

    let base_digest = base.digest_for(&CkksParameters::openfhe_default_128_bit());

    assert_ne!(
        base_digest,
        other_key.digest_for(&CkksParameters::openfhe_default_128_bit()),
    );
    assert_ne!(base_digest, base.digest_for(&other_params));
}

#[test]
fn vector_validation_fails_closed_before_backend_call() {
    let encryptor = encryptor();
    let material = public_material();

    assert_eq!(
        encryptor.encrypt("docs", "point-1", &material, &[]),
        Err(CkksError::EmptyVector),
    );
    assert_eq!(
        encryptor.encrypt("docs", "point-1", &material, &[f64::NAN]),
        Err(CkksError::NonFiniteValue { index: 0 }),
    );

    let small_params = CkksParameters {
        batch_size: 1,
        ..CkksParameters::openfhe_default_128_bit()
    };
    let small_encryptor = CkksVectorEncryptor::new(
        "tenant-a:ckks",
        "embedding",
        small_params,
        SealedTestBackend,
    )
    .unwrap();
    assert_eq!(
        small_encryptor.encrypt("docs", "point-1", &material, &[1.0, 2.0]),
        Err(CkksError::VectorTooWide {
            len: 2,
            batch_size: 1,
        }),
    );
}

#[test]
fn ckks_parameter_validation_rejects_unsafe_shapes() {
    let mut params = CkksParameters::openfhe_default_128_bit();
    params.poly_modulus_degree = 12_288;
    assert!(matches!(
        params.validate(),
        Err(CkksError::InvalidParameters(_)),
    ));

    let mut params = CkksParameters::openfhe_default_128_bit();
    params.batch_size = params.poly_modulus_degree;
    assert!(matches!(
        params.validate(),
        Err(CkksError::InvalidParameters(_)),
    ));

    let mut params = CkksParameters::openfhe_default_128_bit();
    params.scaling_mod_size = 12;
    assert!(matches!(
        params.validate(),
        Err(CkksError::InvalidParameters(_)),
    ));
}

#[test]
fn constructor_rejects_invalid_identifiers_and_public_material() {
    assert_eq!(
        CkksVectorEncryptor::new(
            "tenant/key",
            "embedding",
            CkksParameters::openfhe_default_128_bit(),
            SealedTestBackend,
        )
        .err(),
        Some(CkksError::InvalidKeyId),
    );
    assert_eq!(
        CkksVectorEncryptor::new(
            "tenant-a:ckks",
            "bad\0name",
            CkksParameters::openfhe_default_128_bit(),
            SealedTestBackend,
        )
        .err(),
        Some(CkksError::InvalidVectorName),
    );
    assert!(matches!(
        CkksPublicMaterial::new(Vec::new(), b"pk".to_vec()),
        Err(CkksError::InvalidContext(_)),
    ));
}

#[cfg(unix)]
#[test]
fn command_openfhe_backend_uses_bridge_protocol() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::tempdir().unwrap();
    let script_path = dir.path().join("fake-openfhe-bridge.sh");
    fs::write(
        &script_path,
        r#"#!/usr/bin/env bash
set -euo pipefail
request="$(cat)"
case "$request" in
  *'"scheme":"openfhe-ckks"'*'"vector_name":"embedding"'*) ;;
  *) exit 7 ;;
esac
printf '{"version":1,"ciphertext":"b3BlbmZoZS1jaXBoZXI"}'
"#,
    )
    .unwrap();
    let mut permissions = fs::metadata(&script_path).unwrap().permissions();
    permissions.set_mode(0o700);
    fs::set_permissions(&script_path, permissions).unwrap();

    let backend = CommandOpenFheBackend::new(&script_path);
    let encryptor = CkksVectorEncryptor::new(
        "tenant-a:ckks",
        "embedding",
        CkksParameters::openfhe_default_128_bit(),
        backend,
    )
    .unwrap();
    let encrypted = encryptor
        .encrypt("docs", "point-1", &public_material(), &[1.0, 2.0])
        .unwrap();

    assert_eq!(
        encrypted.ciphertext,
        BASE64URL_NOPAD.encode(b"openfhe-cipher"),
    );
}

#[test]
fn encrypted_ckks_vector_has_stable_json_shape() {
    let encrypted = encryptor()
        .encrypt("docs", "point-1", &public_material(), &[1.0])
        .unwrap();
    let value = serde_json::to_value(encrypted).unwrap();

    assert_eq!(value["version"], json!(1));
    assert_eq!(value["scheme"], json!("openfhe-ckks"));
    assert_eq!(value["key_id"], json!("tenant-a:ckks"));
    assert_eq!(value["vector_name"], json!("embedding"));
    assert_eq!(value["slots"], json!(1));
    assert!(value["context_digest"].as_str().unwrap().len() >= 32);
    assert!(value["ciphertext"].as_str().unwrap().len() >= 32);
}
