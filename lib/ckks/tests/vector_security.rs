use std::fs;
use std::num::NonZeroUsize;
use std::sync::Arc;
use std::time::{Duration, Instant};

use data_encoding::BASE64URL_NOPAD;
use qdrant_ckks::{
    AeadCipher, CKKS_PROFILE_OPENFHE_128_N16384_D4_SCALE50, CkksEncryptionInput, CkksError,
    CkksParameters, CkksPublicMaterial, CkksVectorBackend, CkksVectorEncryptor,
    CommandOpenFheBackend, EncryptionContext, EncryptionError, SecretKey,
};
use serde_json::json;
use sha2::{Digest, Sha256};

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
        SecretKey::from_bytes([29u8; 32]),
        SealedTestBackend,
    )
    .unwrap()
}

#[test]
fn ckks_vector_envelope_does_not_serialize_plain_embedding() {
    let material = public_material();
    let encrypted = encryptor()
        .encrypt("docs", "point-1", &material, &[0.125, -42.5, 9.75])
        .unwrap();
    let verified = encryptor()
        .open("docs", "point-1", &material, &encrypted)
        .unwrap();

    assert_eq!(encrypted.scheme, "openfhe-ckks");
    assert_eq!(encrypted.envelope.key_id, "tenant-a:ckks");
    assert_eq!(verified.crypto_schema_version, 1);
    assert_eq!(verified.encryption_epoch, 0);
    assert_eq!(verified.key_id, "tenant-a:ckks");
    assert_eq!(verified.vector_name, "embedding");
    assert_eq!(verified.slots, 3);

    let serialized = serde_json::to_string(&encrypted).unwrap();
    assert!(!serialized.contains("0.125"));
    assert!(!serialized.contains("-42.5"));
    assert!(!serialized.contains("9.75"));
    assert!(!serialized.contains("\"vector_name\":\"embedding\""));

    let debug = format!("{encrypted:?}");
    assert!(debug.contains("EncryptedEnvelope"));
    assert!(!debug.contains(&encrypted.envelope.ciphertext));
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
fn open_rejects_encryption_epoch_mismatch() {
    let material = public_material();
    let encrypted = encryptor()
        .encrypt("docs", "point-1", &material, &[1.0, 2.0])
        .unwrap();
    let next_epoch_encryptor = encryptor().with_encryption_epoch(1);

    assert_eq!(
        next_epoch_encryptor.open("docs", "point-1", &material, &encrypted),
        Err(CkksError::EncryptionEpochMismatch),
    );
}

#[test]
fn vector_open_accepts_retired_metadata_key_but_new_writes_use_active_key() {
    let material = public_material();
    let old_encrypted = encryptor()
        .encrypt("docs", "point-1", &material, &[1.0, 2.0])
        .unwrap();
    let rotated_encryptor = CkksVectorEncryptor::new(
        "tenant-a:ckks-v2",
        "embedding",
        CkksParameters::openfhe_default_128_bit(),
        SecretKey::from_bytes([30u8; 32]),
        SealedTestBackend,
    )
    .unwrap()
    .with_retired_metadata_key("tenant-a:ckks", SecretKey::from_bytes([29u8; 32]))
    .unwrap();

    let verified = rotated_encryptor
        .open("docs", "point-1", &material, &old_encrypted)
        .unwrap();

    assert_eq!(verified.key_id, "tenant-a:ckks");

    let new_encrypted = rotated_encryptor
        .encrypt("docs", "point-2", &material, &[3.0, 4.0])
        .unwrap();
    let new_verified = rotated_encryptor
        .open("docs", "point-2", &material, &new_encrypted)
        .unwrap();

    assert_eq!(new_encrypted.envelope.key_id, "tenant-a:ckks-v2");
    assert_eq!(new_verified.key_id, "tenant-a:ckks-v2");
}

#[test]
fn ckks_vector_envelope_records_resource_key_metadata() {
    let material = public_material();
    let resource_key = SecretKey::from_bytes([29u8; 32]);
    let encryptor = CkksVectorEncryptor::new_from_resource_key_with_metadata(
        "tenant-a:ckks",
        "embedding",
        CkksParameters::openfhe_default_128_bit(),
        &resource_key,
        "tenant-a/vector-rk@v3",
        "tenant-a/vector-rk-v3",
        3,
        SealedTestBackend,
    )
    .unwrap();
    let encrypted = encryptor
        .encrypt("docs", "point-1", &material, &[1.0, 2.0])
        .unwrap();

    assert_eq!(
        encrypted.envelope.material_fingerprint,
        "tenant-a/vector-rk@v3"
    );
    assert_eq!(encrypted.envelope.rk_id, "tenant-a/vector-rk-v3");
    assert_eq!(encrypted.envelope.rk_epoch, Some(3));
    assert_eq!(
        encryptor
            .open("docs", "point-1", &material, &encrypted)
            .unwrap()
            .key_id,
        "tenant-a:ckks",
    );

    let wrong_epoch = CkksVectorEncryptor::new_from_resource_key_with_metadata(
        "tenant-a:ckks",
        "embedding",
        CkksParameters::openfhe_default_128_bit(),
        &resource_key,
        "tenant-a/vector-rk@v3",
        "tenant-a/vector-rk-v3",
        4,
        SealedTestBackend,
    )
    .unwrap();
    assert!(matches!(
        wrong_epoch.open("docs", "point-1", &material, &encrypted),
        Err(CkksError::Envelope(EncryptionError::KeyMismatch)),
    ));

    let rotated = CkksVectorEncryptor::new_from_resource_key_with_metadata(
        "tenant-a:ckks-v4",
        "embedding",
        CkksParameters::openfhe_default_128_bit(),
        &SecretKey::from_bytes([30u8; 32]),
        "tenant-a/vector-rk@v4",
        "tenant-a/vector-rk-v4",
        4,
        SealedTestBackend,
    )
    .unwrap()
    .with_retired_metadata_resource_key(
        "tenant-a:ckks",
        &resource_key,
        "tenant-a/vector-rk@v3",
        "tenant-a/vector-rk-v3",
        3,
    )
    .unwrap();
    assert_eq!(
        rotated
            .open("docs", "point-1", &material, &encrypted)
            .unwrap()
            .key_id,
        "tenant-a:ckks",
    );
}

#[test]
fn open_rejects_context_digest_mismatch() {
    let material = public_material();
    let encrypted = encryptor()
        .encrypt("docs", "point-1", &material, &[1.0, 2.0])
        .unwrap();
    let other_material =
        CkksPublicMaterial::new(b"openfhe crypto context".to_vec(), b"other key".to_vec()).unwrap();

    assert!(matches!(
        encryptor().open("docs", "point-1", &other_material, &encrypted),
        Err(CkksError::MalformedEnvelope(message))
            if message.contains("context digest does not match")
    ));
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
        SecretKey::from_bytes([29u8; 32]),
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
    assert_eq!(
        CkksParameters::openfhe_default_128_bit().security_profile(),
        Some(CKKS_PROFILE_OPENFHE_128_N16384_D4_SCALE50),
    );

    let mut params = CkksParameters::openfhe_default_128_bit();
    params.poly_modulus_degree = 12_288;
    assert!(matches!(
        params.validate(),
        Err(CkksError::InvalidParameters(_)),
    ));

    let mut params = CkksParameters::openfhe_default_128_bit();
    params.multiplicative_depth = 5;
    assert!(matches!(
        params.validate(),
        Err(CkksError::InvalidParameters(message)) if message.contains("allowlisted profile"),
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
            SecretKey::from_bytes([29u8; 32]),
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
            SecretKey::from_bytes([29u8; 32]),
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
fn command_openfhe_backend_checked_constructor_validates_bridge_path() {
    use std::os::unix::fs::PermissionsExt;

    assert!(matches!(
        CommandOpenFheBackend::new_checked("bash"),
        Err(CkksError::Backend(message)) if message.contains("absolute path")
    ));

    let dir = tempfile::Builder::new()
        .prefix("openfhe-checked")
        .tempdir_in(std::env::current_dir().unwrap())
        .unwrap();
    let script_path = dir.path().join("checked-openfhe-bridge.sh");
    fs::write(&script_path, b"#!/bin/sh\n").unwrap();
    let mut permissions = fs::metadata(&script_path).unwrap().permissions();
    permissions.set_mode(0o700);
    fs::set_permissions(&script_path, permissions).unwrap();

    assert!(CommandOpenFheBackend::new_checked(&script_path).is_ok());
    let bridge_digest = Sha256::digest(fs::read(&script_path).unwrap());
    assert!(
        CommandOpenFheBackend::new_checked_with_sha256_b64(
            &script_path,
            BASE64URL_NOPAD.encode(&bridge_digest),
        )
        .is_ok()
    );
    assert!(matches!(
        CommandOpenFheBackend::new_checked_with_sha256_b64(
            &script_path,
            BASE64URL_NOPAD.encode(&[0u8; 32]),
        ),
        Err(CkksError::Backend(message)) if message.contains("sha256 pin does not match")
    ));
    assert!(matches!(
        CommandOpenFheBackend::new_checked_with_sha256_b64(&script_path, "not base64!"),
        Err(CkksError::Backend(message)) if message.contains("base64url-no-padding")
    ));

    let mut permissions = fs::metadata(dir.path()).unwrap().permissions();
    permissions.set_mode(0o777);
    fs::set_permissions(dir.path(), permissions).unwrap();
    assert!(matches!(
        CommandOpenFheBackend::new_checked(&script_path),
        Err(CkksError::Backend(message)) if message.contains("parent directory")
    ));
    let mut permissions = fs::metadata(dir.path()).unwrap().permissions();
    permissions.set_mode(0o700);
    fs::set_permissions(dir.path(), permissions).unwrap();

    let symlink_path = dir.path().join("checked-openfhe-bridge-link.sh");
    std::os::unix::fs::symlink(&script_path, &symlink_path).unwrap();
    assert!(matches!(
        CommandOpenFheBackend::new_checked(&symlink_path),
        Err(CkksError::Backend(message)) if message.contains("non-symlink")
    ));
}

#[cfg(unix)]
#[test]
fn command_openfhe_backend_revalidates_bridge_before_spawn() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::Builder::new()
        .prefix("openfhe-spawn-revalidate")
        .tempdir_in(std::env::current_dir().unwrap())
        .unwrap();
    let script_path = dir.path().join("checked-openfhe-bridge.sh");
    fs::write(
        &script_path,
        r#"#!/usr/bin/env bash
set -euo pipefail
IFS= read -r _request
printf '{"version":1,"ciphertext":"b3BlbmZoZS1jaXBoZXI"}\n'
"#,
    )
    .unwrap();
    let mut permissions = fs::metadata(&script_path).unwrap().permissions();
    permissions.set_mode(0o700);
    fs::set_permissions(&script_path, permissions).unwrap();

    let bridge_digest = Sha256::digest(fs::read(&script_path).unwrap());
    let backend = CommandOpenFheBackend::new_checked_with_sha256_b64(
        &script_path,
        BASE64URL_NOPAD.encode(&bridge_digest),
    )
    .unwrap();

    fs::write(
        &script_path,
        r#"#!/usr/bin/env bash
set -euo pipefail
IFS= read -r _request
printf '{"version":1,"ciphertext":"cmVwbGFjZWQtY2lwaGVy"}\n'
"#,
    )
    .unwrap();
    let mut permissions = fs::metadata(&script_path).unwrap().permissions();
    permissions.set_mode(0o700);
    fs::set_permissions(&script_path, permissions).unwrap();

    let encryptor = CkksVectorEncryptor::new(
        "tenant-a:ckks",
        "embedding",
        CkksParameters::openfhe_default_128_bit(),
        SecretKey::from_bytes([29u8; 32]),
        backend,
    )
    .unwrap();

    let err = encryptor
        .encrypt("docs", "point-1", &public_material(), &[1.0])
        .unwrap_err();

    assert!(
        matches!(err, CkksError::Backend(message) if message.contains("sha256 pin does not match"))
    );
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
IFS= read -r request
case "$request" in
  *'"scheme":"openfhe-ckks"'*'"vector_name":"embedding"'*) ;;
  *) exit 7 ;;
esac
printf '{"version":1,"ciphertext":"b3BlbmZoZS1jaXBoZXI"}\n'
"#,
    )
    .unwrap();
    let mut permissions = fs::metadata(&script_path).unwrap().permissions();
    permissions.set_mode(0o700);
    fs::set_permissions(&script_path, permissions).unwrap();

    let backend = CommandOpenFheBackend::new_unchecked_for_tests("bash")
        .with_args([script_path.display().to_string()]);
    let encryptor = CkksVectorEncryptor::new(
        "tenant-a:ckks",
        "embedding",
        CkksParameters::openfhe_default_128_bit(),
        SecretKey::from_bytes([29u8; 32]),
        backend,
    )
    .unwrap();
    let first = encryptor
        .encrypt("docs", "point-1", &public_material(), &[1.0, 2.0])
        .unwrap();
    let second = encryptor
        .encrypt("docs", "point-2", &public_material(), &[3.0, 4.0])
        .unwrap();

    assert_eq!(
        encryptor
            .open("docs", "point-1", &public_material(), &first)
            .unwrap()
            .ciphertext,
        BASE64URL_NOPAD.encode(b"openfhe-cipher"),
    );
    assert_eq!(
        encryptor
            .open("docs", "point-2", &public_material(), &second)
            .unwrap()
            .ciphertext,
        BASE64URL_NOPAD.encode(b"openfhe-cipher"),
    );
}

#[cfg(unix)]
#[test]
fn command_openfhe_backend_times_out_and_kills_hung_bridge() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::tempdir().unwrap();
    let script_path = dir.path().join("hung-openfhe-bridge.sh");
    fs::write(
        &script_path,
        r#"#!/usr/bin/env bash
set -euo pipefail
IFS= read -r _request
sleep 10
"#,
    )
    .unwrap();
    let mut permissions = fs::metadata(&script_path).unwrap().permissions();
    permissions.set_mode(0o700);
    fs::set_permissions(&script_path, permissions).unwrap();

    let backend = CommandOpenFheBackend::new_unchecked_for_tests("bash")
        .with_args([script_path.display().to_string()])
        .with_timeout(Duration::from_millis(50));
    let encryptor = CkksVectorEncryptor::new(
        "tenant-a:ckks",
        "embedding",
        CkksParameters::openfhe_default_128_bit(),
        SecretKey::from_bytes([29u8; 32]),
        backend,
    )
    .unwrap();

    let err = encryptor
        .encrypt("docs", "point-1", &public_material(), &[1.0])
        .unwrap_err();

    assert!(matches!(err, CkksError::Backend(message) if message.contains("timed out")));
}

#[cfg(unix)]
#[test]
fn command_openfhe_backend_timeout_does_not_wait_for_stdout_holder() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::tempdir().unwrap();
    let script_path = dir.path().join("stdout-held-openfhe-bridge.sh");
    fs::write(
        &script_path,
        r#"#!/usr/bin/env bash
set -euo pipefail
IFS= read -r _request
(sleep 2) &
sleep 10
"#,
    )
    .unwrap();
    let mut permissions = fs::metadata(&script_path).unwrap().permissions();
    permissions.set_mode(0o700);
    fs::set_permissions(&script_path, permissions).unwrap();

    let backend = CommandOpenFheBackend::new_unchecked_for_tests("bash")
        .with_args([script_path.display().to_string()])
        .with_timeout(Duration::from_millis(50));
    let encryptor = CkksVectorEncryptor::new(
        "tenant-a:ckks",
        "embedding",
        CkksParameters::openfhe_default_128_bit(),
        SecretKey::from_bytes([29u8; 32]),
        backend,
    )
    .unwrap();

    let started = Instant::now();
    let err = encryptor
        .encrypt("docs", "point-1", &public_material(), &[1.0])
        .unwrap_err();

    assert!(matches!(err, CkksError::Backend(message) if message.contains("timed out")));
    assert!(started.elapsed() < Duration::from_secs(1));
}

#[cfg(unix)]
#[test]
fn command_openfhe_backend_rejects_bridge_exit_after_request() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::tempdir().unwrap();
    let script_path = dir.path().join("exit-after-request-openfhe-bridge.sh");
    fs::write(
        &script_path,
        r#"#!/usr/bin/env bash
set -euo pipefail
IFS= read -r _request
exit 0
"#,
    )
    .unwrap();
    let mut permissions = fs::metadata(&script_path).unwrap().permissions();
    permissions.set_mode(0o700);
    fs::set_permissions(&script_path, permissions).unwrap();

    let backend = CommandOpenFheBackend::new_unchecked_for_tests("bash")
        .with_args([script_path.display().to_string()]);
    let encryptor = CkksVectorEncryptor::new(
        "tenant-a:ckks",
        "embedding",
        CkksParameters::openfhe_default_128_bit(),
        SecretKey::from_bytes([29u8; 32]),
        backend,
    )
    .unwrap();

    let err = encryptor
        .encrypt("docs", "point-1", &public_material(), &[1.0])
        .unwrap_err();

    assert!(
        matches!(err, CkksError::Backend(ref message) if message.contains("empty response")),
        "{err:?}",
    );
}

#[cfg(unix)]
#[test]
fn command_openfhe_backend_rejects_oversized_bridge_output() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::tempdir().unwrap();
    let script_path = dir.path().join("noisy-openfhe-bridge.sh");
    fs::write(
        &script_path,
        r#"#!/usr/bin/env bash
set -euo pipefail
IFS= read -r _request
for _ in {1..128}; do
  printf x
done
"#,
    )
    .unwrap();
    let mut permissions = fs::metadata(&script_path).unwrap().permissions();
    permissions.set_mode(0o700);
    fs::set_permissions(&script_path, permissions).unwrap();

    let backend = CommandOpenFheBackend::new_unchecked_for_tests("bash")
        .with_args([script_path.display().to_string()])
        .with_max_output_bytes(32);
    let encryptor = CkksVectorEncryptor::new(
        "tenant-a:ckks",
        "embedding",
        CkksParameters::openfhe_default_128_bit(),
        SecretKey::from_bytes([29u8; 32]),
        backend,
    )
    .unwrap();

    let err = encryptor
        .encrypt("docs", "point-1", &public_material(), &[1.0])
        .unwrap_err();

    assert!(matches!(err, CkksError::Backend(message) if message.contains("stdout exceeded")));
}

#[cfg(unix)]
#[test]
fn command_openfhe_backend_rejects_invalid_json_response() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::tempdir().unwrap();
    let script_path = dir.path().join("invalid-json-openfhe-bridge.sh");
    fs::write(
        &script_path,
        r#"#!/usr/bin/env bash
set -euo pipefail
IFS= read -r _request
printf '{not-json}\n'
"#,
    )
    .unwrap();
    let mut permissions = fs::metadata(&script_path).unwrap().permissions();
    permissions.set_mode(0o700);
    fs::set_permissions(&script_path, permissions).unwrap();

    let backend = CommandOpenFheBackend::new_unchecked_for_tests("bash")
        .with_args([script_path.display().to_string()]);
    let encryptor = CkksVectorEncryptor::new(
        "tenant-a:ckks",
        "embedding",
        CkksParameters::openfhe_default_128_bit(),
        SecretKey::from_bytes([29u8; 32]),
        backend,
    )
    .unwrap();

    let err = encryptor
        .encrypt("docs", "point-1", &public_material(), &[1.0])
        .unwrap_err();

    assert!(
        matches!(err, CkksError::Backend(message) if message.contains("failed to parse OpenFHE bridge response"))
    );
}

#[cfg(unix)]
#[test]
fn command_openfhe_backend_rejects_response_without_newline() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::tempdir().unwrap();
    let script_path = dir.path().join("no-newline-openfhe-bridge.sh");
    fs::write(
        &script_path,
        r#"#!/usr/bin/env bash
set -euo pipefail
IFS= read -r _request
printf '{"version":1,"ciphertext":"b3BlbmZoZS1jaXBoZXI"}'
"#,
    )
    .unwrap();
    let mut permissions = fs::metadata(&script_path).unwrap().permissions();
    permissions.set_mode(0o700);
    fs::set_permissions(&script_path, permissions).unwrap();

    let backend = CommandOpenFheBackend::new_unchecked_for_tests("bash")
        .with_args([script_path.display().to_string()]);
    let encryptor = CkksVectorEncryptor::new(
        "tenant-a:ckks",
        "embedding",
        CkksParameters::openfhe_default_128_bit(),
        SecretKey::from_bytes([29u8; 32]),
        backend,
    )
    .unwrap();

    let err = encryptor
        .encrypt("docs", "point-1", &public_material(), &[1.0])
        .unwrap_err();

    assert!(
        matches!(err, CkksError::Backend(message) if message.contains("empty response") || message.contains("disconnected"))
    );
}

#[cfg(unix)]
#[test]
fn command_openfhe_backend_rejects_oversized_bridge_stderr() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::tempdir().unwrap();
    let script_path = dir.path().join("stderr-noisy-openfhe-bridge.sh");
    fs::write(
        &script_path,
        r#"#!/usr/bin/env bash
set -uo pipefail
IFS= read -r _request
for _ in {1..128}; do
  printf x >&2 || true
done
sleep 0.1
printf '{"version":1,"ciphertext":"b3BlbmZoZS1jaXBoZXI"}\n'
"#,
    )
    .unwrap();
    let mut permissions = fs::metadata(&script_path).unwrap().permissions();
    permissions.set_mode(0o700);
    fs::set_permissions(&script_path, permissions).unwrap();

    let backend = CommandOpenFheBackend::new_unchecked_for_tests("bash")
        .with_args([script_path.display().to_string()])
        .with_max_output_bytes(64);
    let encryptor = CkksVectorEncryptor::new(
        "tenant-a:ckks",
        "embedding",
        CkksParameters::openfhe_default_128_bit(),
        SecretKey::from_bytes([29u8; 32]),
        backend,
    )
    .unwrap();

    let err = encryptor
        .encrypt("docs", "point-1", &public_material(), &[1.0])
        .unwrap_err();

    assert!(
        matches!(err, CkksError::Backend(ref message) if message.contains("stderr exceeded")),
        "unexpected bridge error: {err:?}",
    );
}

#[cfg(unix)]
#[test]
fn command_openfhe_backend_stderr_cap_fails_before_timeout() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::tempdir().unwrap();
    let script_path = dir.path().join("stderr-infinite-openfhe-bridge.sh");
    fs::write(
        &script_path,
        r#"#!/usr/bin/env bash
set -uo pipefail
IFS= read -r _request
while true; do
  printf x >&2 || exit 0
done
"#,
    )
    .unwrap();
    let mut permissions = fs::metadata(&script_path).unwrap().permissions();
    permissions.set_mode(0o700);
    fs::set_permissions(&script_path, permissions).unwrap();

    let backend = CommandOpenFheBackend::new_unchecked_for_tests("bash")
        .with_args([script_path.display().to_string()])
        .with_timeout(Duration::from_secs(5))
        .with_max_output_bytes(64);
    let encryptor = CkksVectorEncryptor::new(
        "tenant-a:ckks",
        "embedding",
        CkksParameters::openfhe_default_128_bit(),
        SecretKey::from_bytes([29u8; 32]),
        backend,
    )
    .unwrap();

    let started = Instant::now();
    let err = encryptor
        .encrypt("docs", "point-1", &public_material(), &[1.0])
        .unwrap_err();

    assert!(
        matches!(err, CkksError::Backend(ref message) if message.contains("stderr exceeded")),
        "unexpected bridge error: {err:?}",
    );
    assert!(started.elapsed() < Duration::from_secs(1));
}

#[cfg(unix)]
#[test]
fn command_openfhe_backend_reuses_worker_process_when_bridge_supports_streaming() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::tempdir().unwrap();
    let script_path = dir.path().join("loop-openfhe-bridge.sh");
    let count_path = dir.path().join("counts.log");
    fs::write(
        &script_path,
        format!(
            r#"#!/usr/bin/env bash
set -euo pipefail
count_file={}
printf 'start\n' >> "$count_file"
while IFS= read -r request; do
  case "$request" in
    *'"scheme":"openfhe-ckks"'*'"vector_name":"embedding"'*) ;;
    *) exit 7 ;;
  esac
  printf 'request\n' >> "$count_file"
  printf '{{"version":1,"ciphertext":"b3BlbmZoZS1jaXBoZXI"}}\n'
done
"#,
            count_path.display(),
        ),
    )
    .unwrap();
    let mut permissions = fs::metadata(&script_path).unwrap().permissions();
    permissions.set_mode(0o700);
    fs::set_permissions(&script_path, permissions).unwrap();

    let backend = CommandOpenFheBackend::new_unchecked_for_tests("bash")
        .with_args([script_path.display().to_string()]);
    let encryptor = CkksVectorEncryptor::new(
        "tenant-a:ckks",
        "embedding",
        CkksParameters::openfhe_default_128_bit(),
        SecretKey::from_bytes([29u8; 32]),
        backend,
    )
    .unwrap();

    encryptor
        .encrypt("docs", "point-1", &public_material(), &[1.0])
        .unwrap();
    encryptor
        .encrypt("docs", "point-2", &public_material(), &[2.0])
        .unwrap();
    drop(encryptor);

    let counts = fs::read_to_string(count_path).unwrap();
    assert_eq!(counts.lines().filter(|line| *line == "start").count(), 1);
    assert_eq!(counts.lines().filter(|line| *line == "request").count(), 2);
}

#[cfg(unix)]
#[test]
fn command_openfhe_backend_uses_pool_size_for_concurrent_requests() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::tempdir().unwrap();
    let script_path = dir.path().join("pooled-openfhe-bridge.sh");
    let count_path = dir.path().join("pool-counts.log");
    fs::write(
        &script_path,
        format!(
            r#"#!/usr/bin/env bash
set -euo pipefail
	count_file={}
	printf 'start\n' >> "$count_file"
	while IFS= read -r _request; do
	  printf 'request\n' >> "$count_file"
	  sleep 2
	  printf '{{"version":1,"ciphertext":"b3BlbmZoZS1jaXBoZXI"}}\n'
	done
"#,
            count_path.display(),
        ),
    )
    .unwrap();
    let mut permissions = fs::metadata(&script_path).unwrap().permissions();
    permissions.set_mode(0o700);
    fs::set_permissions(&script_path, permissions).unwrap();

    let backend = CommandOpenFheBackend::new_unchecked_for_tests("bash")
        .with_args([script_path.display().to_string()])
        .with_pool_size(NonZeroUsize::new(2).unwrap());
    let encryptor = Arc::new(
        CkksVectorEncryptor::new(
            "tenant-a:ckks",
            "embedding",
            CkksParameters::openfhe_default_128_bit(),
            SecretKey::from_bytes([29u8; 32]),
            backend,
        )
        .unwrap(),
    );

    let first_encryptor = Arc::clone(&encryptor);
    let first = std::thread::spawn(move || {
        first_encryptor
            .encrypt("docs", "point-1", &public_material(), &[1.0])
            .unwrap();
    });
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let counts = fs::read_to_string(&count_path).unwrap_or_default();
        if counts.lines().filter(|line| *line == "request").count() == 1 {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "first OpenFHE bridge request did not become busy before timeout"
        );
        std::thread::sleep(Duration::from_millis(10));
    }

    let second_encryptor = Arc::clone(&encryptor);
    let second = std::thread::spawn(move || {
        second_encryptor
            .encrypt("docs", "point-2", &public_material(), &[2.0])
            .unwrap();
    });
    first.join().unwrap();
    second.join().unwrap();
    drop(encryptor);

    let counts = fs::read_to_string(count_path).unwrap();
    assert_eq!(counts.lines().filter(|line| *line == "start").count(), 2);
    assert_eq!(counts.lines().filter(|line| *line == "request").count(), 2);
}

#[test]
fn encrypted_ckks_vector_has_stable_json_shape() {
    let encrypted = encryptor()
        .encrypt("docs", "point-1", &public_material(), &[1.0])
        .unwrap();
    let value = serde_json::to_value(encrypted).unwrap();

    assert_eq!(value["version"], json!(1));
    assert_eq!(value["scheme"], json!("openfhe-ckks"));
    assert_eq!(value["envelope"]["key_id"], json!("tenant-a:ckks"));
    assert!(value["envelope"]["nonce"].as_str().unwrap().len() >= 16);
    assert!(value["envelope"]["ciphertext"].as_str().unwrap().len() >= 32);
}

#[test]
fn vector_metadata_tampering_fails_authentication() {
    let encryptor = encryptor();
    let mut encrypted = encryptor
        .encrypt("docs", "point-1", &public_material(), &[1.0, 2.0, 3.0])
        .unwrap();

    let mut raw = BASE64URL_NOPAD
        .decode(encrypted.envelope.ciphertext.as_bytes())
        .unwrap();
    raw[0] ^= 0x01;
    encrypted.envelope.ciphertext = BASE64URL_NOPAD.encode(&raw);

    assert!(matches!(
        encryptor.open("docs", "point-1", &public_material(), &encrypted),
        Err(CkksError::Envelope(_)),
    ));
}

#[test]
fn vector_header_tampering_fails_authentication() {
    let encryptor = encryptor();
    let mut encrypted = encryptor
        .encrypt("docs", "point-1", &public_material(), &[1.0, 2.0])
        .unwrap();
    encrypted.envelope.material_fingerprint.clear();

    assert!(matches!(
        encryptor.open("docs", "point-1", &public_material(), &encrypted),
        Err(CkksError::Envelope(EncryptionError::OpenFailed)),
    ));
}

#[test]
fn vector_envelope_is_bound_to_collection_point_and_vector() {
    let encryptor = encryptor();
    let encrypted = encryptor
        .encrypt("docs", "point-1", &public_material(), &[1.0, 2.0])
        .unwrap();

    assert!(matches!(
        encryptor.open("docs", "point-2", &public_material(), &encrypted),
        Err(CkksError::Envelope(_)),
    ));

    let other_vector = CkksVectorEncryptor::new(
        "tenant-a:ckks",
        "other",
        CkksParameters::openfhe_default_128_bit(),
        SecretKey::from_bytes([29u8; 32]),
        SealedTestBackend,
    )
    .unwrap();
    assert!(matches!(
        other_vector.open("docs", "point-1", &public_material(), &encrypted),
        Err(CkksError::Envelope(_)),
    ));
}
