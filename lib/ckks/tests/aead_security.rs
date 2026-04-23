use data_encoding::BASE64URL_NOPAD;
use proptest::prelude::*;
use qdrant_ckks::{AeadCipher, EncryptionContext, EncryptionError, SecretKey};

fn fixed_cipher() -> AeadCipher {
    AeadCipher::new("tenant-a:primary", SecretKey::from_bytes([7u8; 32])).unwrap()
}

fn payload_context<'a>(point_id: &'a str) -> EncryptionContext<'a> {
    EncryptionContext::payload_text("docs", point_id, "body")
}

#[test]
fn encrypt_decrypt_round_trip_uses_fresh_nonce() {
    let cipher = fixed_cipher();
    let context = payload_context("42");
    let plaintext = b"security sensitive body text";

    let first = cipher.encrypt(plaintext, context).unwrap();
    let second = cipher.encrypt(plaintext, context).unwrap();

    assert_ne!(first.nonce, second.nonce);
    assert_ne!(first.ciphertext, second.ciphertext);
    assert_eq!(cipher.decrypt(&first, context).unwrap(), plaintext);
    assert_eq!(cipher.decrypt(&second, context).unwrap(), plaintext);
}

#[test]
fn aad_binds_ciphertext_to_collection_point_and_field() {
    let cipher = fixed_cipher();
    let envelope = cipher
        .encrypt(b"do not move between points", payload_context("42"))
        .unwrap();

    let wrong_point = cipher.decrypt(&envelope, payload_context("43"));
    let wrong_collection = cipher.decrypt(
        &envelope,
        EncryptionContext::payload_text("other_docs", "42", "body"),
    );
    let wrong_field = cipher.decrypt(
        &envelope,
        EncryptionContext::payload_text("docs", "42", "summary"),
    );

    assert_eq!(wrong_point, Err(EncryptionError::OpenFailed));
    assert_eq!(wrong_collection, Err(EncryptionError::OpenFailed));
    assert_eq!(wrong_field, Err(EncryptionError::OpenFailed));
}

#[test]
fn ciphertext_tampering_fails_authentication() {
    let cipher = fixed_cipher();
    let mut envelope = cipher
        .encrypt(b"authenticated", payload_context("42"))
        .unwrap();
    let mut raw = BASE64URL_NOPAD
        .decode(envelope.ciphertext.as_bytes())
        .unwrap();

    raw[0] ^= 0x80;
    envelope.ciphertext = BASE64URL_NOPAD.encode(&raw);

    assert_eq!(
        cipher.decrypt(&envelope, payload_context("42")),
        Err(EncryptionError::OpenFailed),
    );
}

#[test]
fn envelope_metadata_is_rejected_before_decryption() {
    let cipher = fixed_cipher();
    let mut envelope = cipher.encrypt(b"metadata", payload_context("42")).unwrap();

    envelope.version = 2;
    assert_eq!(
        cipher.decrypt(&envelope, payload_context("42")),
        Err(EncryptionError::UnsupportedVersion(2)),
    );

    envelope.version = 1;
    envelope.algorithm = "plaintext".to_string();
    assert_eq!(
        cipher.decrypt(&envelope, payload_context("42")),
        Err(EncryptionError::UnsupportedAlgorithm(
            "plaintext".to_string()
        )),
    );

    envelope.algorithm = "AES-256-GCM".to_string();
    envelope.key_id = "tenant-b:primary".to_string();
    assert_eq!(
        cipher.decrypt(&envelope, payload_context("42")),
        Err(EncryptionError::KeyMismatch),
    );
}

#[test]
fn key_ids_are_strict_ascii_capability_names() {
    assert!(AeadCipher::new("valid._:-09AZaz", SecretKey::from_bytes([1u8; 32])).is_ok());
    assert_eq!(
        AeadCipher::new("", SecretKey::from_bytes([1u8; 32])).err(),
        Some(EncryptionError::InvalidKeyId),
    );
    assert_eq!(
        AeadCipher::new("tenant/key", SecretKey::from_bytes([1u8; 32])).err(),
        Some(EncryptionError::InvalidKeyId),
    );
    assert_eq!(
        AeadCipher::new("테넌트", SecretKey::from_bytes([1u8; 32])).err(),
        Some(EncryptionError::InvalidKeyId),
    );
}

#[test]
fn debug_output_redacts_secrets_and_ciphertexts() {
    let secret = SecretKey::from_bytes([42u8; 32]);
    let debug_secret = format!("{secret:?}");
    assert!(debug_secret.contains("redacted"));
    assert!(!debug_secret.contains("42"));

    let cipher = AeadCipher::new("tenant-a:primary", secret).unwrap();
    let envelope = cipher
        .encrypt(b"hidden text", payload_context("42"))
        .unwrap();
    let debug_envelope = format!("{envelope:?}");

    assert!(debug_envelope.contains("ciphertext_len"));
    assert!(!debug_envelope.contains(&envelope.nonce));
    assert!(!debug_envelope.contains(&envelope.ciphertext));
    assert!(!debug_envelope.contains("hidden text"));
}

proptest! {
    #[test]
    fn arbitrary_bytes_round_trip(bytes in proptest::collection::vec(any::<u8>(), 0..4096)) {
        let cipher = fixed_cipher();
        let context = payload_context("property");
        let envelope = cipher.encrypt(&bytes, context).unwrap();
        let decrypted = cipher.decrypt(&envelope, context).unwrap();
        prop_assert_eq!(decrypted, bytes);
    }
}
