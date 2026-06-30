use data_encoding::BASE64URL_NOPAD;
use proptest::prelude::*;
use qdrant_sec::{
    AeadCipher, AeadKeyring, CKKS_VECTOR_KEY_DOMAIN, EncryptionContext, EncryptionError,
    LocalMasterKeyProvider, MasterKeyProvider, PAYLOAD_TEXT_KEY_DOMAIN,
    RESOURCE_KEY_WRAP_ALGORITHM, SecretKey, WrappedKeyBlob, rewrap_resource_key,
};
use ring::aead::{AES_256_GCM, Aad, LessSafeKey, Nonce, UnboundKey};
use serde_json::Value;

fn fixed_cipher() -> AeadCipher {
    test_cipher("tenant-a:primary", 7, "tenant-a/primary@v1")
}

fn test_cipher(key_id: &str, key_byte: u8, material_fingerprint: &str) -> AeadCipher {
    AeadCipher::new_with_material_fingerprint(
        key_id,
        SecretKey::from_bytes([key_byte; 32]),
        material_fingerprint,
    )
    .unwrap()
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

    assert!(!first.material_fingerprint.is_empty());
    assert_eq!(first.material_fingerprint, cipher.material_fingerprint());
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
fn empty_ciphertext_reports_ciphertext_length_error() {
    let cipher = fixed_cipher();
    let mut envelope = cipher
        .encrypt(b"authenticated", payload_context("42"))
        .unwrap();
    envelope.ciphertext.clear();

    assert_eq!(
        cipher.decrypt(&envelope, payload_context("42")),
        Err(EncryptionError::InvalidCiphertextLength),
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
fn envelope_material_fingerprint_must_match_active_key() {
    let cipher = fixed_cipher();
    let other_cipher = test_cipher("tenant-a:primary", 8, "tenant-a/other@v1");
    let envelope = cipher.encrypt(b"metadata", payload_context("42")).unwrap();

    assert_eq!(
        other_cipher.decrypt(&envelope, payload_context("42")),
        Err(EncryptionError::MaterialFingerprintMismatch),
    );
}

#[test]
fn configured_material_fingerprint_id_replaces_raw_key_fingerprint() {
    let cipher = AeadCipher::new_with_material_fingerprint(
        "tenant-a:primary",
        SecretKey::from_bytes([7u8; 32]),
        "tenant-a/payload@v3",
    )
    .unwrap();
    let envelope = cipher.encrypt(b"metadata", payload_context("42")).unwrap();

    assert_eq!(cipher.material_fingerprint(), "tenant-a/payload@v3");
    assert_eq!(envelope.material_fingerprint, "tenant-a/payload@v3");
    assert_eq!(
        AeadCipher::new_with_material_fingerprint(
            "tenant-a:primary",
            SecretKey::from_bytes([7u8; 32]),
            "",
        )
        .err(),
        Some(EncryptionError::InvalidMaterialFingerprintId),
    );
}

#[test]
fn local_master_key_provider_wraps_resource_key_with_aad() {
    let aad = b"qdrant-sec\x00resource-key-wrap\x00docs\x00rk-epoch-3";
    let provider =
        LocalMasterKeyProvider::new("tenant-a/mk@v1", SecretKey::from_bytes([55u8; 32])).unwrap();
    let resource_key = SecretKey::from_bytes([77u8; 32]);
    let payload_cipher = AeadCipher::new_with_material_fingerprint(
        "tenant-a:payload",
        resource_key.derive_subkey(PAYLOAD_TEXT_KEY_DOMAIN).unwrap(),
        "tenant-a/payload@v1",
    )
    .unwrap();
    let context = payload_context("42");
    let envelope = payload_cipher
        .encrypt(b"wrapped resource key data", context)
        .unwrap();

    let wrapped = provider.wrap_resource_key(&resource_key, aad).unwrap();
    assert_eq!(wrapped.version, 1);
    assert_eq!(wrapped.algorithm, RESOURCE_KEY_WRAP_ALGORITHM);
    assert_eq!(wrapped.mk_id, "tenant-a/mk@v1");

    let unwrapped =
        LocalMasterKeyProvider::new("tenant-a/mk@v1", SecretKey::from_bytes([55u8; 32]))
            .unwrap()
            .unwrap_resource_key(&wrapped, aad)
            .unwrap();
    let unwrapped_cipher = AeadCipher::new_with_material_fingerprint(
        "tenant-a:payload",
        unwrapped.derive_subkey(PAYLOAD_TEXT_KEY_DOMAIN).unwrap(),
        "tenant-a/payload@v1",
    )
    .unwrap();

    assert_eq!(
        unwrapped_cipher
            .decrypt(&envelope, context)
            .unwrap()
            .as_slice(),
        b"wrapped resource key data",
    );
    assert_eq!(
        provider.unwrap_resource_key(&wrapped, b"wrong aad").err(),
        Some(EncryptionError::OpenFailed),
    );
}

#[test]
fn wrapped_resource_key_rejects_unknown_metadata_fields() {
    let provider =
        LocalMasterKeyProvider::new("tenant-a/mk@v1", SecretKey::from_bytes([55u8; 32])).unwrap();
    let wrapped = provider
        .wrap_resource_key(&SecretKey::from_bytes([77u8; 32]), b"aad")
        .unwrap();
    let mut value = serde_json::to_value(wrapped).unwrap();

    value
        .as_object_mut()
        .unwrap()
        .insert("unexpected_header".to_string(), serde_json::json!(true));

    assert!(serde_json::from_value::<WrappedKeyBlob>(value).is_err());
}

#[test]
fn rewrap_resource_key_rotates_master_key_without_reencrypting_data() {
    let old_provider =
        LocalMasterKeyProvider::new("tenant-a/mk@v1", SecretKey::from_bytes([55u8; 32])).unwrap();
    let new_provider =
        LocalMasterKeyProvider::new("tenant-a/mk@v2", SecretKey::from_bytes([56u8; 32])).unwrap();
    let old_aad = b"qdrant-sec\x00resource-key-wrap\x00docs-rk-v1\x00mk-v1";
    let new_aad = b"qdrant-sec\x00resource-key-wrap\x00docs-rk-v1\x00mk-v2";
    let resource_key = SecretKey::from_bytes([77u8; 32]);
    let payload_cipher = AeadCipher::new_with_material_fingerprint(
        "tenant-a:payload",
        resource_key.derive_subkey(PAYLOAD_TEXT_KEY_DOMAIN).unwrap(),
        "tenant-a/payload@v1",
    )
    .unwrap();
    let context = payload_context("42");
    let envelope = payload_cipher
        .encrypt(b"data does not need re-encryption for MK rotation", context)
        .unwrap();
    let old_wrapped = old_provider
        .wrap_resource_key(&resource_key, old_aad)
        .unwrap();

    let new_wrapped =
        rewrap_resource_key(&old_provider, &new_provider, &old_wrapped, old_aad, new_aad).unwrap();
    assert_eq!(new_wrapped.mk_id, "tenant-a/mk@v2");
    assert_ne!(new_wrapped.wrapped_key, old_wrapped.wrapped_key);

    assert_eq!(
        old_provider
            .unwrap_resource_key(&new_wrapped, new_aad)
            .err(),
        Some(EncryptionError::MasterKeyMismatch),
    );
    assert_eq!(
        new_provider
            .unwrap_resource_key(&new_wrapped, old_aad)
            .err(),
        Some(EncryptionError::OpenFailed),
    );

    let rewrapped_resource_key = new_provider
        .unwrap_resource_key(&new_wrapped, new_aad)
        .unwrap();
    let rewrapped_payload_cipher = AeadCipher::new_with_material_fingerprint(
        "tenant-a:payload",
        rewrapped_resource_key
            .derive_subkey(PAYLOAD_TEXT_KEY_DOMAIN)
            .unwrap(),
        "tenant-a/payload@v1",
    )
    .unwrap();
    assert_eq!(
        rewrapped_payload_cipher
            .decrypt(&envelope, context)
            .unwrap()
            .as_slice(),
        b"data does not need re-encryption for MK rotation",
    );
}

#[test]
fn resource_key_rotation_matches_sdk_test_vector() {
    let fixture: Value = serde_json::from_str(include_str!(
        "../../../docs/qdrant-sec-resource-key-rotation-test-vector.json"
    ))
    .expect("resource key rotation test vector must be valid JSON");
    let get = |key: &str| {
        fixture
            .get(key)
            .and_then(Value::as_str)
            .unwrap_or_else(|| panic!("test vector must define string field {key}"))
    };

    assert_eq!(get("wrap_algorithm"), RESOURCE_KEY_WRAP_ALGORITHM);

    let old_mk = BASE64URL_NOPAD
        .decode(get("old_mk_b64").as_bytes())
        .unwrap();
    let new_mk = BASE64URL_NOPAD
        .decode(get("new_mk_b64").as_bytes())
        .unwrap();
    let rk = BASE64URL_NOPAD
        .decode(get("resource_key_b64").as_bytes())
        .unwrap();
    let old_nonce = BASE64URL_NOPAD
        .decode(get("old_wrapped_nonce").as_bytes())
        .unwrap();
    let new_nonce = BASE64URL_NOPAD
        .decode(get("new_wrapped_nonce").as_bytes())
        .unwrap();
    let old_aad = BASE64URL_NOPAD
        .decode(get("old_aad_b64").as_bytes())
        .unwrap();
    let new_aad = BASE64URL_NOPAD
        .decode(get("new_aad_b64").as_bytes())
        .unwrap();

    let deterministic_wrap =
        |mk: &[u8], nonce_bytes: &[u8], aad: &[u8]| -> Result<String, ring::error::Unspecified> {
            let key = LessSafeKey::new(UnboundKey::new(&AES_256_GCM, mk)?);
            let mut in_out = rk.clone();
            let tag = key.seal_in_place_separate_tag(
                Nonce::try_assume_unique_for_key(nonce_bytes)?,
                Aad::from(aad),
                &mut in_out,
            )?;
            in_out.extend_from_slice(tag.as_ref());
            Ok(BASE64URL_NOPAD.encode(&in_out))
        };

    assert_eq!(
        deterministic_wrap(&old_mk, &old_nonce, &old_aad).unwrap(),
        get("old_wrapped_key_b64"),
    );
    assert_eq!(
        deterministic_wrap(&new_mk, &new_nonce, &new_aad).unwrap(),
        get("new_wrapped_key_b64"),
    );

    let old_provider = LocalMasterKeyProvider::new(
        get("old_mk_id"),
        SecretKey::try_from_slice(&old_mk).unwrap(),
    )
    .unwrap();
    let new_provider = LocalMasterKeyProvider::new(
        get("new_mk_id"),
        SecretKey::try_from_slice(&new_mk).unwrap(),
    )
    .unwrap();
    let old_wrapped = WrappedKeyBlob {
        version: fixture["version"].as_u64().unwrap() as u8,
        algorithm: get("wrap_algorithm").to_string(),
        mk_id: get("old_mk_id").to_string(),
        nonce: get("old_wrapped_nonce").to_string(),
        wrapped_key: get("old_wrapped_key_b64").to_string(),
    };
    let new_wrapped = WrappedKeyBlob {
        version: fixture["version"].as_u64().unwrap() as u8,
        algorithm: get("wrap_algorithm").to_string(),
        mk_id: get("new_mk_id").to_string(),
        nonce: get("new_wrapped_nonce").to_string(),
        wrapped_key: get("new_wrapped_key_b64").to_string(),
    };

    assert_eq!(
        old_provider
            .unwrap_resource_key(&old_wrapped, &old_aad)
            .unwrap()
            .as_bytes(),
        rk.as_slice(),
    );
    assert_eq!(
        new_provider
            .unwrap_resource_key(&new_wrapped, &new_aad)
            .unwrap()
            .as_bytes(),
        rk.as_slice(),
    );
    assert_eq!(
        new_provider
            .unwrap_resource_key(&new_wrapped, &old_aad)
            .err(),
        Some(EncryptionError::OpenFailed),
    );
}

#[test]
fn wrapped_resource_key_debug_redacts_wrapped_key_material() {
    let provider =
        LocalMasterKeyProvider::new("tenant-a/mk@v1", SecretKey::from_bytes([56u8; 32])).unwrap();
    let wrapped = provider
        .wrap_resource_key(&SecretKey::from_bytes([78u8; 32]), b"aad")
        .unwrap();

    let debug_provider = format!("{provider:?}");
    let debug_wrapped = format!("{wrapped:?}");

    assert!(debug_provider.contains("redacted"));
    assert!(!debug_provider.contains("56"));
    assert!(debug_wrapped.contains("wrapped_key_len"));
    assert!(!debug_wrapped.contains(&wrapped.nonce));
    assert!(!debug_wrapped.contains(&wrapped.wrapped_key));
    assert_eq!(
        LocalMasterKeyProvider::new("tenant-a/other-mk", SecretKey::from_bytes([56u8; 32]))
            .unwrap()
            .unwrap_resource_key(&wrapped, b"aad")
            .err(),
        Some(EncryptionError::MasterKeyMismatch),
    );
}

#[test]
fn stripping_material_fingerprint_breaks_authentication() {
    let cipher = fixed_cipher();
    let mut envelope = cipher.encrypt(b"metadata", payload_context("42")).unwrap();
    envelope.material_fingerprint.clear();

    assert_eq!(
        cipher.decrypt(&envelope, payload_context("42")),
        Err(EncryptionError::InvalidMaterialFingerprintId),
    );
}

#[test]
fn keyring_encrypts_with_active_key_and_decrypts_retired_key() {
    let context = payload_context("42");
    let retired_cipher = test_cipher("tenant-a:payload-old", 9, "tenant-a/payload-old@v1");
    let retired_envelope = retired_cipher.encrypt(b"before rotation", context).unwrap();
    let keyring = AeadKeyring::new(test_cipher(
        "tenant-a:payload-new",
        10,
        "tenant-a/payload-new@v1",
    ))
    .with_retired(retired_cipher);

    assert_eq!(
        keyring
            .decrypt(&retired_envelope, context)
            .unwrap()
            .as_slice(),
        b"before rotation",
    );

    let active_envelope = keyring.encrypt(b"after rotation", context).unwrap();
    assert_eq!(active_envelope.key_id, "tenant-a:payload-new");
    assert_eq!(
        active_envelope.material_fingerprint,
        keyring.material_fingerprint(),
    );
    assert_eq!(
        keyring
            .decrypt(&active_envelope, context)
            .unwrap()
            .as_slice(),
        b"after rotation",
    );
}

#[test]
fn keyring_decrypts_matching_retired_key_after_unrelated_retired_keys() {
    let context = payload_context("42");
    let matching_retired = test_cipher("tenant-a:payload-old", 44, "tenant-a/payload-old@v1");
    let retired_envelope = matching_retired
        .encrypt(b"older rotation window", context)
        .unwrap();
    let mut keyring = AeadKeyring::new(test_cipher(
        "tenant-a:payload-new",
        45,
        "tenant-a/payload-new@v1",
    ));

    for index in 0..8 {
        let key_id = format!("tenant-a:payload-unrelated-{index}");
        let fingerprint = format!("tenant-a/payload-unrelated@v{index}");
        keyring = keyring.with_retired(test_cipher(&key_id, 46 + index, &fingerprint));
    }
    keyring = keyring.with_retired(matching_retired);

    assert_eq!(
        keyring
            .decrypt(&retired_envelope, context)
            .unwrap()
            .as_slice(),
        b"older rotation window",
    );
}

#[test]
fn keyring_requires_matching_fingerprint_before_decrypt() {
    let context = payload_context("42");
    let envelope = test_cipher("tenant-a:payload", 31, "tenant-a/payload@old")
        .encrypt(b"not in this keyring", context)
        .unwrap();
    let keyring = AeadKeyring::new(test_cipher("tenant-a:payload", 32, "tenant-a/payload@new"));

    assert_eq!(
        keyring.decrypt(&envelope, context),
        Err(EncryptionError::KeyMismatch),
    );
}

#[test]
fn keyring_returns_open_failed_for_matching_retired_tamper() {
    let context = payload_context("42");
    let retired_cipher = test_cipher("tenant-a:payload-old", 33, "tenant-a/payload-old@v1");
    let mut envelope = retired_cipher.encrypt(b"before rotation", context).unwrap();
    let mut raw = BASE64URL_NOPAD
        .decode(envelope.ciphertext.as_bytes())
        .unwrap();
    raw[0] ^= 0x80;
    envelope.ciphertext = BASE64URL_NOPAD.encode(&raw);

    let keyring = AeadKeyring::new(test_cipher(
        "tenant-a:payload-new",
        34,
        "tenant-a/payload-new@v1",
    ))
    .with_retired(retired_cipher)
    .with_retired(test_cipher(
        "tenant-a:payload-old",
        35,
        "tenant-a/payload-old@v2",
    ));

    assert_eq!(
        keyring.decrypt(&envelope, context),
        Err(EncryptionError::OpenFailed),
    );
}

#[test]
fn keyring_does_not_fallback_after_matching_active_open_failure() {
    let context = payload_context("42");
    let active_cipher = test_cipher("tenant-a:payload", 38, "tenant-a/payload@v1");
    let retired_cipher = test_cipher("tenant-a:payload", 39, "tenant-a/payload@v1");
    let envelope = retired_cipher
        .encrypt(b"old key material", context)
        .unwrap();
    let keyring = AeadKeyring::new(active_cipher).with_retired(retired_cipher);

    assert_eq!(
        keyring.decrypt(&envelope, context),
        Err(EncryptionError::OpenFailed),
    );
}

#[test]
fn keyring_does_not_try_later_retired_keys_after_matching_retired_open_failure() {
    let context = payload_context("42");
    let active_cipher = test_cipher("tenant-a:payload-new", 40, "tenant-a/payload-new@v1");
    let first_retired = test_cipher("tenant-a:payload-old", 41, "tenant-a/payload-old@v1");
    let later_retired = test_cipher("tenant-a:payload-old", 42, "tenant-a/payload-old@v1");
    let envelope = later_retired
        .encrypt(b"ambiguous retired metadata", context)
        .unwrap();
    let keyring = AeadKeyring::new(active_cipher)
        .with_retired(first_retired)
        .with_retired(later_retired);

    assert_eq!(
        keyring.decrypt(&envelope, context),
        Err(EncryptionError::OpenFailed),
    );
}

#[test]
fn envelope_records_and_authenticates_resource_key_metadata() {
    let context = payload_context("42");
    let secret = SecretKey::from_bytes([36u8; 32]);
    let cipher = AeadCipher::new_with_material_fingerprint(
        "tenant-a:payload",
        secret,
        "tenant-a/payload-rk@v3",
    )
    .unwrap()
    .with_resource_key_metadata("tenant-a/payload-rk-v3", 3)
    .unwrap();

    let envelope = cipher.encrypt(b"resource scoped", context).unwrap();

    assert_eq!(envelope.rk_id, "tenant-a/payload-rk-v3");
    assert_eq!(envelope.rk_epoch, Some(3));
    assert_eq!(
        cipher.decrypt(&envelope, context).unwrap(),
        b"resource scoped"
    );

    let mut tampered_epoch = envelope.clone();
    tampered_epoch.rk_epoch = Some(4);
    let epoch_4_cipher = AeadCipher::new_with_material_fingerprint(
        "tenant-a:payload",
        SecretKey::from_bytes([36u8; 32]),
        "tenant-a/payload-rk@v3",
    )
    .unwrap()
    .with_resource_key_metadata("tenant-a/payload-rk-v3", 4)
    .unwrap();
    assert_eq!(
        epoch_4_cipher.decrypt(&tampered_epoch, context),
        Err(EncryptionError::OpenFailed),
    );

    let mut tampered_rk = envelope.clone();
    tampered_rk.rk_id = "tenant-a/payload-rk-v4".to_string();
    let rk_v4_cipher = AeadCipher::new_with_material_fingerprint(
        "tenant-a:payload",
        SecretKey::from_bytes([36u8; 32]),
        "tenant-a/payload-rk@v3",
    )
    .unwrap()
    .with_resource_key_metadata("tenant-a/payload-rk-v4", 3)
    .unwrap();
    assert_eq!(
        rk_v4_cipher.decrypt(&tampered_rk, context),
        Err(EncryptionError::OpenFailed),
    );
}

#[test]
fn resource_key_metadata_rejects_legacy_envelope_without_rk_metadata() {
    let context = payload_context("42");
    let legacy_cipher = AeadCipher::new_with_material_fingerprint(
        "tenant-a:payload",
        SecretKey::from_bytes([37u8; 32]),
        "tenant-a/payload-rk@v3",
    )
    .unwrap();
    let envelope = legacy_cipher.encrypt(b"legacy envelope", context).unwrap();
    assert!(envelope.rk_id.is_empty());
    assert_eq!(envelope.rk_epoch, None);

    let tagged_cipher = AeadCipher::new_with_material_fingerprint(
        "tenant-a:payload",
        SecretKey::from_bytes([37u8; 32]),
        "tenant-a/payload-rk@v3",
    )
    .unwrap()
    .with_resource_key_metadata("tenant-a/payload-rk-v3", 3)
    .unwrap();

    assert_eq!(
        tagged_cipher.decrypt(&envelope, context),
        Err(EncryptionError::KeyMismatch),
    );
}

#[test]
fn key_ids_are_strict_ascii_capability_names() {
    assert!(
        AeadCipher::new_with_material_fingerprint(
            "valid._:-09AZaz",
            SecretKey::from_bytes([1u8; 32]),
            "tenant-a/payload@v1",
        )
        .is_ok()
    );
    assert_eq!(
        AeadCipher::new_with_material_fingerprint(
            "",
            SecretKey::from_bytes([1u8; 32]),
            "tenant-a/payload@v1",
        )
        .err(),
        Some(EncryptionError::InvalidKeyId),
    );
    assert_eq!(
        AeadCipher::new_with_material_fingerprint(
            "tenant/key",
            SecretKey::from_bytes([1u8; 32]),
            "tenant-a/payload@v1",
        )
        .err(),
        Some(EncryptionError::InvalidKeyId),
    );
    assert_eq!(
        AeadCipher::new_with_material_fingerprint(
            "테넌트",
            SecretKey::from_bytes([1u8; 32]),
            "tenant-a/payload@v1",
        )
        .err(),
        Some(EncryptionError::InvalidKeyId),
    );
}

#[test]
fn derived_subkeys_separate_payload_and_vector_domains() {
    let master_key = SecretKey::from_bytes([19u8; 32]);
    let payload_cipher = AeadCipher::new_with_material_fingerprint(
        "tenant-a:primary",
        master_key.derive_subkey(PAYLOAD_TEXT_KEY_DOMAIN).unwrap(),
        "tenant-a/payload@v1",
    )
    .unwrap();
    let vector_cipher = AeadCipher::new_with_material_fingerprint(
        "tenant-a:primary",
        master_key.derive_subkey(CKKS_VECTOR_KEY_DOMAIN).unwrap(),
        "tenant-a/vector@v1",
    )
    .unwrap();
    let context = payload_context("42");
    let envelope = payload_cipher
        .encrypt(b"domain separated", context)
        .unwrap();

    assert_eq!(
        payload_cipher
            .decrypt(&envelope, context)
            .unwrap()
            .as_slice(),
        b"domain separated",
    );
    assert_eq!(
        vector_cipher.decrypt(&envelope, context),
        Err(EncryptionError::MaterialFingerprintMismatch),
    );
}

#[test]
fn debug_output_redacts_secrets_and_ciphertexts() {
    let secret = SecretKey::from_bytes([42u8; 32]);
    let debug_secret = format!("{secret:?}");
    assert!(debug_secret.contains("redacted"));
    assert!(!debug_secret.contains("42"));

    let cipher = AeadCipher::new_with_material_fingerprint(
        "tenant-a:primary",
        secret,
        "tenant-a/primary@v1",
    )
    .unwrap();
    let envelope = cipher
        .encrypt(b"hidden text", payload_context("42"))
        .unwrap();
    let debug_envelope = format!("{envelope:?}");

    assert!(debug_envelope.contains("ciphertext_len"));
    assert!(!debug_envelope.contains(&envelope.nonce));
    assert!(!debug_envelope.contains(&envelope.ciphertext));
    assert!(!debug_envelope.contains("hidden text"));
    assert!(!debug_envelope.contains("tenant-a:primary"));
    assert!(!debug_envelope.contains("tenant-a/primary@v1"));
    if !envelope.material_fingerprint.is_empty() {
        assert!(!debug_envelope.contains(&envelope.material_fingerprint));
    }
}

#[test]
fn encryption_error_debug_redacts_attacker_controlled_values() {
    let sentinel = "aead-debug-secret-sentinel";
    let rendered = format!(
        "{:?}",
        EncryptionError::UnsupportedAlgorithm(format!("algorithm.{sentinel}"))
    );

    assert!(rendered.contains("UnsupportedAlgorithm"), "{rendered}");
    assert!(rendered.contains("[redacted]"), "{rendered}");
    assert!(!rendered.contains(sentinel), "{rendered}");
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
