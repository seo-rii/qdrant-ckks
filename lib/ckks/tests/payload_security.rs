use data_encoding::BASE64URL_NOPAD;
use proptest::prelude::*;
use qdrant_ckks::{
    AeadCipher, AeadKeyring, CLIENT_ENCRYPTED_PAYLOAD_MARKER, ClientPayloadSignatureVerification,
    ClientPayloadValidationContext, ENCRYPTED_PAYLOAD_MARKER, EncryptionError, ExistingPayloadMode,
    PayloadEncryptionError, PayloadEncryptionPolicy, PayloadTextEncryptor, SecretKey,
    client_payload_signature_message, is_client_encrypted_payload_value,
    is_encrypted_payload_value, validate_client_payload_value,
};
use ring::rand::SystemRandom;
use ring::signature::{Ed25519KeyPair, KeyPair};
use serde_json::{Map, Value, json};

fn encryptor() -> PayloadTextEncryptor {
    let cipher = AeadCipher::new("tenant-a:payload", SecretKey::from_bytes([11u8; 32])).unwrap();
    PayloadTextEncryptor::new("docs", cipher).unwrap()
}

#[test]
fn resource_key_constructor_derives_payload_text_subkey() {
    let policy = PayloadEncryptionPolicy::new(["body"]).unwrap();
    let encryptor = PayloadTextEncryptor::new_from_resource_key_with_material_fingerprint(
        "docs",
        "tenant-a:payload",
        &SecretKey::from_bytes([71u8; 32]),
        "tenant-a/payload@v1",
    )
    .unwrap();
    let mut payload = object(json!({ "body": "domain separated" }));

    encryptor
        .encrypt_selected_fields("point-1", &mut payload, &policy)
        .unwrap();

    let wrong_raw_resource_key = PayloadTextEncryptor::new(
        "docs",
        AeadCipher::new_with_material_fingerprint(
            "tenant-a:payload",
            SecretKey::from_bytes([71u8; 32]),
            "tenant-a/payload@v1",
        )
        .unwrap(),
    )
    .unwrap();
    assert_eq!(
        wrong_raw_resource_key.decrypt_selected_fields("point-1", &mut payload, &policy),
        Err(PayloadEncryptionError::Crypto(EncryptionError::OpenFailed)),
    );
}

fn object(value: Value) -> Map<String, Value> {
    match value {
        Value::Object(object) => object,
        _ => unreachable!("test fixture must be a JSON object"),
    }
}

fn client_envelope(point_id: &str, field_path: &str) -> Value {
    json!({
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
                "point_id": point_id,
                "field_path": field_path,
                "schema_version": 1
            },
            "nonce": "AAAAAAAAAAAAAAAA",
            "ciphertext": "AQID"
        }
    })
}

fn signed_client_envelope(point_id: &str, field_path: &str) -> (Value, Vec<u8>) {
    let mut envelope = client_envelope(point_id, field_path);
    let signature = json!({
        "alg": "ed25519",
        "key_id": "tenant-a/client-signing-v1",
        "sig": ""
    });
    envelope
        .get_mut(CLIENT_ENCRYPTED_PAYLOAD_MARKER)
        .unwrap()
        .as_object_mut()
        .unwrap()
        .insert("signature".to_string(), signature);

    let rng = SystemRandom::new();
    let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
    let key_pair = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();
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

#[test]
fn client_payload_envelope_validates_expected_aad_and_key_policy() {
    let envelope = client_envelope("point-1", "body");
    let context = ClientPayloadValidationContext {
        collection_id: "docs",
        point_id: "point-1",
        field_path: "body",
        expected_key_id: Some("tenant-a/client-rk-2026-04"),
        key_id_required: true,
        signature_verification: None,
    };

    validate_client_payload_value(&envelope, context).unwrap();
    assert!(is_client_encrypted_payload_value(&envelope));
    assert!(!is_encrypted_payload_value(&envelope));
}

#[test]
fn client_payload_envelope_rejects_aad_and_key_mismatch() {
    let envelope = client_envelope("point-1", "body");
    assert_eq!(
        validate_client_payload_value(
            &envelope,
            ClientPayloadValidationContext {
                collection_id: "docs",
                point_id: "point-2",
                field_path: "body",
                expected_key_id: Some("tenant-a/client-rk-2026-04"),
                key_id_required: true,
                signature_verification: None,
            },
        ),
        Err(PayloadEncryptionError::ClientEnvelopeAadMismatch(
            "point_id".to_string()
        )),
    );
    assert_eq!(
        validate_client_payload_value(
            &envelope,
            ClientPayloadValidationContext {
                collection_id: "docs",
                point_id: "point-1",
                field_path: "body",
                expected_key_id: Some("tenant-a/other-rk"),
                key_id_required: true,
                signature_verification: None,
            },
        ),
        Err(PayloadEncryptionError::ClientKeyIdMismatch),
    );
}

#[test]
fn client_payload_envelope_verifies_ed25519_signature() {
    let (envelope, public_key) = signed_client_envelope("point-1", "body");
    validate_client_payload_value(
        &envelope,
        ClientPayloadValidationContext {
            collection_id: "docs",
            point_id: "point-1",
            field_path: "body",
            expected_key_id: Some("tenant-a/client-rk-2026-04"),
            key_id_required: true,
            signature_verification: Some(ClientPayloadSignatureVerification {
                expected_key_id: "tenant-a/client-signing-v1",
                public_key: &public_key,
            }),
        },
    )
    .unwrap();

    let mut tampered = envelope.clone();
    tampered
        .get_mut(CLIENT_ENCRYPTED_PAYLOAD_MARKER)
        .unwrap()
        .as_object_mut()
        .unwrap()
        .insert("ciphertext".to_string(), Value::String("BAUG".to_string()));
    assert_eq!(
        validate_client_payload_value(
            &tampered,
            ClientPayloadValidationContext {
                collection_id: "docs",
                point_id: "point-1",
                field_path: "body",
                expected_key_id: Some("tenant-a/client-rk-2026-04"),
                key_id_required: true,
                signature_verification: Some(ClientPayloadSignatureVerification {
                    expected_key_id: "tenant-a/client-signing-v1",
                    public_key: &public_key,
                }),
            },
        ),
        Err(PayloadEncryptionError::InvalidClientSignature),
    );
}

#[test]
fn client_payload_envelope_requires_signature_when_verifier_is_configured() {
    let envelope = client_envelope("point-1", "body");
    let public_key = [7u8; 32];

    assert_eq!(
        validate_client_payload_value(
            &envelope,
            ClientPayloadValidationContext {
                collection_id: "docs",
                point_id: "point-1",
                field_path: "body",
                expected_key_id: Some("tenant-a/client-rk-2026-04"),
                key_id_required: true,
                signature_verification: Some(ClientPayloadSignatureVerification {
                    expected_key_id: "tenant-a/client-signing-v1",
                    public_key: &public_key,
                }),
            },
        ),
        Err(PayloadEncryptionError::MissingClientSignature),
    );
}

#[test]
fn selected_body_field_is_encrypted_without_leaking_plaintext() {
    let encryptor = encryptor();
    let policy = PayloadEncryptionPolicy::new(["body"]).unwrap();
    let mut payload = object(json!({
        "body": "classified body text",
        "title": "public title"
    }));

    assert_eq!(
        encryptor
            .encrypt_selected_fields("point-1", &mut payload, &policy)
            .unwrap(),
        1,
    );

    let body = payload.get("body").unwrap();
    assert!(is_encrypted_payload_value(body));

    let serialized = serde_json::to_string(&payload).unwrap();
    assert!(serialized.contains(ENCRYPTED_PAYLOAD_MARKER));
    assert!(serialized.contains("\"schema_version\":1"));
    assert!(serialized.contains("\"encryption_epoch\":0"));
    assert!(serialized.contains("\"material_fingerprint\""));
    assert!(!serialized.contains("classified body text"));
    assert!(serialized.contains("public title"));

    assert_eq!(
        encryptor
            .decrypt_selected_fields("point-1", &mut payload, &policy)
            .unwrap(),
        1,
    );
    assert_eq!(payload.get("body"), Some(&json!("classified body text")));
}

#[test]
fn payload_decrypt_rejects_wrong_encryption_epoch() {
    let base_encryptor = encryptor();
    let next_epoch_encryptor = encryptor().with_encryption_epoch(1);
    let policy = PayloadEncryptionPolicy::new(["body"]).unwrap();
    let mut payload = object(json!({ "body": "epoch scoped" }));

    base_encryptor
        .encrypt_selected_fields("point-1", &mut payload, &policy)
        .unwrap();

    assert_eq!(
        next_epoch_encryptor.decrypt_selected_fields("point-1", &mut payload, &policy),
        Err(PayloadEncryptionError::EncryptionEpochMismatch),
    );
}

#[test]
fn payload_outer_metadata_tampering_fails_authentication() {
    let encryptor = encryptor();
    let policy = PayloadEncryptionPolicy::new(["body"]).unwrap();
    let mut payload = object(json!({ "body": "epoch scoped" }));

    encryptor
        .encrypt_selected_fields("point-1", &mut payload, &policy)
        .unwrap();

    payload
        .get_mut("body")
        .unwrap()
        .as_object_mut()
        .unwrap()
        .get_mut(ENCRYPTED_PAYLOAD_MARKER)
        .unwrap()
        .as_object_mut()
        .unwrap()
        .insert("schema_version".to_string(), json!(2));
    assert_eq!(
        encryptor.decrypt_selected_fields("point-1", &mut payload, &policy),
        Err(PayloadEncryptionError::Crypto(EncryptionError::OpenFailed)),
    );

    payload
        .get_mut("body")
        .unwrap()
        .as_object_mut()
        .unwrap()
        .get_mut(ENCRYPTED_PAYLOAD_MARKER)
        .unwrap()
        .as_object_mut()
        .unwrap()
        .insert("schema_version".to_string(), json!(1));
    payload
        .get_mut("body")
        .unwrap()
        .as_object_mut()
        .unwrap()
        .get_mut(ENCRYPTED_PAYLOAD_MARKER)
        .unwrap()
        .as_object_mut()
        .unwrap()
        .insert("encryption_epoch".to_string(), json!(1));
    assert_eq!(
        encryptor.decrypt_selected_fields("point-1", &mut payload, &policy),
        Err(PayloadEncryptionError::Crypto(EncryptionError::OpenFailed)),
    );

    payload
        .get_mut("body")
        .unwrap()
        .as_object_mut()
        .unwrap()
        .get_mut(ENCRYPTED_PAYLOAD_MARKER)
        .unwrap()
        .as_object_mut()
        .unwrap()
        .insert("encryption_epoch".to_string(), json!(0));
    payload
        .get_mut("body")
        .unwrap()
        .as_object_mut()
        .unwrap()
        .get_mut(ENCRYPTED_PAYLOAD_MARKER)
        .unwrap()
        .as_object_mut()
        .unwrap()
        .get_mut("envelope")
        .unwrap()
        .as_object_mut()
        .unwrap()
        .insert("material_fingerprint".to_string(), json!(""));
    assert_eq!(
        encryptor.decrypt_selected_fields("point-1", &mut payload, &policy),
        Err(PayloadEncryptionError::Crypto(EncryptionError::OpenFailed)),
    );
}

#[test]
fn payload_decrypt_accepts_retired_key_but_new_writes_use_active_key() {
    let policy = PayloadEncryptionPolicy::new(["body"]).unwrap();
    let old_cipher =
        AeadCipher::new("tenant-a:payload-old", SecretKey::from_bytes([11u8; 32])).unwrap();
    let old_encryptor = PayloadTextEncryptor::new("docs", old_cipher).unwrap();
    let mut old_payload = object(json!({ "body": "rotation protected" }));

    old_encryptor
        .encrypt_selected_fields("point-1", &mut old_payload, &policy)
        .unwrap();

    let keyring = AeadKeyring::new(
        AeadCipher::new("tenant-a:payload-new", SecretKey::from_bytes([12u8; 32])).unwrap(),
    )
    .with_retired(
        AeadCipher::new("tenant-a:payload-old", SecretKey::from_bytes([11u8; 32])).unwrap(),
    );
    let rotated_encryptor = PayloadTextEncryptor::new_with_keyring("docs", keyring).unwrap();

    assert_eq!(
        rotated_encryptor
            .decrypt_selected_fields("point-1", &mut old_payload, &policy)
            .unwrap(),
        1,
    );
    assert_eq!(old_payload.get("body"), Some(&json!("rotation protected")));

    let mut new_payload = object(json!({ "body": "active key only" }));
    rotated_encryptor
        .encrypt_selected_fields("point-2", &mut new_payload, &policy)
        .unwrap();
    let serialized = serde_json::to_string(&new_payload).unwrap();

    assert!(serialized.contains("tenant-a:payload-new"));
    assert!(!serialized.contains("tenant-a:payload-old"));
}

#[test]
fn encrypted_payload_is_bound_to_point_and_field_path() {
    let encryptor = encryptor();
    let body_policy = PayloadEncryptionPolicy::new(["body"]).unwrap();
    let summary_policy = PayloadEncryptionPolicy::new(["summary"]).unwrap();
    let mut payload = object(json!({ "body": "copy protection" }));

    encryptor
        .encrypt_selected_fields("point-1", &mut payload, &body_policy)
        .unwrap();
    assert_eq!(
        encryptor.decrypt_selected_fields("point-2", &mut payload, &body_policy),
        Err(PayloadEncryptionError::Crypto(EncryptionError::OpenFailed)),
    );

    let encrypted_body = payload.remove("body").unwrap();
    payload.insert("summary".to_string(), encrypted_body);
    assert_eq!(
        encryptor.decrypt_selected_fields("point-1", &mut payload, &summary_policy),
        Err(PayloadEncryptionError::Crypto(EncryptionError::OpenFailed)),
    );
}

#[test]
fn encrypting_already_encrypted_payload_is_idempotent() {
    let encryptor = encryptor();
    let policy = PayloadEncryptionPolicy::new(["body"]).unwrap();
    let mut payload = object(json!({ "body": "one encryption only" }));

    assert_eq!(
        encryptor
            .encrypt_selected_fields("point-1", &mut payload, &policy)
            .unwrap(),
        1,
    );
    let once = serde_json::to_string(&payload).unwrap();
    assert_eq!(
        encryptor
            .encrypt_selected_fields("point-1", &mut payload, &policy)
            .unwrap(),
        0,
    );
    assert_eq!(serde_json::to_string(&payload).unwrap(), once);
}

#[test]
fn existing_payload_mode_can_fail_or_reencrypt_stale_envelopes() {
    let old_encryptor = encryptor();
    let new_encryptor = encryptor().with_encryption_epoch(1);
    let policy = PayloadEncryptionPolicy::new(["body"]).unwrap();
    let mut payload = object(json!({ "body": "rotate this" }));

    old_encryptor
        .encrypt_selected_fields("point-1", &mut payload, &policy)
        .unwrap();
    let mut fail_payload = payload.clone();
    assert_eq!(
        new_encryptor.encrypt_selected_fields_with_mode(
            "point-1",
            &mut fail_payload,
            &policy,
            ExistingPayloadMode::FailIfExisting,
        ),
        Err(PayloadEncryptionError::AlreadyEncrypted("body".to_string())),
    );

    assert_eq!(
        new_encryptor
            .encrypt_selected_fields_with_mode(
                "point-1",
                &mut payload,
                &policy,
                ExistingPayloadMode::ReencryptIfStale,
            )
            .unwrap(),
        1,
    );
    let serialized = serde_json::to_string(&payload).unwrap();
    assert!(serialized.contains("\"encryption_epoch\":1"));
    assert!(!serialized.contains("rotate this"));

    assert_eq!(
        new_encryptor
            .decrypt_selected_fields("point-1", &mut payload, &policy)
            .unwrap(),
        1,
    );
    assert_eq!(payload.get("body"), Some(&json!("rotate this")));
}

#[test]
fn malformed_marker_does_not_bypass_encryption() {
    let encryptor = encryptor();
    let policy = PayloadEncryptionPolicy::new(["body"]).unwrap();
    let mut payload = object(json!({
        "body": {
            "$qdrant_ckks": {
                "kind": "payload_text"
            },
            "plaintext": "secret body"
        }
    }));

    assert!(!is_encrypted_payload_value(payload.get("body").unwrap()));
    assert_eq!(
        encryptor.encrypt_selected_fields("point-1", &mut payload, &policy),
        Err(PayloadEncryptionError::MalformedEnvelope(
            "body".to_string()
        )),
    );

    let serialized = serde_json::to_string(&payload).unwrap();
    assert!(serialized.contains("secret body"));
}

#[test]
fn nested_payload_paths_are_supported() {
    let encryptor = encryptor();
    let policy = PayloadEncryptionPolicy::new(["document.body"]).unwrap();
    let mut payload = object(json!({
        "document": {
            "body": "nested secret",
            "author": "analyst"
        }
    }));

    encryptor
        .encrypt_selected_fields("point-1", &mut payload, &policy)
        .unwrap();
    let serialized = serde_json::to_string(&payload).unwrap();
    assert!(!serialized.contains("nested secret"));

    encryptor
        .decrypt_selected_fields("point-1", &mut payload, &policy)
        .unwrap();
    assert_eq!(payload["document"]["body"], json!("nested secret"));
    assert_eq!(payload["document"]["author"], json!("analyst"));
}

#[test]
fn strict_missing_fields_and_non_strings_fail_closed() {
    let encryptor = encryptor();
    let strict = PayloadEncryptionPolicy::new(["body"])
        .unwrap()
        .with_strict_missing_fields(true);
    let mut missing_payload = Map::new();

    assert_eq!(
        encryptor.encrypt_selected_fields("point-1", &mut missing_payload, &strict),
        Err(PayloadEncryptionError::MissingField("body".to_string())),
    );

    let policy = PayloadEncryptionPolicy::new(["body"]).unwrap();
    let mut numeric_payload = object(json!({ "body": 7 }));
    assert_eq!(
        encryptor.encrypt_selected_fields("point-1", &mut numeric_payload, &policy),
        Err(PayloadEncryptionError::ExpectedString {
            field: "body".to_string(),
            found: "number",
        }),
    );
}

#[test]
fn malformed_or_plaintext_values_do_not_decrypt() {
    let encryptor = encryptor();
    let policy = PayloadEncryptionPolicy::new(["body"]).unwrap();
    let mut plaintext_payload = object(json!({ "body": "not encrypted" }));

    assert_eq!(
        encryptor.decrypt_selected_fields("point-1", &mut plaintext_payload, &policy),
        Err(PayloadEncryptionError::ExpectedEncryptedEnvelope {
            field: "body".to_string(),
            found: "string",
        }),
    );

    let mut malformed_payload = object(json!({
        "body": {
            "$qdrant_ckks": {
                "kind": "payload_text"
            }
        }
    }));
    assert_eq!(
        encryptor.decrypt_selected_fields("point-1", &mut malformed_payload, &policy),
        Err(PayloadEncryptionError::MalformedEnvelope(
            "body".to_string()
        )),
    );
}

#[test]
fn invalid_policies_are_rejected() {
    assert_eq!(
        PayloadEncryptionPolicy::new(Vec::<String>::new()),
        Err(PayloadEncryptionError::EmptyPolicy),
    );
    assert_eq!(
        PayloadEncryptionPolicy::new([".body"]),
        Err(PayloadEncryptionError::InvalidFieldPath(
            ".body".to_string()
        )),
    );
    assert_eq!(
        PayloadEncryptionPolicy::new(["body..text"]),
        Err(PayloadEncryptionError::InvalidFieldPath(
            "body..text".to_string()
        )),
    );
    assert_eq!(
        PayloadEncryptionPolicy::new([format!("{ENCRYPTED_PAYLOAD_MARKER}.body")]),
        Err(PayloadEncryptionError::InvalidFieldPath(format!(
            "{ENCRYPTED_PAYLOAD_MARKER}.body"
        ))),
    );
    assert_eq!(
        PayloadEncryptionPolicy::new([format!("{CLIENT_ENCRYPTED_PAYLOAD_MARKER}.body")]),
        Err(PayloadEncryptionError::InvalidFieldPath(format!(
            "{CLIENT_ENCRYPTED_PAYLOAD_MARKER}.body"
        ))),
    );
    assert_eq!(
        PayloadEncryptionPolicy::new(["$qdrant_ciphertext.body"]),
        Err(PayloadEncryptionError::InvalidFieldPath(
            "$qdrant_ciphertext.body".to_string()
        )),
    );
    assert_eq!(
        PayloadEncryptionPolicy::new(["items[].name"]),
        Err(PayloadEncryptionError::InvalidFieldPath(
            "items[].name".to_string()
        )),
    );
    assert_eq!(
        PayloadEncryptionPolicy::new(["items.*.name"]),
        Err(PayloadEncryptionError::InvalidFieldPath(
            "items.*.name".to_string()
        )),
    );
    assert_eq!(
        PayloadEncryptionPolicy::new(["items.0.name"]),
        Err(PayloadEncryptionError::InvalidFieldPath(
            "items.0.name".to_string()
        )),
    );
}

proptest! {
    #[test]
    fn arbitrary_utf8_body_round_trips(body in "\\PC{0,512}") {
        let encryptor = encryptor();
        let policy = PayloadEncryptionPolicy::new(["body"]).unwrap();
        let mut payload = object(json!({ "body": body.clone() }));

        encryptor.encrypt_selected_fields("property-point", &mut payload, &policy).unwrap();
        encryptor.decrypt_selected_fields("property-point", &mut payload, &policy).unwrap();
        prop_assert_eq!(payload.get("body"), Some(&json!(body)));
    }
}
