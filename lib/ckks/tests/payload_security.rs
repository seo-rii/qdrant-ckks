use proptest::prelude::*;
use qdrant_ckks::{
    AeadCipher, ENCRYPTED_PAYLOAD_MARKER, EncryptionError, PayloadEncryptionError,
    PayloadEncryptionPolicy, PayloadTextEncryptor, SecretKey, is_encrypted_payload_value,
};
use serde_json::{Map, Value, json};

fn encryptor() -> PayloadTextEncryptor {
    let cipher = AeadCipher::new("tenant-a:payload", SecretKey::from_bytes([11u8; 32])).unwrap();
    PayloadTextEncryptor::new("docs", cipher).unwrap()
}

fn object(value: Value) -> Map<String, Value> {
    match value {
        Value::Object(object) => object,
        _ => unreachable!("test fixture must be a JSON object"),
    }
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
