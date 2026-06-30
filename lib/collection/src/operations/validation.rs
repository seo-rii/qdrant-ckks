use actix_web_validator::error::flatten_errors;
use serde_json::Value;
use validator::{ValidationError, ValidationErrors};

/// Warn about validation errors in the log.
///
/// Validation errors are pretty printed field-by-field.
pub fn warn_validation_errors(description: &str, errs: &ValidationErrors) {
    log::warn!("{description} has validation errors:");
    describe_errors(errs)
        .into_iter()
        .for_each(|(key, msg)| log::warn!("- {key}: {msg}"));
}

/// Label the given validation errors in a single string.
pub fn label_errors(label: impl AsRef<str>, errs: &ValidationErrors) -> String {
    format!(
        "{}: [{}]",
        label.as_ref(),
        describe_errors(errs)
            .into_iter()
            .map(|(field, err)| format!("{field}: {err}"))
            .collect::<Vec<_>>()
            .join("; ")
    )
}

/// Describe the given validation errors.
///
/// Returns a list of error messages for fields: `(field, message)`
fn describe_errors(errs: &ValidationErrors) -> Vec<(String, String)> {
    flatten_errors(errs)
        .into_iter()
        .map(|(_, name, err)| (name, describe_error(err)))
        .collect()
}

/// Describe a specific validation error.
fn describe_error(
    err @ ValidationError {
        code,
        message,
        params,
    }: &ValidationError,
) -> String {
    // Prefer to return message if set
    if let Some(message) = message {
        return message.to_string();
    } else if let Some(Value::String(message)) = params.get("message") {
        return message.clone();
    }

    // Generate messages based on codes
    match code.as_ref() {
        "duplicate_private_result_oram_binding" => {
            "private result ORAM supports one configured binding in v1".to_string()
        }
        "private_hnsw_oram_single_vector_selector" => {
            "private HNSW ORAM supports exactly one vector per rule in v1".to_string()
        }
        "private_hnsw_oram_safe_vector_store_name" => {
            "private HNSW ORAM vector names must be safe non-client-state store path components"
                .to_string()
        }
        "private_result_oram_requires_payload_selector" => {
            "private result ORAM bindings must use payload_paths selectors".to_string()
        }
        "private_hnsw_oram_requires_vector_selector" => {
            "private HNSW ORAM bindings must use vector_names selectors".to_string()
        }
        "private_result_oram_overlapping_selector" => {
            "private result ORAM payload selector overlaps another encryption selector".to_string()
        }
        "private_hnsw_oram_overlapping_selector" => {
            "private HNSW ORAM vector selector overlaps another encryption selector".to_string()
        }
        "unsupported_vector_encryption_binding"
            if params
                .get("value")
                .is_some_and(|value| value.to_string().contains("private-result-oram/v1")) =>
        {
            "private result ORAM bindings must use payload_paths selectors".to_string()
        }
        "unsupported_payload_encryption_binding"
            if params
                .get("value")
                .is_some_and(|value| value.to_string().contains("private-hnsw-oram/v1")) =>
        {
            "private HNSW ORAM bindings must use vector_names selectors".to_string()
        }
        "overlapping_encryption_selector"
            if params
                .get("value")
                .is_some_and(|value| value.to_string().contains("private-result-oram/v1")) =>
        {
            "private result ORAM payload selector overlaps another encryption selector".to_string()
        }
        "overlapping_encryption_selector"
            if params
                .get("value")
                .is_some_and(|value| value.to_string().contains("private-hnsw-oram/v1")) =>
        {
            "private HNSW ORAM vector selector overlaps another encryption selector".to_string()
        }
        "range" => {
            let msg = match (params.get("min"), params.get("max")) {
                (Some(min), None) => format!("must be {min} or larger"),
                (Some(min), Some(max)) => format!("must be from {min} to {max}"),
                (None, Some(max)) => format!("must be {max} or smaller"),
                // Should be unreachable
                _ => err.to_string(),
            };
            match params.get("value") {
                Some(value) => format!("value {value} invalid, {msg}"),
                None => msg,
            }
        }
        "length" => {
            let msg = match (params.get("equal"), params.get("min"), params.get("max")) {
                (Some(equal), _, _) => format!("must be exactly {equal} characters"),
                (None, Some(min), None) => format!("must be at least {min} characters"),
                (None, Some(min), Some(max)) => {
                    format!("must be from {min} to {max} characters")
                }
                (None, None, Some(max)) => format!("must be at most {max} characters"),
                // Should be unreachable
                _ => err.to_string(),
            };
            match params.get("value") {
                Some(value) => format!("value {value} invalid, {msg}"),
                None => msg,
            }
        }
        "must_not_match" => {
            match (
                params.get("value"),
                params.get("other_field"),
                params.get("other_value"),
            ) {
                (Some(value), Some(other_field), Some(other_value)) => {
                    format!("value {value} must not match {other_value} in {other_field}")
                }
                (Some(value), Some(other_field), None) => {
                    format!("value {value} must not match value in {other_field}")
                }
                (None, Some(other_field), Some(other_value)) => {
                    format!("must not match {other_value} in {other_field}")
                }
                (None, Some(other_field), None) => {
                    format!("must not match value in {other_field}")
                }
                // Should be unreachable
                _ => err.to_string(),
            }
        }
        "does_not_contain" => match params.get("pattern") {
            Some(pattern) => format!("cannot contain {pattern}"),
            None => err.to_string(),
        },
        "not_empty" => "value invalid, must not be empty".to_string(),
        "closed_line" => {
            "value invalid, the first and the last points should be same to form a closed line"
                .to_string()
        }
        "min_line_length" => match (params.get("min_length"), params.get("length")) {
            (Some(min_length), Some(length)) => {
                format!("value invalid, the size must be at least {min_length}, got {length}")
            }
            _ => err.to_string(),
        },
        // Undescribed error codes
        _ => err.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use api::grpc::qdrant::{GeoLineString, GeoPoint, GeoPolygon};
    use validator::Validate;

    use super::*;

    #[derive(Validate, Debug)]
    struct SomeThing {
        #[validate(range(min = 1))]
        pub idx: usize,
    }

    #[derive(Validate, Debug)]
    struct OtherThing {
        #[validate(nested)]
        pub things: Vec<SomeThing>,
    }

    fn build_polygon(
        exterior_points: Vec<(f64, f64)>,
        interiors_points: Vec<Vec<(f64, f64)>>,
    ) -> GeoPolygon {
        let exterior_line = GeoLineString {
            points: exterior_points
                .into_iter()
                .map(|(lon, lat)| GeoPoint { lon, lat })
                .collect(),
        };

        let interior_lines = interiors_points
            .into_iter()
            .map(|points| GeoLineString {
                points: points
                    .into_iter()
                    .map(|(lon, lat)| GeoPoint { lon, lat })
                    .collect(),
            })
            .collect();

        GeoPolygon {
            exterior: Some(exterior_line),
            interiors: interior_lines,
        }
    }

    #[test]
    fn test_validation() {
        let bad_config = OtherThing {
            things: vec![SomeThing { idx: 0 }],
        };
        assert!(
            bad_config.validate().is_err(),
            "validation of bad config should fail"
        );
    }

    #[test]
    fn test_config_validation_render() {
        let bad_config = OtherThing {
            things: vec![
                SomeThing { idx: 0 },
                SomeThing { idx: 1 },
                SomeThing { idx: 2 },
            ],
        };

        let errors = bad_config
            .validate()
            .expect_err("validation of bad config should fail");

        assert_eq!(
            describe_errors(&errors),
            vec![(
                "things[0].idx".into(),
                "value 0 invalid, must be 1 or larger".into()
            )]
        );
    }

    #[test]
    fn test_polygon_validation_render() {
        let test_cases = vec![
            (
                build_polygon(vec![], vec![]),
                vec![("exterior".into(), "value invalid, must not be empty".into())],
            ),
            (
                build_polygon(vec![(1., 1.),(2., 2.),(1., 1.)], vec![]),
                vec![("exterior".into(), "value invalid, the size must be at least 4, got 3".into())],
            ),
            (
                build_polygon(vec![(1., 1.),(2., 2.),(3., 3.),(4., 4.)], vec![]),
                vec![(
                    "exterior".into(),
                    "value invalid, the first and the last points should be same to form a closed line".into(),
                )],
            ),
            (
                build_polygon(
                    vec![(1., 1.),(2., 2.),(3., 3.),(1., 1.)],
                    vec![vec![(1., 1.),(2., 2.),(1., 1.)]],
                ),
                vec![("interiors".into(), "value invalid, the size must be at least 4, got 3".into())],
            ),
            (
                build_polygon(
                    vec![(1., 1.),(2., 2.),(3., 3.),(1., 1.)],
                    vec![vec![(1., 1.),(2., 2.),(3., 3.),(4., 4.)]],
                ),
                vec![(
                    "interiors".into(),
                    "value invalid, the first and the last points should be same to form a closed line".into(),
                )],
            ),
        ];

        for (polygon, expected_errors) in test_cases {
            let errors = polygon
                .validate()
                .expect_err("validation of bad polygon should fail");

            assert_eq!(describe_errors(&errors), expected_errors);
        }
    }

    #[test]
    fn describe_error_redacts_private_result_oram_selector_values() {
        assert_eq!(
            describe_error(&ValidationError::new(
                "private_result_oram_requires_payload_selector"
            )),
            "private result ORAM bindings must use payload_paths selectors",
        );
        assert_eq!(
            describe_error(&ValidationError::new(
                "private_result_oram_overlapping_selector"
            )),
            "private result ORAM payload selector overlaps another encryption selector",
        );

        let mut duplicate = ValidationError::new("duplicate_private_result_oram_binding");
        duplicate.add_param(
            std::borrow::Cow::from("value"),
            &serde_json::json!([
                {
                    "id": "body_private_result",
                    "selector": { "paths": ["body.secret"] },
                    "binding": "private-result-oram/v1",
                },
                {
                    "id": "summary_private_result",
                    "selector": { "paths": ["summary.secret"] },
                    "binding": "private-result-oram/v1",
                },
            ]),
        );
        let duplicate_message = describe_error(&duplicate);
        assert!(duplicate_message.contains("private result ORAM supports one configured binding"));
        assert!(!duplicate_message.contains("body.secret"));
        assert!(!duplicate_message.contains("summary.secret"));
        assert!(!duplicate_message.contains("body_private_result"));

        let mut overlap = ValidationError::new("overlapping_encryption_selector");
        overlap.add_param(
            std::borrow::Cow::from("value"),
            &serde_json::json!([
                {
                    "id": "body_private_result",
                    "selector": { "paths": ["body.secret"] },
                    "binding": "private-result-oram/v1",
                },
                {
                    "id": "body_client_payload",
                    "selector": { "paths": ["body.secret"] },
                    "binding": "client-payload/v1",
                },
            ]),
        );
        let overlap_message = describe_error(&overlap);
        assert!(overlap_message.contains("private result ORAM payload selector overlaps"));
        assert!(!overlap_message.contains("body.secret"));
        assert!(!overlap_message.contains("body_private_result"));
        assert!(!overlap_message.contains("body_client_payload"));

        let mut wrong_selector = ValidationError::new("unsupported_vector_encryption_binding");
        wrong_selector.add_param(
            std::borrow::Cow::from("value"),
            &serde_json::json!([
                {
                    "id": "result_wrong_selector_rule",
                    "selector": { "names": ["result-secret-vector"] },
                    "binding": "private-result-oram/v1",
                },
            ]),
        );
        let wrong_selector_message = describe_error(&wrong_selector);
        assert!(wrong_selector_message.contains("must use payload_paths selectors"));
        assert!(!wrong_selector_message.contains("result_wrong_selector_rule"));
        assert!(!wrong_selector_message.contains("result-secret-vector"));
    }

    #[test]
    fn describe_error_redacts_private_hnsw_oram_selector_values() {
        assert_eq!(
            describe_error(&ValidationError::new(
                "private_hnsw_oram_requires_vector_selector"
            )),
            "private HNSW ORAM bindings must use vector_names selectors",
        );
        assert_eq!(
            describe_error(&ValidationError::new(
                "private_hnsw_oram_overlapping_selector"
            )),
            "private HNSW ORAM vector selector overlaps another encryption selector",
        );

        let mut multi_vector = ValidationError::new("private_hnsw_oram_single_vector_selector");
        multi_vector.add_param(
            std::borrow::Cow::from("value"),
            &serde_json::json!([
                {
                    "id": "embedding_private_hnsw",
                    "selector": { "names": ["embedding", "body-secret"] },
                    "binding": "private-hnsw-oram/v1",
                },
            ]),
        );
        let multi_vector_message = describe_error(&multi_vector);
        assert!(multi_vector_message.contains("private HNSW ORAM supports exactly one vector"));
        assert!(!multi_vector_message.contains("embedding_private_hnsw"));
        assert!(!multi_vector_message.contains("body-secret"));

        let mut unsafe_store_name =
            ValidationError::new("private_hnsw_oram_safe_vector_store_name");
        unsafe_store_name.add_param(
            std::borrow::Cow::from("value"),
            &serde_json::json!([
                {
                    "id": "stash_private_hnsw",
                    "selector": {
                        "names": [
                            "stash",
                            "clientStateBackups.json",
                            "clientStateCiphertext.json",
                            "clientStateCiphertextHash.json",
                            "clientStateCiphertextHashes.json",
                            "client_state_ciphertext.json",
                            "client_state_ciphertext_hash.json",
                            "client_state_ciphertext_hashes.json",
                            "encryptedClientStateBackups.json",
                            "encrypted_client_state.json",
                            "encrypted_client_state_backup.json",
                            "encrypted_client_state_snapshot.json",
                            "encryptedClientStateCiphertext.json",
                            "encrypted_client_state_ciphertext.json",
                            "encryptedClientStateCiphertextHash.json",
                            "encryptedClientStateCiphertextHashes.json",
                            "encrypted_client_state_ciphertext_hash.json",
                            "encrypted_client_state_ciphertext_hashes.json",
                            "oramPositionMapBackups.json",
                            "oram_position_map_backups.json",
                            "positionMapBackups.json",
                            "position_map_backups.json",
                            "stashBackups.json",
                            "stateCiphertext.json",
                            "stateCiphertextHash.json",
                            "stateCiphertextHashes.json",
                            "state_ciphertext.json",
                            "state_ciphertext_hash.json",
                            "state_ciphertext_hashes.json",
                            "tokenPositionMapBackups.json",
                            "token_position_map_backups.json"
                        ]
                    },
                    "binding": "private-hnsw-oram/v1",
                },
            ]),
        );
        let unsafe_store_name_message = describe_error(&unsafe_store_name);
        assert!(unsafe_store_name_message.contains("safe non-client-state store path"));
        assert!(!unsafe_store_name_message.contains("stash_private_hnsw"));
        assert!(!unsafe_store_name_message.contains("stash"));
        assert!(!unsafe_store_name_message.contains("clientStateBackups"));
        assert!(!unsafe_store_name_message.contains("clientStateCiphertext"));
        assert!(!unsafe_store_name_message.contains("clientStateCiphertextHash"));
        assert!(!unsafe_store_name_message.contains("clientStateCiphertextHashes"));
        assert!(!unsafe_store_name_message.contains("client_state_ciphertext"));
        assert!(!unsafe_store_name_message.contains("client_state_ciphertext_hash"));
        assert!(!unsafe_store_name_message.contains("client_state_ciphertext_hashes"));
        assert!(!unsafe_store_name_message.contains("encryptedClientStateBackups"));
        assert!(!unsafe_store_name_message.contains("encrypted_client_state"));
        assert!(!unsafe_store_name_message.contains("encrypted_client_state_backup"));
        assert!(!unsafe_store_name_message.contains("encrypted_client_state_snapshot"));
        assert!(!unsafe_store_name_message.contains("encryptedClientStateCiphertext"));
        assert!(!unsafe_store_name_message.contains("encrypted_client_state_ciphertext"));
        assert!(!unsafe_store_name_message.contains("encryptedClientStateCiphertextHash"));
        assert!(!unsafe_store_name_message.contains("encryptedClientStateCiphertextHashes"));
        assert!(!unsafe_store_name_message.contains("encrypted_client_state_ciphertext_hash"));
        assert!(!unsafe_store_name_message.contains("encrypted_client_state_ciphertext_hashes"));
        assert!(!unsafe_store_name_message.contains("oramPositionMapBackups"));
        assert!(!unsafe_store_name_message.contains("oram_position_map_backups"));
        assert!(!unsafe_store_name_message.contains("positionMapBackups"));
        assert!(!unsafe_store_name_message.contains("position_map_backups"));
        assert!(!unsafe_store_name_message.contains("stashBackups"));
        assert!(!unsafe_store_name_message.contains("stateCiphertext"));
        assert!(!unsafe_store_name_message.contains("stateCiphertextHash"));
        assert!(!unsafe_store_name_message.contains("stateCiphertextHashes"));
        assert!(!unsafe_store_name_message.contains("state_ciphertext"));
        assert!(!unsafe_store_name_message.contains("state_ciphertext_hash"));
        assert!(!unsafe_store_name_message.contains("state_ciphertext_hashes"));
        assert!(!unsafe_store_name_message.contains("tokenPositionMapBackups"));
        assert!(!unsafe_store_name_message.contains("token_position_map_backups"));

        let mut overlap = ValidationError::new("overlapping_encryption_selector");
        overlap.add_param(
            std::borrow::Cow::from("value"),
            &serde_json::json!([
                {
                    "id": "embedding_private_hnsw",
                    "selector": { "names": ["embedding"] },
                    "binding": "private-hnsw-oram/v1",
                },
                {
                    "id": "embedding_client_ckks",
                    "selector": { "names": ["embedding"] },
                    "binding": "vector-envelope/v1",
                },
            ]),
        );
        let overlap_message = describe_error(&overlap);
        assert!(overlap_message.contains("private HNSW ORAM vector selector overlaps"));
        assert!(!overlap_message.contains("embedding_private_hnsw"));
        assert!(!overlap_message.contains("embedding_client_ckks"));
        assert!(!overlap_message.contains("embedding"));

        let mut wrong_selector = ValidationError::new("unsupported_payload_encryption_binding");
        wrong_selector.add_param(
            std::borrow::Cow::from("value"),
            &serde_json::json!([
                {
                    "id": "hnsw_wrong_selector_rule",
                    "selector": { "paths": ["secret.payload"] },
                    "binding": "private-hnsw-oram/v1",
                },
            ]),
        );
        let wrong_selector_message = describe_error(&wrong_selector);
        assert!(wrong_selector_message.contains("must use vector_names selectors"));
        assert!(!wrong_selector_message.contains("hnsw_wrong_selector_rule"));
        assert!(!wrong_selector_message.contains("secret.payload"));
    }
}
