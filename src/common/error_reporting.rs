use std::time::Duration;

use common::defaults::APP_USER_AGENT;
use serde_json::json;

pub struct ErrorReporter;

impl ErrorReporter {
    fn get_url() -> String {
        if cfg!(debug_assertions) {
            "https://staging-telemetry.qdrant.io".to_string()
        } else {
            "https://telemetry.qdrant.io".to_string()
        }
    }

    /// Build serialized JSON payload for telemetry error reporting.
    fn build_report_payload(error: &str, reporting_id: &str, backtrace: Option<&str>) -> String {
        let error = redact_crypto_material_for_report(error);
        let backtrace = backtrace.map(redact_crypto_material_for_report);
        let report = json!({
            "id": reporting_id,
            "error": error,
            "backtrace": backtrace.as_deref(),
        });
        report.to_string()
    }

    pub fn report(error: &str, reporting_id: &str, backtrace: Option<&str>) {
        let client = match reqwest::blocking::Client::builder()
            .user_agent(APP_USER_AGENT.as_str())
            .build()
        {
            Ok(client) => client,
            Err(err) => {
                log::warn!("Failed to build telemetry reporter client: {err}");
                return;
            }
        };

        let data = Self::build_report_payload(error, reporting_id, backtrace);

        if let Err(err) = client
            .post(Self::get_url())
            .body(data)
            .header("Content-Type", "application/json")
            .timeout(Duration::from_secs(1))
            .send()
        {
            log::debug!("Telemetry panic report was not sent: {err}");
        }
    }
}

fn redact_crypto_material_for_report(value: &str) -> String {
    let compact = value
        .chars()
        .filter(|character| character.is_ascii_alphanumeric())
        .flat_map(char::to_lowercase)
        .collect::<String>();
    let contains_crypto_material = [
        "qdrantsec",
        "qdrantclientaead",
        "qdrantsecvectors",
        "ciphertext",
        "encryptedquery",
        "wrappedkey",
        "valueb64",
        "nonceb64",
        "signatureb64",
        "privatekey",
        "secretkey",
        "vaulttoken",
        "xapikey",
    ]
    .iter()
    .any(|needle| compact.contains(needle));

    if contains_crypto_material {
        "[redacted: crypto material omitted from telemetry report]".to_string()
    } else {
        value.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::ErrorReporter;

    #[test]
    /// Ensure panic report payload contains the expected fields.
    fn test_build_report_payload_with_backtrace() {
        let payload = ErrorReporter::build_report_payload("panic", "node-1", Some("bt-line"));

        assert!(payload.contains("\"id\":\"node-1\""));
        assert!(payload.contains("\"error\":\"panic\""));
        assert!(payload.contains("\"backtrace\":\"bt-line\""));
    }

    #[test]
    /// Missing backtrace must serialize as null.
    fn test_build_report_payload_without_backtrace() {
        let payload = ErrorReporter::build_report_payload("panic", "node-2", None);

        assert!(payload.contains("\"id\":\"node-2\""));
        assert!(payload.contains("\"error\":\"panic\""));
        assert!(payload.contains("\"backtrace\":null"));
    }

    #[test]
    fn test_build_report_payload_redacts_crypto_material() {
        let payload = ErrorReporter::build_report_payload(
            r#"panic while handling {"$qdrant_sec":{"envelope":{"nonce":"nonce-sentinel","ciphertext":"ciphertext-sentinel"}}}"#,
            "node-3",
            Some("frame with wrappedKeyB64=wrapped-sentinel and x-vault-token=token"),
        );

        assert!(payload.contains("crypto material omitted"));
        assert!(!payload.contains("$qdrant_sec"));
        assert!(!payload.contains("nonce-sentinel"));
        assert!(!payload.contains("ciphertext-sentinel"));
        assert!(!payload.contains("wrapped-sentinel"));
        assert!(!payload.contains("x-vault-token"));
    }
}
