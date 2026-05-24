use std::fmt;

use serde::{Deserialize, Serialize};

#[derive(Clone, Serialize, Deserialize, Default)]
pub struct InferenceConfig {
    pub address: Option<String>,
    pub timeout: Option<u64>,
    pub token: Option<String>,
    #[serde(default)]
    pub allowed_api_key_headers: Vec<String>,
    #[serde(default)]
    pub expected_host: Option<String>,
}

impl fmt::Debug for InferenceConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let address = self.address.as_deref().map(|address| {
            let Ok(mut redacted) = reqwest::Url::parse(address) else {
                return "[invalid-url]".to_string();
            };
            let _ = redacted.set_username("");
            let _ = redacted.set_password(None);
            redacted.set_query(redacted.query().map(|_| "[redacted]"));
            redacted.set_fragment(redacted.fragment().map(|_| "[redacted]"));
            redacted.to_string()
        });

        f.debug_struct("InferenceConfig")
            .field("address", &address)
            .field("timeout", &self.timeout)
            .field("token", &self.token.as_ref().map(|_| "[redacted]"))
            .field("allowed_api_key_headers", &self.allowed_api_key_headers)
            .field("expected_host", &self.expected_host)
            .finish()
    }
}

impl InferenceConfig {
    pub fn new(address: Option<String>) -> Self {
        Self {
            address,
            timeout: None,
            token: None,
            allowed_api_key_headers: Vec::new(),
            expected_host: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inference_config_debug_redacts_token() {
        let config = InferenceConfig {
            address: Some(
                "https://inference-user:inference-password@inference.local/v1?token=qdrant-sec-inference-query-token#qdrant-sec-inference-fragment"
                    .to_string(),
            ),
            timeout: Some(10),
            token: Some("qdrant-sec-inference-config-token-sentinel".to_string()),
            allowed_api_key_headers: vec!["openai-api-key".to_string()],
            expected_host: Some("inference.local".to_string()),
        };

        let rendered = format!("{config:?}");

        assert!(rendered.contains("inference.local"), "{rendered}");
        assert!(rendered.contains("openai-api-key"), "{rendered}");
        assert!(rendered.contains("expected_host"), "{rendered}");
        assert!(rendered.contains("inference.local"), "{rendered}");
        assert!(rendered.contains("[redacted]"), "{rendered}");
        assert!(!rendered.contains("inference-user"), "{rendered}");
        assert!(!rendered.contains("inference-password"), "{rendered}");
        assert!(
            !rendered.contains("qdrant-sec-inference-query-token"),
            "{rendered}",
        );
        assert!(
            !rendered.contains("qdrant-sec-inference-fragment"),
            "{rendered}",
        );
        assert!(
            !rendered.contains("qdrant-sec-inference-config-token-sentinel"),
            "{rendered}",
        );
    }
}
