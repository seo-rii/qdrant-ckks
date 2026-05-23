use std::fmt;

use serde::{Deserialize, Serialize};

#[derive(Clone, Serialize, Deserialize, Default)]
pub struct InferenceConfig {
    pub address: Option<String>,
    pub timeout: Option<u64>,
    pub token: Option<String>,
    #[serde(default)]
    pub allowed_api_key_headers: Vec<String>,
}

impl fmt::Debug for InferenceConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("InferenceConfig")
            .field("address", &self.address)
            .field("timeout", &self.timeout)
            .field("token", &self.token.as_ref().map(|_| "[redacted]"))
            .field("allowed_api_key_headers", &self.allowed_api_key_headers)
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
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inference_config_debug_redacts_token() {
        let config = InferenceConfig {
            address: Some("http://inference.local".to_string()),
            timeout: Some(10),
            token: Some("qdrant-sec-inference-config-token-sentinel".to_string()),
            allowed_api_key_headers: vec!["openai-api-key".to_string()],
        };

        let rendered = format!("{config:?}");

        assert!(rendered.contains("http://inference.local"), "{rendered}");
        assert!(rendered.contains("openai-api-key"), "{rendered}");
        assert!(rendered.contains("[redacted]"), "{rendered}");
        assert!(
            !rendered.contains("qdrant-sec-inference-config-token-sentinel"),
            "{rendered}",
        );
    }
}
