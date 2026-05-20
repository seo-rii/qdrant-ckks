use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct InferenceConfig {
    pub address: Option<String>,
    pub timeout: Option<u64>,
    pub token: Option<String>,
    #[serde(default)]
    pub allowed_api_key_headers: Vec<String>,
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
