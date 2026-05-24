use std::collections::HashMap;
use std::fmt;

use api::rest::{Bm25Config, Document, DocumentOptions, Image, InferenceObject};
use serde::de::IntoDeserializer;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use storage::content_manager::errors::StorageError;

use super::service::InferenceData;

#[derive(Serialize, Clone)]
pub struct InferenceInput {
    pub data: Value,
    pub data_type: InferenceDataType,
    pub model: String,
    pub options: Option<HashMap<String, Value>>,
}

impl fmt::Debug for InferenceInput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("InferenceInput")
            .field("data", &"[redacted]")
            .field("data_type", &self.data_type)
            .field("model", &self.model)
            .field("options_present", &self.options.is_some())
            .finish()
    }
}

impl InferenceInput {
    /// Attempts to parse the input's options into a local model config.
    pub fn parse_bm25_config(
        options: Option<HashMap<String, Value>>,
    ) -> Result<Bm25Config, StorageError> {
        let options = options.unwrap_or_default();
        Bm25Config::deserialize(options.into_deserializer())
            .map_err(|_| StorageError::bad_input("Invalid BM25 config"))
    }
}

#[derive(Debug, Serialize, Clone)]
#[serde(rename_all = "snake_case")]
pub enum InferenceDataType {
    Text,
    Image,
    Object,
}

impl From<InferenceData> for InferenceInput {
    fn from(value: InferenceData) -> Self {
        match value {
            InferenceData::Document(doc) => {
                let Document {
                    text,
                    model,
                    options,
                } = doc;
                InferenceInput {
                    data: Value::String(text),
                    data_type: InferenceDataType::Text,
                    model,
                    options: options.map(DocumentOptions::into_options),
                }
            }
            InferenceData::Image(img) => {
                let Image {
                    image,
                    model,
                    options,
                } = img;
                InferenceInput {
                    data: image,
                    data_type: InferenceDataType::Image,
                    model,
                    options: options.options,
                }
            }
            InferenceData::Object(obj) => {
                let InferenceObject {
                    object,
                    model,
                    options,
                } = obj;
                InferenceInput {
                    data: object,
                    data_type: InferenceDataType::Object,
                    model,
                    options: options.options,
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use serde_json::json;

    use super::*;

    #[test]
    fn bm25_config_parse_error_does_not_echo_option_values() {
        let sentinel = "do-not-echo-bm25-option-secret";
        let err = InferenceInput::parse_bm25_config(Some(HashMap::from([(
            "k".to_string(),
            json!(sentinel),
        )])))
        .expect_err("invalid BM25 config must fail");
        let rendered = err.to_string();

        assert!(rendered.contains("Invalid BM25 config"), "{rendered}");
        assert!(!rendered.contains(sentinel), "{rendered}");
    }
}
