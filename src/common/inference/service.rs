use std::fmt::{self, Display};
use std::hash::Hash;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use actix_web::http::header::HttpDate;
use api::rest::models::InferenceUsage;
use api::rest::{Document, Image, InferenceObject};
use collection::operations::point_ops::VectorPersisted;
use common::defaults::APP_USER_AGENT;
use itertools::{Either, Itertools};
use parking_lot::RwLock;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use storage::content_manager::errors::StorageError;

pub use super::inference_input::InferenceInput;
use super::local_model;
use crate::common::inference::api_keys::{InferenceApiKeys, convert_to_reqwest_headers};
use crate::common::inference::config::InferenceConfig;
use crate::common::inference::params::InferenceParams;

#[derive(Debug, Serialize, Default, Clone, Copy)]
#[serde(rename_all = "lowercase")]
pub enum InferenceType {
    #[default]
    Update,
    Search,
}

impl Display for InferenceType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", format!("{self:?}").to_lowercase())
    }
}

#[derive(Serialize)]
pub struct InferenceRequest {
    pub(crate) inputs: Vec<InferenceInput>,
    pub(crate) inference: Option<InferenceType>,
    #[serde(default)]
    pub(crate) token: Option<String>,
}

impl fmt::Debug for InferenceRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("InferenceRequest")
            .field("input_count", &self.inputs.len())
            .field("inference", &self.inference)
            .field("token", &self.token.as_ref().map(|_| "[redacted]"))
            .finish()
    }
}

#[derive(Deserialize)]
#[cfg_attr(test, derive(Serialize))]
pub struct InferenceResponse {
    pub embeddings: Vec<VectorPersisted>,
    pub usage: Option<InferenceUsage>,
}

impl fmt::Debug for InferenceResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("InferenceResponse")
            .field("embedding_count", &self.embeddings.len())
            .field("usage", &self.usage)
            .finish()
    }
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Hash)]
pub enum InferenceData {
    Document(Document),
    Image(Image),
    Object(InferenceObject),
}

#[derive(Debug, Deserialize)]
struct InferenceError {
    pub error: String,
}

impl fmt::Debug for InferenceData {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("InferenceData")
            .field("type", &self.type_name())
            .field("data", &"[redacted]")
            .finish()
    }
}

impl InferenceData {
    pub(crate) fn type_name(&self) -> &'static str {
        match self {
            InferenceData::Document(_) => "document",
            InferenceData::Image(_) => "image",
            InferenceData::Object(_) => "object",
        }
    }
}

pub struct InferenceService {
    pub(crate) config: InferenceConfig,
    pub(crate) client: Client,
}

static INFERENCE_SERVICE: RwLock<Option<Arc<InferenceService>>> = RwLock::new(None);

/// We assume that the inference provider will handle timeouts itself, if
/// not provided by the user or configured. But we need ensurance, that we don't
/// wait forever for a response.
static DEFAULT_INFERENCE_TIMEOUT_SECS: u64 = 10 * 60; // 10 minutes

impl InferenceService {
    pub fn new(config: Option<InferenceConfig>) -> Result<Self, StorageError> {
        let config = config.unwrap_or_default();
        let InferenceConfig {
            address: _,
            timeout,
            token: _,
            allowed_api_key_headers: _,
            expected_host: _,
        } = &config;

        let timeout = timeout.unwrap_or(DEFAULT_INFERENCE_TIMEOUT_SECS);
        let client_builder = Client::builder()
            .user_agent(APP_USER_AGENT.as_str())
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(timeout));

        let client = client_builder.build().map_err(|err| {
            StorageError::service_error(format!("failed to build inference HTTP client: {err}"))
        })?;

        Ok(Self { config, client })
    }

    pub fn init_global(config: Option<InferenceConfig>) -> Result<(), StorageError> {
        let mut inference_service = INFERENCE_SERVICE.write();

        let service = Self::new(config)?;
        service.validate()?;

        *inference_service = Some(Arc::new(service));
        Ok(())
    }

    pub fn get_global() -> Option<Arc<InferenceService>> {
        INFERENCE_SERVICE.read().as_ref().cloned()
    }

    pub(crate) fn validate(&self) -> Result<(), StorageError> {
        let Some(address) = self.config.address.as_deref() else {
            // BM25 local inference does not require a remote address.
            return Ok(());
        };

        if address.is_empty() {
            return Err(StorageError::service_error(
                "InferenceService configuration error: address is empty",
            ));
        }

        let parsed = reqwest::Url::parse(address).map_err(|_| {
            StorageError::service_error(
                "InferenceService configuration error: address must be a valid http(s) URL",
            )
        })?;
        if parsed.scheme() != "http" && parsed.scheme() != "https" {
            return Err(StorageError::service_error(
                "InferenceService configuration error: address must use http or https",
            ));
        }
        if parsed.scheme() == "http" && !is_loopback_http_url(&parsed) {
            return Err(StorageError::service_error(
                "InferenceService configuration error: address must use https except loopback http for local development",
            ));
        }
        if !parsed.username().is_empty() || parsed.password().is_some() {
            return Err(StorageError::service_error(
                "InferenceService configuration error: address must not include credentials",
            ));
        }
        if parsed.query().is_some() || parsed.fragment().is_some() {
            return Err(StorageError::service_error(
                "InferenceService configuration error: address must not include query parameters or fragments",
            ));
        }
        validate_expected_inference_host(&parsed, self.config.expected_host.as_deref())?;
        Ok(())
    }

    pub async fn infer(
        &self,
        inference_inputs: Vec<InferenceInput>,
        inference_type: InferenceType,
        inference_params: InferenceParams,
    ) -> Result<InferenceResponse, StorageError> {
        let (
            (local_inference_inputs, local_inference_positions),
            (remote_inference_inputs, remote_inference_positions),
        ): ((Vec<_>, Vec<_>), (Vec<_>, Vec<_>)) = inference_inputs
            .into_iter()
            // Keep track of the input's positions so we can properly merge them together later.
            .enumerate()
            .partition_map(|(pos, input)| {
                // Check if input is targeting a local model or the configured remote server.
                if local_model::is_local_model(&input.model) {
                    Either::Left((input, pos))
                } else {
                    Either::Right((input, pos))
                }
            });

        // Run inference on local models
        let local_model_results = local_model::infer_local(local_inference_inputs, inference_type)?;

        // Early return with the local model's results if no other inference_inputs were passed.
        // If local models is also empty, we automatically return an empty response here.
        if remote_inference_inputs.is_empty() {
            return Ok(InferenceResponse {
                embeddings: local_model_results,
                usage: None, // No usage since everything was processed locally.
            });
        }

        let remote_result = self
            .infer_remote(remote_inference_inputs, inference_type, inference_params)
            .await?;

        Self::merge_local_and_remote_result(
            local_model_results,
            local_inference_positions,
            remote_result,
            remote_inference_positions,
        )
    }

    async fn infer_remote(
        &self,
        inference_inputs: Vec<InferenceInput>,
        inference_type: InferenceType,
        inference_params: InferenceParams,
    ) -> Result<InferenceResponse, StorageError> {
        self.validate()?;

        // Assume that either:
        // - User doesn't have access to generating random JWT tokens (like in serverless)
        // - Inference server checks validity of the tokens.

        let InferenceParams { api_keys, timeout } = inference_params;
        let InferenceApiKeys {
            keys: mut ext_api_keys,
            token: inference_token,
        } = api_keys;

        let token = inference_token.or_else(|| self.config.token.clone());

        let Some(url) = self.config.address.as_ref() else {
            return Err(StorageError::service_error(
                "InferenceService URL not configured - please provide valid address in config",
            ));
        };

        let request_body = InferenceRequest {
            inputs: inference_inputs,
            inference: Some(inference_type),
            token,
        };

        let request = self.client.post(url);
        let request = if let Some(timeout) = timeout {
            request.timeout(timeout)
        } else {
            request
        };

        let mut request = request.json(&request_body);
        if !ext_api_keys.is_empty() {
            ext_api_keys.retain(|key, _| {
                self.config
                    .allowed_api_key_headers
                    .iter()
                    .any(|allowed| allowed.eq_ignore_ascii_case(key))
            });
        }

        if !ext_api_keys.is_empty() {
            request = request.headers(convert_to_reqwest_headers(&ext_api_keys));
        }

        let response = request.send().await;

        let (response_body, status, retry_after) = match response {
            Ok(response) => {
                let status = response.status();
                let retry_after = Self::parse_retry_after(response.headers());
                match response.text().await {
                    Ok(body) => (body, status, retry_after),
                    Err(err) => {
                        return Err(StorageError::service_error(format!(
                            "Failed to read inference response body: {err}"
                        )));
                    }
                }
            }
            Err(error) => {
                let status = error.status();
                let error = error.without_url();
                if let Some(status) = status {
                    (error.to_string(), status, None)
                } else {
                    return Err(StorageError::service_error(format!(
                        "Failed to send inference request: {error}"
                    )));
                }
            }
        };

        Self::handle_inference_response(status, &response_body, retry_after)
    }

    fn merge_local_and_remote_result(
        local_results: Vec<VectorPersisted>,
        local_pos: Vec<usize>,
        remote_res: InferenceResponse,
        remote_pos: Vec<usize>,
    ) -> Result<InferenceResponse, StorageError> {
        if local_results.len() != local_pos.len() || remote_res.embeddings.len() != remote_pos.len()
        {
            return Err(StorageError::service_error(
                "InferenceService internal error: inference result count mismatch",
            ));
        }

        // Skip merging with local results if we only have inference results from remote.
        if local_results.is_empty() {
            return Ok(remote_res);
        }

        // Merge remote results and local results together in the exact same order they have been passed.
        let merged = merge_position_items(
            local_results,
            local_pos,
            remote_res.embeddings,
            remote_pos,
        )
        .ok_or_else(|| {
            StorageError::service_error(
                "InferenceService internal error: inference result positions are not contiguous",
            )
        })?;

        Ok(InferenceResponse {
            embeddings: merged,
            usage: remote_res.usage, // Only account for usage of remote.
        })
    }

    fn parse_retry_after(headers: &reqwest::header::HeaderMap) -> Option<Duration> {
        headers
            .get(reqwest::header::RETRY_AFTER)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| {
                // Check if the value is a valid duration in seconds
                if let Ok(seconds) = value.parse::<u64>() {
                    return Some(Duration::from_secs(seconds));
                }

                // Check if the value is a valid Date
                if let Ok(http_date) = value.parse::<HttpDate>() {
                    let ts = SystemTime::from(http_date);
                    return ts
                        .duration_since(SystemTime::now())
                        .ok()
                        .map(|d| d.max(Duration::ZERO));
                }

                None
            })
    }

    pub(crate) fn handle_inference_response(
        status: reqwest::StatusCode,
        response_body: &str,
        retry_after: Option<Duration>,
    ) -> Result<InferenceResponse, StorageError> {
        match status {
            reqwest::StatusCode::OK => serde_json::from_str(response_body).map_err(|e| {
                StorageError::service_error(format!(
                    "Failed to parse successful inference response: {e}. Response body redacted",
                ))
            }),
            reqwest::StatusCode::BAD_REQUEST => {
                // Provider errors can echo request text, image payloads, or auth context.
                // Treat response bodies as untrusted sensitive data and keep them out of user/log errors.
                let parsed_body: Result<InferenceError, _> = serde_json::from_str(response_body);
                match parsed_body {
                    Ok(InferenceError { error: _ }) => Err(StorageError::bad_request(format!(
                        "Inference request validation failed ({status}); provider response body redacted",
                    ))),
                    Err(_) => Err(StorageError::bad_request(format!(
                        "Invalid inference request ({status}); provider response body redacted",
                    ))),
                }
            }
            status @ (reqwest::StatusCode::UNAUTHORIZED | reqwest::StatusCode::FORBIDDEN) => {
                Err(StorageError::service_error(format!(
                    "Authentication failed for inference service ({status}); provider response body redacted",
                )))
            }
            status @ reqwest::StatusCode::TOO_MANY_REQUESTS => {
                Err(StorageError::rate_limit_exceeded(
                    format!(
                        "Too many requests for inference service ({status}); provider response body redacted",
                    ),
                    retry_after,
                ))
            }
            status @ (reqwest::StatusCode::INTERNAL_SERVER_ERROR
            | reqwest::StatusCode::SERVICE_UNAVAILABLE
            | reqwest::StatusCode::GATEWAY_TIMEOUT) => Err(StorageError::service_error(format!(
                "Inference service error ({status}); provider response body redacted",
            ))),
            _ => {
                if status.is_server_error() {
                    Err(StorageError::service_error(format!(
                        "Inference service error ({status}); provider response body redacted",
                    )))
                } else if status.is_client_error() {
                    Err(StorageError::bad_request(format!(
                        "Inference can't process request ({status}); provider response body redacted",
                    )))
                } else {
                    Err(StorageError::service_error(format!(
                        "Unexpected inference error ({status}); provider response body redacted",
                    )))
                }
            }
        }
    }
}

fn is_loopback_http_url(parsed: &reqwest::Url) -> bool {
    parsed.scheme() == "http"
        && parsed.host_str().is_some_and(|host| {
            host.eq_ignore_ascii_case("localhost")
                || host == "127.0.0.1"
                || host == "::1"
                || host == "[::1]"
        })
}

fn is_loopback_inference_url(parsed: &reqwest::Url) -> bool {
    is_loopback_http_url(parsed)
        || parsed.host_str().is_some_and(|host| {
            host.eq_ignore_ascii_case("localhost")
                || host == "127.0.0.1"
                || host == "::1"
                || host == "[::1]"
        })
}

fn inference_url_authority(parsed: &reqwest::Url) -> Option<String> {
    let host = parsed.host_str()?;
    Some(match parsed.port() {
        Some(port) => format!("{host}:{port}"),
        None => host.to_string(),
    })
}

fn is_valid_expected_inference_host(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 253
        && !value.contains("://")
        && !value.contains('/')
        && !value.contains('?')
        && !value.contains('#')
        && !value
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace())
}

fn validate_expected_inference_host(
    parsed: &reqwest::Url,
    expected_host: Option<&str>,
) -> Result<(), StorageError> {
    if expected_host.is_some_and(|host| !is_valid_expected_inference_host(host)) {
        return Err(StorageError::service_error(
            "InferenceService configuration error: expected_host is invalid",
        ));
    }

    if is_loopback_inference_url(parsed) && expected_host.is_none() {
        return Ok(());
    }

    let Some(expected_host) = expected_host else {
        return Err(StorageError::service_error(
            "InferenceService configuration error: expected_host is required for non-loopback endpoints",
        ));
    };

    let Some(actual_host) = inference_url_authority(parsed) else {
        return Err(StorageError::service_error(
            "InferenceService configuration error: address must include a host",
        ));
    };

    if !actual_host.eq_ignore_ascii_case(expected_host) {
        return Err(StorageError::service_error(
            "InferenceService configuration error: address host does not match expected_host",
        ));
    }

    Ok(())
}

/// 2-way merge of lists with `PositionItems`. Also checks for skipped items and returns `None` in case an item is left out.
fn merge_position_items<I>(
    left: impl IntoIterator<Item = I>,
    left_pos: Vec<usize>,
    right: impl IntoIterator<Item = I>,
    right_pos: Vec<usize>,
) -> Option<Vec<I>> {
    let left_iter = left.into_iter().zip(left_pos);
    let right_iter = right.into_iter().zip(right_pos);

    let mut i = 0; // Check that we cover all items and don't skip any.
    left_iter
        .merge_by(right_iter, |l: &(I, usize), r: &(I, usize)| l.1 < r.1)
        .map(|item| {
            if item.1 == i {
                i += 1;
                Some(item.0)
            } else {
                None
            }
        })
        .collect::<Option<Vec<_>>>()
}

#[cfg(test)]
mod test {
    use std::collections::HashMap;

    use api::rest::{Bm25Config, Document};
    use mockito::Matcher;
    use rand::rngs::StdRng;
    use rand::seq::SliceRandom;
    use rand::{RngExt, SeedableRng};
    use serde_json::{Value, json};

    use super::*;
    use crate::common::inference::api_keys::InferenceApiKeys;
    use crate::common::inference::bm25::Bm25;
    use crate::common::inference::inference_input::InferenceDataType;

    const BM25_LOCAL_MODEL_NAME: &str = "bm25";

    #[test]
    fn test_merge_position_items() {
        let (left, right): ((Vec<_>, Vec<_>), (Vec<_>, Vec<_>)) =
            (0..1000).map(|i| (i, i)).partition(|i| i.0 % 7 == 0);
        let merged = merge_position_items(left.0, left.1, right.0, right.1);
        assert_eq!(merged, Some((0..1000).collect::<Vec<_>>()));
    }

    #[test]
    fn test_merge_position_items_fail() {
        let (left, mut right): ((Vec<_>, Vec<_>), (Vec<_>, Vec<_>)) =
            (0..1000).map(|i| (i, i)).partition(|i| i.0 % 7 == 0);

        right.0.remove(5);
        right.1.remove(5);

        let merged = merge_position_items(left.0, left.1, right.0, right.1);

        // We were missing an item and therefore expect `None`.
        assert_eq!(merged, None);
    }

    #[test]
    fn inference_merge_rejects_result_count_mismatch() {
        let err = InferenceService::merge_local_and_remote_result(
            vec![VectorPersisted::Dense(vec![1.0])],
            vec![0],
            InferenceResponse {
                embeddings: Vec::new(),
                usage: None,
            },
            vec![1],
        )
        .expect_err("remote result count mismatch must fail closed");

        assert!(
            err.to_string().contains("inference result count mismatch"),
            "{err}",
        );
    }

    #[test]
    fn inference_merge_rejects_non_contiguous_positions() {
        let err = InferenceService::merge_local_and_remote_result(
            vec![VectorPersisted::Dense(vec![1.0])],
            vec![0],
            InferenceResponse {
                embeddings: vec![VectorPersisted::Dense(vec![2.0])],
                usage: None,
            },
            vec![2],
        )
        .expect_err("non-contiguous result positions must fail closed");

        assert!(
            err.to_string()
                .contains("inference result positions are not contiguous"),
            "{err}",
        );
    }

    #[test]
    fn debug_redacts_inference_request_inputs_and_token() {
        let request = InferenceRequest {
            inputs: vec![InferenceInput {
                data: Value::String("remote-inference-plaintext-sentinel".to_string()),
                data_type: InferenceDataType::Text,
                model: "model-v1".to_string(),
                options: None,
            }],
            inference: Some(InferenceType::Search),
            token: Some("remote-inference-token-sentinel".to_string()),
        };

        let rendered = format!("{request:?}");

        assert!(!rendered.contains("remote-inference-plaintext-sentinel"));
        assert!(!rendered.contains("remote-inference-token-sentinel"));
        assert!(rendered.contains("input_count: 1"), "{rendered}");
        assert!(rendered.contains("[redacted]"), "{rendered}");
    }

    #[test]
    fn debug_redacts_inference_data_payload() {
        let data = InferenceData::Document(Document {
            text: "inference-data-plaintext-sentinel".to_string(),
            model: "model-v1".to_string(),
            options: None,
        });

        let rendered = format!("{data:?}");

        assert!(!rendered.contains("inference-data-plaintext-sentinel"));
        assert!(rendered.contains("document"), "{rendered}");
        assert!(rendered.contains("[redacted]"), "{rendered}");
    }

    #[test]
    fn debug_redacts_inference_response_embeddings() {
        let response = InferenceResponse {
            embeddings: vec![VectorPersisted::Dense(vec![0.123456, 0.234567, 0.345678])],
            usage: None,
        };

        let rendered = format!("{response:?}");

        assert!(rendered.contains("embedding_count: 1"), "{rendered}");
        assert!(!rendered.contains("0.123456"), "{rendered}");
        assert!(!rendered.contains("0.234567"), "{rendered}");
        assert!(!rendered.contains("0.345678"), "{rendered}");
    }

    #[test]
    fn inference_service_rejects_unsafe_endpoint_urls_without_echoing_secrets() {
        for (address, expected_host) in [
            ("ftp://inference.local/v1", Some("inference.local")),
            ("http://inference.local/v1", Some("inference.local")),
            ("https://inference.local/v1", None),
            ("https://wrong.inference.local/v1", Some("inference.local")),
            (
                "https://user:password@inference.local/v1",
                Some("inference.local"),
            ),
            (
                "https://inference.local/v1?token=qdrant-sec-inference-url-token",
                Some("inference.local"),
            ),
            (
                "https://inference.local/v1#qdrant-sec-inference-url-fragment",
                Some("inference.local"),
            ),
            (
                "not a url qdrant-sec-inference-url-token",
                Some("inference.local"),
            ),
        ] {
            let service = InferenceService::new(Some(InferenceConfig {
                address: Some(address.to_string()),
                timeout: None,
                token: None,
                allowed_api_key_headers: Vec::new(),
                expected_host: expected_host.map(str::to_string),
            }))
            .unwrap();

            let err = service
                .validate()
                .expect_err("unsafe inference endpoint URL must fail validation");
            let rendered = err.to_string();

            assert!(rendered.contains("InferenceService configuration error"));
            assert!(!rendered.contains("user"), "{rendered}");
            assert!(!rendered.contains("password"), "{rendered}");
            assert!(
                !rendered.contains("qdrant-sec-inference-url-token"),
                "{rendered}"
            );
            assert!(
                !rendered.contains("qdrant-sec-inference-url-fragment"),
                "{rendered}"
            );
        }
    }

    #[test]
    fn inference_service_accepts_https_endpoint_path_without_query() {
        let service = InferenceService::new(Some(InferenceConfig {
            address: Some("https://inference.local/v1/embeddings".to_string()),
            timeout: None,
            token: None,
            allowed_api_key_headers: Vec::new(),
            expected_host: Some("inference.local".to_string()),
        }))
        .unwrap();

        service
            .validate()
            .expect("safe inference endpoint URL with path should be accepted");
    }

    #[test]
    fn inference_service_accepts_loopback_http_endpoint_for_local_development() {
        for address in [
            "http://127.0.0.1:6334/v1/embeddings",
            "http://localhost:6334/v1/embeddings",
            "http://[::1]:6334/v1/embeddings",
        ] {
            let service = InferenceService::new(Some(InferenceConfig {
                address: Some(address.to_string()),
                timeout: None,
                token: None,
                allowed_api_key_headers: Vec::new(),
                expected_host: None,
            }))
            .unwrap();

            service
                .validate()
                .expect("loopback http inference endpoint should be accepted");
        }
    }

    #[test]
    fn remote_inference_error_redacts_provider_response_body() {
        for (status, body) in [
            (
                reqwest::StatusCode::OK,
                "successful-response-plaintext-sentinel",
            ),
            (
                reqwest::StatusCode::BAD_REQUEST,
                r#"{"error":"bad-request-plaintext-sentinel"}"#,
            ),
            (
                reqwest::StatusCode::FORBIDDEN,
                "forbidden-token-plaintext-sentinel",
            ),
            (
                reqwest::StatusCode::INTERNAL_SERVER_ERROR,
                "server-error-plaintext-sentinel",
            ),
        ] {
            let err = InferenceService::handle_inference_response(status, body, None)
                .expect_err("test response must fail");
            let rendered = err.to_string();

            assert!(
                !rendered.contains("plaintext-sentinel"),
                "status {status} leaked provider body: {rendered}",
            );
            assert!(
                rendered.contains("redacted"),
                "status {status} did not explain redaction: {rendered}",
            );
        }
    }

    #[tokio::test]
    async fn test_bm25_end_to_end() {
        let mut rng = StdRng::seed_from_u64(42);

        // Test without any BM25
        let only_inference_inputs: Vec<_> = (0..rng.random_range(30..100))
            .map(|_| make_normal_inference_input("this is some input", &mut rng))
            .collect();
        let res = run_inference_with_mocked_remote(only_inference_inputs.clone()).await;
        check_inference_response(only_inference_inputs, res);

        // Test with only BM25
        let only_bm25_inputs: Vec<_> = (0..rng.random_range(30..100))
            .map(|_| make_bm25_inference_input("this is some input"))
            .collect();
        let res = run_inference_with_mocked_remote(only_bm25_inputs.clone()).await;
        check_inference_response(only_bm25_inputs, res);

        // Test BM25 and inference mixed.
        let mut inputs: Vec<InferenceInput> = vec![];
        inputs.extend(
            (0..rng.random_range(30..100)).map(|_| make_bm25_inference_input("this is some input")),
        );
        inputs.extend(
            (0..rng.random_range(30..100))
                .map(|_| make_normal_inference_input("this is some input", &mut rng)),
        );
        inputs.shuffle(&mut rng);
        let res = run_inference_with_mocked_remote(inputs.clone()).await;
        check_inference_response(inputs, res);
    }

    #[tokio::test]
    async fn remote_inference_does_not_follow_redirects() {
        let mut redirect_target = mockito::Server::new_async().await;
        let target_mock = redirect_target
            .mock("POST", "/")
            .with_status(200)
            .with_body(
                json!(InferenceResponse {
                    embeddings: vec![VectorPersisted::Dense(vec![1.0])],
                    usage: None,
                })
                .to_string(),
            )
            .create_async()
            .await;

        let mut redirect_source = mockito::Server::new_async().await;
        let source_mock = redirect_source
            .mock("POST", "/")
            .match_header("openai-api-key", "secret-provider-key")
            .with_status(307)
            .with_header("location", &redirect_target.url())
            .with_body("redirecting")
            .create_async()
            .await;

        let service = InferenceService::new(Some(InferenceConfig {
            address: Some(redirect_source.url()),
            timeout: None,
            token: Some("inference-token".to_string()),
            allowed_api_key_headers: vec!["openai-api-key".to_string()],
            expected_host: None,
        }))
        .unwrap();

        let mut api_keys = InferenceApiKeys::new(None);
        api_keys.keys.insert(
            "openai-api-key".to_string(),
            "secret-provider-key".to_string(),
        );

        let err = service
            .infer(
                vec![make_normal_inference_input(
                    "sensitive remote inference input",
                    &mut StdRng::seed_from_u64(7),
                )],
                InferenceType::Update,
                InferenceParams::new(api_keys, None),
            )
            .await
            .expect_err("redirect response must not be followed");

        let err = err.to_string();
        assert!(
            err.contains("307") || err.contains("Temporary Redirect"),
            "unexpected redirect error: {err}",
        );
        source_mock.expect(1).assert_async().await;
        target_mock.expect(0).assert_async().await;
    }

    #[tokio::test]
    async fn remote_inference_send_error_redacts_request_url() {
        let service = InferenceService::new(Some(InferenceConfig {
            address: Some("http://127.0.0.1:1/infer".to_string()),
            timeout: None,
            token: None,
            allowed_api_key_headers: Vec::new(),
            expected_host: None,
        }))
        .unwrap();

        let err = service
            .infer_remote(
                vec![make_normal_inference_input(
                    "sensitive remote inference input",
                    &mut StdRng::seed_from_u64(17),
                )],
                InferenceType::Update,
                InferenceParams::new(InferenceApiKeys::default(), Some(Duration::from_secs(1))),
            )
            .await
            .expect_err("unreachable local inference endpoint must fail");
        let rendered = err.to_string();

        assert!(
            rendered.contains("Failed to send inference request"),
            "{rendered}"
        );
        assert!(!rendered.contains("infer?token"), "{rendered}");
    }

    #[tokio::test]
    async fn remote_inference_validates_config_before_send() {
        let service = InferenceService::new(Some(InferenceConfig {
            address: Some(
                "https://inference.local/infer?token=qdrant-sec-inference-preflight-token"
                    .to_string(),
            ),
            timeout: None,
            token: None,
            allowed_api_key_headers: Vec::new(),
            expected_host: Some("inference.local".to_string()),
        }))
        .unwrap();

        let err = service
            .infer_remote(
                vec![make_normal_inference_input(
                    "sensitive remote inference input",
                    &mut StdRng::seed_from_u64(18),
                )],
                InferenceType::Update,
                InferenceParams::new(InferenceApiKeys::default(), Some(Duration::from_secs(1))),
            )
            .await
            .expect_err("invalid configured URL must fail before request send");
        let rendered = err.to_string();

        assert!(rendered.contains("InferenceService configuration error"));
        assert!(
            !rendered.contains("qdrant-sec-inference-preflight-token"),
            "{rendered}"
        );
    }

    #[tokio::test]
    async fn remote_inference_does_not_forward_unallowed_api_key_headers() {
        let mut server = mockito::Server::new_async().await;
        let mock = server
            .mock("POST", "/")
            .match_header("openai-api-key", Matcher::Missing)
            .match_header("cohere-api-key", "forwarded-provider-key")
            .with_status(200)
            .with_body(
                json!(InferenceResponse {
                    embeddings: vec![VectorPersisted::Dense(vec![1.0])],
                    usage: None,
                })
                .to_string(),
            )
            .create_async()
            .await;

        let service = InferenceService::new(Some(InferenceConfig {
            address: Some(server.url()),
            timeout: None,
            token: None,
            allowed_api_key_headers: vec!["cohere-api-key".to_string()],
            expected_host: None,
        }))
        .unwrap();

        let mut api_keys = InferenceApiKeys::new(None);
        api_keys
            .keys
            .insert("openai-api-key".to_string(), "must-not-forward".to_string());
        api_keys.keys.insert(
            "cohere-api-key".to_string(),
            "forwarded-provider-key".to_string(),
        );

        service
            .infer(
                vec![make_normal_inference_input(
                    "sensitive remote inference input",
                    &mut StdRng::seed_from_u64(8),
                )],
                InferenceType::Update,
                InferenceParams::new(api_keys, None),
            )
            .await
            .expect("allowed provider key should still support remote inference");

        mock.expect(1).assert_async().await;
    }

    fn make_normal_inference_input(input: &str, rand: &mut StdRng) -> InferenceInput {
        let options = if rand.random_bool(0.3) {
            let mut opts = HashMap::default();
            let value = rand.random_iter::<char>().take(10).collect::<String>(); // Test utf8
            opts.insert("some-key".to_string(), Value::String(value));
            Some(opts)
        } else {
            None
        };

        InferenceInput {
            data: Value::String(input.to_string()),
            data_type: InferenceDataType::Text,
            model: "anyModel".to_string(),
            options,
        }
    }

    fn make_bm25_inference_input(input: &str) -> InferenceInput {
        let bm25_config = Bm25Config::default();

        let options: HashMap<String, Value> =
            serde_json::from_str(&serde_json::to_string(&bm25_config).unwrap()).unwrap();

        InferenceInput {
            data: Value::String(input.to_string()),
            data_type: InferenceDataType::Text,
            model: BM25_LOCAL_MODEL_NAME.to_string(),
            options: Some(options),
        }
    }

    fn check_inference_response(inputs: Vec<InferenceInput>, response: InferenceResponse) {
        assert_eq!(inputs.len(), response.embeddings.len());

        for (idx, (input, response)) in inputs.into_iter().zip(response.embeddings).enumerate() {
            if input.model == BM25_LOCAL_MODEL_NAME {
                // In our test-setup, only BM25 returns sparse vectors. Normal inference is mocked
                // and always returns dense vectors.
                assert!(matches!(response, VectorPersisted::Sparse(..)));
                let bm25_config = InferenceInput::parse_bm25_config(input.options).unwrap();

                // Re-run bm25 and check that response is correct.
                let bm25 = Bm25::new(bm25_config).doc_embed(input.data.as_str().unwrap());
                assert_eq!(response, bm25);
            } else {
                let expected_vector = VectorPersisted::Dense(vec![0.0; idx]);
                assert_eq!(response, expected_vector);
            }
        }
    }

    async fn run_inference_with_mocked_remote(
        inference_inputs: Vec<InferenceInput>,
    ) -> InferenceResponse {
        // Request a new server from the pool
        let mut server = mockito::Server::new_async().await;

        // Create dummy dense vectors for non-bm25 inputs with the length of the index.
        // The dummy dense vector have the dimension of the position they appeared in `inference_inputs`,
        // so we can easily check for correct ordering later, although it is a bit hacky.
        let expected_embeddings: Vec<_> = inference_inputs
            .iter()
            .enumerate()
            .filter(|(_, item)| item.model != BM25_LOCAL_MODEL_NAME)
            .map(|(index, _)| {
                let values = vec![0.0; index];
                VectorPersisted::Dense(values)
            })
            .collect();

        // Create an HTTP mock
        let mock = server
            .mock("POST", "/")
            .with_status(200)
            .with_header("content-type", "text/json")
            .with_body(
                json!(InferenceResponse {
                    embeddings: expected_embeddings,
                    usage: None,
                })
                .to_string(),
            )
            .create_async()
            .await;

        let config = InferenceConfig {
            address: Some(server.url()), // Use mock's URL as address when doing inference.
            timeout: None,
            token: Some(String::default()),
            allowed_api_key_headers: Vec::new(),
            expected_host: None,
        };

        let service = InferenceService::new(Some(config)).unwrap();

        let has_remote_inference_items = inference_inputs
            .iter()
            .any(|i| i.model != BM25_LOCAL_MODEL_NAME);

        let res = service
            .infer(
                inference_inputs,
                InferenceType::Update,
                InferenceParams::new(InferenceApiKeys::new(Some("key".to_string())), None),
            )
            .await
            .expect("Failed to do inference");

        // We expect exactly 1 request if there is any inference (non-bm25) request
        // and 0 if all inputs are bm25.
        if has_remote_inference_items {
            mock.expect(1).assert_async().await;
        } else {
            mock.expect(0).assert_async().await;
        }

        res
    }
}
