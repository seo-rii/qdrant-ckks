use std::sync::Arc;
use std::time::Duration;

use common::defaults::APP_USER_AGENT;
use common::types::{DetailsLevel, TelemetryDetail};
use reqwest::{Client, StatusCode};
use segment::common::anonymize::Anonymize;
use storage::content_manager::errors::StorageResult;
use storage::rbac::{Access, Auth, AuthType};
use tokio::sync::Mutex;

use super::telemetry::TelemetryCollector;

const DETAIL: TelemetryDetail = TelemetryDetail {
    level: DetailsLevel::Level2,
    histograms: false,
    per_collection: false,
};
const REPORTING_INTERVAL: Duration = Duration::from_secs(60 * 60); // One hour

pub struct TelemetryReporter {
    telemetry_url: String,
    telemetry: Arc<Mutex<TelemetryCollector>>,
}

fn full_reporter_auth() -> Auth {
    Auth::new(
        Access::full("Telemetry reporter"),
        None,
        None,
        AuthType::Internal,
        None,
    )
}

fn telemetry_failure_log_message(status: StatusCode, content_length: Option<u64>) -> String {
    match content_length {
        Some(content_length) => {
            format!(
                "Failed to report telemetry: resp status:{status:?} resp body omitted (content_length:{content_length})"
            )
        }
        None => format!(
            "Failed to report telemetry: resp status:{status:?} resp body omitted (content_length:unknown)"
        ),
    }
}

impl TelemetryReporter {
    fn new(telemetry: Arc<Mutex<TelemetryCollector>>) -> Self {
        let telemetry_url = if cfg!(debug_assertions) {
            "https://staging-telemetry.qdrant.io".to_string()
        } else {
            "https://telemetry.qdrant.io".to_string()
        };

        Self {
            telemetry_url,
            telemetry,
        }
    }

    async fn report(&self, client: &Client) -> StorageResult<()> {
        let data = self
            .telemetry
            .lock()
            .await
            .prepare_data(&full_reporter_auth(), DETAIL, None, None)
            .await?
            .anonymize();
        let data = serde_json::to_string(&data)?;
        let resp = client
            .post(&self.telemetry_url)
            .body(data)
            .header("Content-Type", "application/json")
            .send()
            .await?;
        if !resp.status().is_success() {
            log::error!(
                "{}",
                telemetry_failure_log_message(resp.status(), resp.content_length())
            );
        }
        Ok(())
    }

    pub async fn run(telemetry: Arc<Mutex<TelemetryCollector>>) {
        let reporter = Self::new(telemetry);
        let client = match Client::builder()
            .user_agent(APP_USER_AGENT.as_str())
            .build()
        {
            Ok(client) => client,
            Err(err) => {
                log::error!("Failed to build telemetry HTTP client: {err}");
                return;
            }
        };
        loop {
            if let Err(err) = reporter.report(&client).await {
                log::error!("Failed to report telemetry {err}")
            }
            tokio::time::sleep(REPORTING_INTERVAL).await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn telemetry_failure_log_message_omits_response_body() {
        let response_body = "$qdrant_client_aead ciphertext signature wrapped_key_b64";
        let log_message = telemetry_failure_log_message(
            StatusCode::BAD_GATEWAY,
            Some(response_body.len() as u64),
        );

        assert!(log_message.contains("502"));
        assert!(log_message.contains("body omitted"));
        assert!(log_message.contains("content_length"));
        assert!(!log_message.contains(response_body));
        assert!(!log_message.contains("$qdrant_client_aead"));
        assert!(!log_message.contains("wrapped_key_b64"));
    }
}
