use std::task::{Context, Poll};

use futures_util::future::BoxFuture;
use tonic::Code;
use tonic::body::BoxBody;
use tonic::codegen::http::Response;
use tower::Service;
use tower_layer::Layer;

use crate::common::error_reporting::redact_crypto_material_for_report;

#[derive(Clone)]
pub struct LoggingMiddleware<T> {
    inner: T,
}

#[derive(Clone)]
pub struct LoggingMiddlewareLayer;

impl LoggingMiddlewareLayer {
    pub fn new() -> Self {
        Self
    }
}

fn redacted_grpc_status_message(status: &tonic::Status) -> String {
    redact_crypto_material_for_report(status.message())
}

impl<S> Service<tonic::codegen::http::Request<tonic::transport::Body>> for LoggingMiddleware<S>
where
    S: Service<tonic::codegen::http::Request<tonic::transport::Body>, Response = Response<BoxBody>>
        + Clone,
    S::Future: Send + 'static,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = BoxFuture<'static, Result<S::Response, S::Error>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(
        &mut self,
        request: tonic::codegen::http::Request<tonic::transport::Body>,
    ) -> Self::Future {
        let clone = self.inner.clone();
        let mut inner = std::mem::replace(&mut self.inner, clone);

        let method_name = request.uri().path().to_string();
        let instant = std::time::Instant::now();
        let future = inner.call(request);
        Box::pin(async move {
            let response = future.await;
            let elapsed_sec = instant.elapsed().as_secs_f32();
            match response {
                Err(error) => {
                    log::error!("gRPC request error {method_name}");
                    Err(error)
                }
                Ok(response_tonic) => {
                    let grpc_status = tonic::Status::from_header_map(response_tonic.headers());
                    if let Some(grpc_status) = grpc_status {
                        let redacted_message = redacted_grpc_status_message(&grpc_status);
                        match grpc_status.code() {
                            Code::Ok => {
                                log::trace!("gRPC {method_name} Ok {elapsed_sec:.6}");
                            }
                            Code::Cancelled => {
                                // cluster mode generates a large amount of `stream error received: stream no longer needed`
                                log::trace!("gRPC cancelled {method_name} {elapsed_sec:.6}");
                            }
                            Code::DeadlineExceeded
                            | Code::Aborted
                            | Code::OutOfRange
                            | Code::ResourceExhausted
                            | Code::NotFound
                            | Code::InvalidArgument
                            | Code::AlreadyExists
                            | Code::FailedPrecondition
                            | Code::PermissionDenied
                            | Code::Unauthenticated => {
                                log::info!(
                                    "gRPC {} failed with {} {:?} {:.6}",
                                    method_name,
                                    grpc_status.code(),
                                    redacted_message,
                                    elapsed_sec,
                                );
                            }
                            Code::Internal
                            | Code::Unimplemented
                            | Code::Unavailable
                            | Code::DataLoss
                            | Code::Unknown => log::error!(
                                "gRPC {} unexpectedly failed with {} {:?} {:.6}",
                                method_name,
                                grpc_status.code(),
                                redacted_message,
                                elapsed_sec,
                            ),
                        };
                    } else {
                        // Fallback to response's `status_code` if no `grpc-status` header found.
                        match response_tonic.status().as_u16() {
                            100..=199 => {
                                log::trace!(
                                    "gRPC information {} {} {:.6}",
                                    method_name,
                                    response_tonic.status(),
                                    elapsed_sec,
                                );
                            }
                            200..=299 => {
                                log::trace!(
                                    "gRPC success {} {} {:.6}",
                                    method_name,
                                    response_tonic.status(),
                                    elapsed_sec,
                                );
                            }
                            300..=399 => {
                                log::debug!(
                                    "gRPC redirection {} {} {:.6}",
                                    method_name,
                                    response_tonic.status(),
                                    elapsed_sec,
                                );
                            }
                            400..=499 => {
                                log::info!(
                                    "gRPC client error {} {} {:.6}",
                                    method_name,
                                    response_tonic.status(),
                                    elapsed_sec,
                                );
                            }
                            500..=599 => {
                                log::error!(
                                    "gRPC server error {} {} {:.6}",
                                    method_name,
                                    response_tonic.status(),
                                    elapsed_sec,
                                );
                            }
                            _ => {
                                log::warn!(
                                    "gRPC {} unknown status code {} {:.6}",
                                    method_name,
                                    response_tonic.status(),
                                    elapsed_sec,
                                );
                            }
                        };
                    }
                    Ok(response_tonic)
                }
            }
        })
    }
}

impl<S> Layer<S> for LoggingMiddlewareLayer {
    type Service = LoggingMiddleware<S>;

    fn layer(&self, service: S) -> Self::Service {
        LoggingMiddleware { inner: service }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn grpc_status_log_message_redacts_crypto_material() {
        let status = tonic::Status::invalid_argument(
            "invalid $qdrant_client_aead envelope ciphertext wrapped_key_b64",
        );

        let rendered = redacted_grpc_status_message(&status);

        assert!(rendered.contains("redacted"));
        assert!(!rendered.contains("$qdrant_client_aead"));
        assert!(!rendered.contains("ciphertext"));
        assert!(!rendered.contains("wrapped_key_b64"));
    }

    #[test]
    fn grpc_status_log_message_redacts_private_oram_access_pattern_fields() {
        let status = tonic::Status::invalid_argument(
            "private ORAM read failed for session_id=session-sentinel \
             path_label=leaf-sentinel candidate_heap=candidate-sentinel \
             payload_fetch_token=fetch-token-sentinel \
             updated_buckets=updated-bucket-sentinel \
             bucket_commitment=bucket-commitment-sentinel",
        );

        let rendered = redacted_grpc_status_message(&status);

        assert!(rendered.contains("redacted"));
        assert!(!rendered.contains("session-sentinel"));
        assert!(!rendered.contains("leaf-sentinel"));
        assert!(!rendered.contains("candidate-sentinel"));
        assert!(!rendered.contains("fetch-token-sentinel"));
        assert!(!rendered.contains("updated-bucket-sentinel"));
        assert!(!rendered.contains("bucket-commitment-sentinel"));
    }
}
