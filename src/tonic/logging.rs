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
             sessionId=session-camel-sentinel \
             paths=raw-path-sentinel \
             accessPath=access-path-camel-sentinel \
             read_paths=read-path-sentinel \
             read_buckets=read-bucket-sentinel \
             readBuckets=read-bucket-camel-sentinel \
             read_bucket_id=single-read-bucket-sentinel \
             readBucketId=single-read-bucket-camel-sentinel \
             read_bucket_ids=read-bucket-id-sentinel \
             readBucketIds=read-bucket-id-camel-sentinel \
             read_bucket_id_sequence=read-bucket-id-sequence-sentinel \
             read_bucket_id_sequences=read-bucket-id-sequences-sentinel \
             bucketIdSequence=bucket-id-sequence-camel-sentinel \
             bucketIdSequences=bucket-id-sequences-camel-sentinel \
             root_hash=root-hash-sentinel \
             oldRootHash=old-root-hash-camel-sentinel \
             new_root_hash=new-root-hash-sentinel \
             path_label=leaf-sentinel candidate_heap=candidate-sentinel \
             candidateNodes=candidate-node-camel-sentinel \
             pathLabels=leaf-camel-sentinel \
             readPathLabels=read-path-labels-camel-sentinel \
             oramPaths=oram-path-camel-sentinel \
             accessedLeafLabels=accessed-leaf-camel-sentinel \
             entryNodeId=entry-node-camel-sentinel \
             levelMask=level-mask-camel-sentinel \
             visitedNodeIds=visited-node-camel-sentinel \
             neighbors=neighbors-sentinel \
             neighborId=neighbor-id-camel-sentinel \
             neighborLevels=neighbor-level-camel-sentinel \
             client_signature=client-signature-sentinel \
             request_signature=request-signature-sentinel \
             readSignature=read-signature-camel-sentinel \
             commitSignature=commit-signature-camel-sentinel \
             payload_fetch_token=fetch-token-sentinel \
             payloadFetchTokens=fetch-token-camel-sentinel \
             resultIds=result-id-camel-sentinel \
             point_tokens=point-token-snake-sentinel \
             clientState=client-state-camel-sentinel \
             tokenPositionMap=token-position-map-camel-sentinel \
             updated_bucket=updated-bucket-singular-sentinel \
             updated_buckets=updated-bucket-sentinel \
             updatedBuckets=updated-bucket-camel-sentinel \
             bucket_commitment=bucket-commitment-sentinel \
             bucket_commitments=bucket-commitment-snake-plural-sentinel \
             bucketCommitments=bucket-commitment-camel-plural-sentinel \
             leaf_commitment=single-leaf-commitment-sentinel \
             leaf_commitments=leaf-commitment-snake-sentinel \
             leafCommitment=single-leaf-commitment-camel-sentinel \
             leafCommitments=leaf-commitment-camel-sentinel \
             bucket_ids=bucket-id-snake-sentinel \
             bucketIds=bucket-id-camel-sentinel \
             unknown_field=unknown-field-snake-sentinel \
             unknownField=unknown-field-camel-sentinel",
        );

        let rendered = redacted_grpc_status_message(&status);

        assert!(rendered.contains("redacted"));
        assert!(!rendered.contains("session-sentinel"));
        assert!(!rendered.contains("session-camel-sentinel"));
        assert!(!rendered.contains("raw-path-sentinel"));
        assert!(!rendered.contains("access-path-camel-sentinel"));
        assert!(!rendered.contains("read-path-sentinel"));
        assert!(!rendered.contains("read-bucket-sentinel"));
        assert!(!rendered.contains("read-bucket-camel-sentinel"));
        assert!(!rendered.contains("single-read-bucket-sentinel"));
        assert!(!rendered.contains("single-read-bucket-camel-sentinel"));
        assert!(!rendered.contains("read-bucket-id-sentinel"));
        assert!(!rendered.contains("read-bucket-id-camel-sentinel"));
        assert!(!rendered.contains("read-bucket-id-sequence-sentinel"));
        assert!(!rendered.contains("read-bucket-id-sequences-sentinel"));
        assert!(!rendered.contains("bucket-id-sequence-camel-sentinel"));
        assert!(!rendered.contains("bucket-id-sequences-camel-sentinel"));
        assert!(!rendered.contains("root-hash-sentinel"));
        assert!(!rendered.contains("old-root-hash-camel-sentinel"));
        assert!(!rendered.contains("new-root-hash-sentinel"));
        assert!(!rendered.contains("leaf-sentinel"));
        assert!(!rendered.contains("candidate-node-camel-sentinel"));
        assert!(!rendered.contains("leaf-camel-sentinel"));
        assert!(!rendered.contains("read-path-labels-camel-sentinel"));
        assert!(!rendered.contains("oram-path-camel-sentinel"));
        assert!(!rendered.contains("accessed-leaf-camel-sentinel"));
        assert!(!rendered.contains("entry-node-camel-sentinel"));
        assert!(!rendered.contains("level-mask-camel-sentinel"));
        assert!(!rendered.contains("visited-node-camel-sentinel"));
        assert!(!rendered.contains("neighbors-sentinel"));
        assert!(!rendered.contains("neighbor-id-camel-sentinel"));
        assert!(!rendered.contains("neighbor-level-camel-sentinel"));
        assert!(!rendered.contains("candidate-sentinel"));
        assert!(!rendered.contains("client-signature-sentinel"));
        assert!(!rendered.contains("request-signature-sentinel"));
        assert!(!rendered.contains("read-signature-camel-sentinel"));
        assert!(!rendered.contains("commit-signature-camel-sentinel"));
        assert!(!rendered.contains("fetch-token-sentinel"));
        assert!(!rendered.contains("fetch-token-camel-sentinel"));
        assert!(!rendered.contains("result-id-camel-sentinel"));
        assert!(!rendered.contains("point-token-snake-sentinel"));
        assert!(!rendered.contains("client-state-camel-sentinel"));
        assert!(!rendered.contains("token-position-map-camel-sentinel"));
        assert!(!rendered.contains("updated-bucket-singular-sentinel"));
        assert!(!rendered.contains("updated-bucket-sentinel"));
        assert!(!rendered.contains("updated-bucket-camel-sentinel"));
        assert!(!rendered.contains("bucket-commitment-sentinel"));
        assert!(!rendered.contains("bucket-commitment-snake-plural-sentinel"));
        assert!(!rendered.contains("bucket-commitment-camel-plural-sentinel"));
        assert!(!rendered.contains("single-leaf-commitment-sentinel"));
        assert!(!rendered.contains("leaf-commitment-snake-sentinel"));
        assert!(!rendered.contains("single-leaf-commitment-camel-sentinel"));
        assert!(!rendered.contains("leaf-commitment-camel-sentinel"));
        assert!(!rendered.contains("bucket-id-snake-sentinel"));
        assert!(!rendered.contains("bucket-id-camel-sentinel"));
        assert!(!rendered.contains("unknown-field-snake-sentinel"));
        assert!(!rendered.contains("unknown-field-camel-sentinel"));
    }
}
