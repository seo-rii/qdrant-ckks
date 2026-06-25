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
             session_ids=session-list-sentinel \
             sessionIds=session-list-camel-sentinel \
             paths=raw-path-sentinel \
             accessPath=access-path-camel-sentinel \
             read_paths=read-path-sentinel \
             read_path_labels=read-path-labels-snake-sentinel \
             read_buckets=read-bucket-sentinel \
             readBuckets=read-bucket-camel-sentinel \
             read_bucket_id=single-read-bucket-sentinel \
             readBucketId=single-read-bucket-camel-sentinel \
             read_bucket_ids=read-bucket-id-sentinel \
             readBucketIds=read-bucket-id-camel-sentinel \
             read_bucket_id_sequence=read-bucket-id-sequence-sentinel \
             readBucketIdSequence=read-bucket-id-sequence-camel-sentinel \
             read_bucket_id_sequences=read-bucket-id-sequences-sentinel \
             read_bucket_sequence=read-bucket-sequence-short-sentinel \
             readBucketSequence=read-bucket-sequence-short-camel-sentinel \
             readBucketSequences=read-bucket-sequences-short-camel-sentinel \
             bucket_id_sequence=bucket-id-sequence-snake-sentinel \
             bucketIdSequence=bucket-id-sequence-camel-sentinel \
             bucketIdSequences=bucket-id-sequences-camel-sentinel \
             bucket_sequence=bucket-sequence-short-snake-sentinel \
             bucketSequence=bucket-sequence-short-camel-sentinel \
             bucketSequences=bucket-sequences-short-camel-sentinel \
             root_hash=root-hash-sentinel \
             rootHashes=root-hashes-camel-sentinel \
             oldRootHash=old-root-hash-camel-sentinel \
             old_root_hashes=old-root-hashes-snake-sentinel \
             new_root_hash=new-root-hash-sentinel \
             newRootHashes=new-root-hashes-camel-sentinel \
             path_label=leaf-sentinel pathLabel=path-label-camel-sentinel \
             leaf_label=leaf-label-snake-sentinel \
             candidate_heap=candidate-sentinel \
             candidateNodes=candidate-node-camel-sentinel \
             candidateScores=candidate-scores-camel-sentinel \
             candidate_distance=candidate-distance-sentinel \
             score=score-sentinel scores=scores-sentinel \
             distance=distance-sentinel distances=distances-sentinel \
             distanceScores=distance-scores-camel-sentinel \
             nodeScores=node-scores-camel-sentinel \
             nodeDistances=node-distances-camel-sentinel \
             query_vector=query-vector-sentinel \
             queryVector=query-vector-camel-sentinel \
             query_embeddings=query-embeddings-sentinel \
             queryPlaintext=query-plaintext-camel-sentinel \
             pathLabels=leaf-camel-sentinel \
             readPathLabels=read-path-labels-camel-sentinel \
             oramPaths=oram-path-camel-sentinel \
             accessedLeafLabels=accessed-leaf-camel-sentinel \
             bucket_plaintext=bucket-plaintext-sentinel \
             plaintextBucket=plaintext-bucket-camel-sentinel \
             block_plaintext=block-plaintext-sentinel \
             plaintextBlock=plaintext-block-camel-sentinel \
             entryNodeId=entry-node-camel-sentinel \
             node_block=node-block-sentinel \
             nodePlaintext=node-plaintext-camel-sentinel \
             levelMask=level-mask-camel-sentinel \
             visitedNodeIds=visited-node-camel-sentinel \
             neighbors=neighbors-sentinel \
             neighborId=neighbor-id-camel-sentinel \
             neighborLevels=neighbor-level-camel-sentinel \
             client_signature=client-signature-sentinel \
             request_signature=request-signature-sentinel \
             readSignature=read-signature-camel-sentinel \
             commitSignature=commit-signature-camel-sentinel \
             owner_signing_key_id=owner-signing-key-sentinel \
             ownerSigningKeyIds=owner-signing-key-ids-camel-sentinel \
             signing_key_id=signing-key-sentinel \
             signingKeyIds=signing-key-ids-camel-sentinel \
             signature_public_keys=signature-public-keys-sentinel \
             signaturePublicKeys=signature-public-keys-camel-sentinel \
             fetch_token=short-fetch-token-sentinel \
             fetchTokens=short-fetch-token-camel-sentinel \
             payload_fetch_token=fetch-token-sentinel \
             payloadFetchTokens=fetch-token-camel-sentinel \
             payload_bytes=payload-bytes-sentinel \
             payloadPlaintext=payload-plaintext-camel-sentinel \
             vector_bytes=vector-bytes-sentinel \
             vectorPlaintext=vector-plaintext-camel-sentinel \
             resultIds=result-id-camel-sentinel \
             point_tokens=point-token-snake-sentinel \
             clientState=client-state-camel-sentinel \
             clientStateCiphertext=client-state-ciphertext-camel-sentinel \
             clientStateCiphertextHash=client-state-ciphertext-hash-camel-sentinel \
             encryptedClientStateCiphertext=encrypted-client-state-ciphertext-camel-sentinel \
             stateCiphertext=state-ciphertext-camel-sentinel \
             position_map=position-map-snake-sentinel \
             positionMap=position-map-camel-sentinel \
             positionMaps=position-maps-camel-sentinel \
             stash=stash-sentinel \
             tokenPositionMap=token-position-map-camel-sentinel \
             updated_bucket=updated-bucket-singular-sentinel \
             updated_bucket_id=updated-bucket-id-snake-sentinel \
             updatedBucketId=updated-bucket-id-camel-sentinel \
             updated_bucket_commitment=updated-bucket-commitment-snake-sentinel \
             updatedBucketCommitment=updated-bucket-commitment-camel-sentinel \
             updated_buckets=updated-bucket-sentinel \
             updatedBuckets=updated-bucket-camel-sentinel \
             bucket_commitment=bucket-commitment-sentinel \
             bucket_commitments=bucket-commitment-snake-plural-sentinel \
             bucketCommitments=bucket-commitment-camel-plural-sentinel \
             leaf_commitment=single-leaf-commitment-sentinel \
             leaf_commitments=leaf-commitment-snake-sentinel \
             leafCommitment=single-leaf-commitment-camel-sentinel \
             leafCommitments=leaf-commitment-camel-sentinel \
             leaf_hash=leaf-hash-sentinel \
             leafHash=leaf-hash-camel-sentinel \
             merkle_proof=merkle-proof-sentinel \
             merkleProof=merkle-proof-camel-sentinel \
             proof=proof-sentinel \
             proofs=proofs-sentinel \
             sibling=sibling-sentinel \
             siblings=siblings-sentinel \
             sibling_hash=sibling-hash-sentinel \
             siblingHash=sibling-hash-camel-sentinel \
             bucket_ids=bucket-id-snake-sentinel \
             bucketIds=bucket-id-camel-sentinel \
             unknown_field=unknown-field-snake-sentinel \
             unknownField=unknown-field-camel-sentinel",
        );

        let rendered = redacted_grpc_status_message(&status);

        assert!(rendered.contains("redacted"));
        assert!(!rendered.contains("session-sentinel"));
        assert!(!rendered.contains("session-camel-sentinel"));
        assert!(!rendered.contains("session-list-sentinel"));
        assert!(!rendered.contains("session-list-camel-sentinel"));
        assert!(!rendered.contains("raw-path-sentinel"));
        assert!(!rendered.contains("access-path-camel-sentinel"));
        assert!(!rendered.contains("read-path-sentinel"));
        assert!(!rendered.contains("read-path-labels-snake-sentinel"));
        assert!(!rendered.contains("read-bucket-sentinel"));
        assert!(!rendered.contains("read-bucket-camel-sentinel"));
        assert!(!rendered.contains("single-read-bucket-sentinel"));
        assert!(!rendered.contains("single-read-bucket-camel-sentinel"));
        assert!(!rendered.contains("read-bucket-id-sentinel"));
        assert!(!rendered.contains("read-bucket-id-camel-sentinel"));
        assert!(!rendered.contains("read-bucket-id-sequence-sentinel"));
        assert!(!rendered.contains("read-bucket-id-sequence-camel-sentinel"));
        assert!(!rendered.contains("read-bucket-id-sequences-sentinel"));
        assert!(!rendered.contains("read-bucket-sequence-short-sentinel"));
        assert!(!rendered.contains("read-bucket-sequence-short-camel-sentinel"));
        assert!(!rendered.contains("read-bucket-sequences-short-camel-sentinel"));
        assert!(!rendered.contains("bucket-id-sequence-snake-sentinel"));
        assert!(!rendered.contains("bucket-id-sequence-camel-sentinel"));
        assert!(!rendered.contains("bucket-id-sequences-camel-sentinel"));
        assert!(!rendered.contains("bucket-sequence-short-snake-sentinel"));
        assert!(!rendered.contains("bucket-sequence-short-camel-sentinel"));
        assert!(!rendered.contains("bucket-sequences-short-camel-sentinel"));
        assert!(!rendered.contains("root-hash-sentinel"));
        assert!(!rendered.contains("root-hashes-camel-sentinel"));
        assert!(!rendered.contains("old-root-hash-camel-sentinel"));
        assert!(!rendered.contains("old-root-hashes-snake-sentinel"));
        assert!(!rendered.contains("new-root-hash-sentinel"));
        assert!(!rendered.contains("new-root-hashes-camel-sentinel"));
        assert!(!rendered.contains("leaf-sentinel"));
        assert!(!rendered.contains("path-label-camel-sentinel"));
        assert!(!rendered.contains("leaf-label-snake-sentinel"));
        assert!(!rendered.contains("candidate-node-camel-sentinel"));
        assert!(!rendered.contains("candidate-scores-camel-sentinel"));
        assert!(!rendered.contains("candidate-distance-sentinel"));
        assert!(!rendered.contains("score-sentinel"));
        assert!(!rendered.contains("scores-sentinel"));
        assert!(!rendered.contains("distance-sentinel"));
        assert!(!rendered.contains("distances-sentinel"));
        assert!(!rendered.contains("distance-scores-camel-sentinel"));
        assert!(!rendered.contains("node-scores-camel-sentinel"));
        assert!(!rendered.contains("node-distances-camel-sentinel"));
        assert!(!rendered.contains("query-vector-sentinel"));
        assert!(!rendered.contains("query-vector-camel-sentinel"));
        assert!(!rendered.contains("query-embeddings-sentinel"));
        assert!(!rendered.contains("query-plaintext-camel-sentinel"));
        assert!(!rendered.contains("leaf-camel-sentinel"));
        assert!(!rendered.contains("read-path-labels-camel-sentinel"));
        assert!(!rendered.contains("oram-path-camel-sentinel"));
        assert!(!rendered.contains("accessed-leaf-camel-sentinel"));
        assert!(!rendered.contains("bucket-plaintext-sentinel"));
        assert!(!rendered.contains("plaintext-bucket-camel-sentinel"));
        assert!(!rendered.contains("block-plaintext-sentinel"));
        assert!(!rendered.contains("plaintext-block-camel-sentinel"));
        assert!(!rendered.contains("entry-node-camel-sentinel"));
        assert!(!rendered.contains("node-block-sentinel"));
        assert!(!rendered.contains("node-plaintext-camel-sentinel"));
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
        assert!(!rendered.contains("owner-signing-key-sentinel"));
        assert!(!rendered.contains("owner-signing-key-ids-camel-sentinel"));
        assert!(!rendered.contains("signing-key-sentinel"));
        assert!(!rendered.contains("signing-key-ids-camel-sentinel"));
        assert!(!rendered.contains("signature-public-keys-sentinel"));
        assert!(!rendered.contains("signature-public-keys-camel-sentinel"));
        assert!(!rendered.contains("short-fetch-token-sentinel"));
        assert!(!rendered.contains("short-fetch-token-camel-sentinel"));
        assert!(!rendered.contains("fetch-token-sentinel"));
        assert!(!rendered.contains("fetch-token-camel-sentinel"));
        assert!(!rendered.contains("payload-bytes-sentinel"));
        assert!(!rendered.contains("payload-plaintext-camel-sentinel"));
        assert!(!rendered.contains("vector-bytes-sentinel"));
        assert!(!rendered.contains("vector-plaintext-camel-sentinel"));
        assert!(!rendered.contains("result-id-camel-sentinel"));
        assert!(!rendered.contains("point-token-snake-sentinel"));
        assert!(!rendered.contains("client-state-camel-sentinel"));
        assert!(!rendered.contains("client-state-ciphertext-camel-sentinel"));
        assert!(!rendered.contains("client-state-ciphertext-hash-camel-sentinel"));
        assert!(!rendered.contains("encrypted-client-state-ciphertext-camel-sentinel"));
        assert!(!rendered.contains("state-ciphertext-camel-sentinel"));
        assert!(!rendered.contains("position-map-snake-sentinel"));
        assert!(!rendered.contains("position-map-camel-sentinel"));
        assert!(!rendered.contains("position-maps-camel-sentinel"));
        assert!(!rendered.contains("stash-sentinel"));
        assert!(!rendered.contains("token-position-map-camel-sentinel"));
        assert!(!rendered.contains("updated-bucket-singular-sentinel"));
        assert!(!rendered.contains("updated-bucket-id-snake-sentinel"));
        assert!(!rendered.contains("updated-bucket-id-camel-sentinel"));
        assert!(!rendered.contains("updated-bucket-commitment-snake-sentinel"));
        assert!(!rendered.contains("updated-bucket-commitment-camel-sentinel"));
        assert!(!rendered.contains("updated-bucket-sentinel"));
        assert!(!rendered.contains("updated-bucket-camel-sentinel"));
        assert!(!rendered.contains("bucket-commitment-sentinel"));
        assert!(!rendered.contains("bucket-commitment-snake-plural-sentinel"));
        assert!(!rendered.contains("bucket-commitment-camel-plural-sentinel"));
        assert!(!rendered.contains("single-leaf-commitment-sentinel"));
        assert!(!rendered.contains("leaf-commitment-snake-sentinel"));
        assert!(!rendered.contains("single-leaf-commitment-camel-sentinel"));
        assert!(!rendered.contains("leaf-commitment-camel-sentinel"));
        assert!(!rendered.contains("leaf-hash-sentinel"));
        assert!(!rendered.contains("leaf-hash-camel-sentinel"));
        assert!(!rendered.contains("merkle-proof-sentinel"));
        assert!(!rendered.contains("merkle-proof-camel-sentinel"));
        assert!(!rendered.contains("proof-sentinel"));
        assert!(!rendered.contains("proofs-sentinel"));
        assert!(!rendered.contains("sibling-sentinel"));
        assert!(!rendered.contains("siblings-sentinel"));
        assert!(!rendered.contains("sibling-hash-sentinel"));
        assert!(!rendered.contains("sibling-hash-camel-sentinel"));
        assert!(!rendered.contains("bucket-id-snake-sentinel"));
        assert!(!rendered.contains("bucket-id-camel-sentinel"));
        assert!(!rendered.contains("unknown-field-snake-sentinel"));
        assert!(!rendered.contains("unknown-field-camel-sentinel"));
    }
}
