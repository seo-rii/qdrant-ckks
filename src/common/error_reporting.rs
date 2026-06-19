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

pub(crate) fn redact_crypto_material_for_report(value: &str) -> String {
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
        "authorization",
        "bearer",
        "apikey",
        "accesskeyid",
        "awssessiontoken",
        "awssecuritytoken",
        "contextdigest",
        "cryptocontext",
        "cryptocontextb64",
        "materialfingerprint",
        "publickeyb64",
        "wrappedkey",
        "valueb64",
        "nonceb64",
        "signatureb64",
        "signaturesig",
        "sigb64",
        "privatekey",
        "secretaccesskey",
        "secretkey",
        "securitytoken",
        "sessiontoken",
        "vaulttoken",
        "xamzcredential",
        "xamzsignature",
        "xamzsecuritytoken",
        "xapikey",
        "accessedleaflabel",
        "accessedleaflabels",
        "accesspath",
        "accesspaths",
        "bucketcommitment",
        "bucketcommitments",
        "bucketid",
        "bucketids",
        "bucketidsequence",
        "bucketidsequences",
        "candidateheap",
        "candidateid",
        "candidateids",
        "candidatenode",
        "candidatenodes",
        "clientsignature",
        "clientstate",
        "commitsignature",
        "entrynodeid",
        "entrynodeids",
        "fetchtoken",
        "fetchtokens",
        "leafcommitment",
        "leafcommitments",
        "leaflabel",
        "leaflabels",
        "levelmask",
        "levelmasks",
        "manifestsignature",
        "neighbor",
        "neighbors",
        "neighborid",
        "neighborids",
        "neighborlevel",
        "neighborlevels",
        "nodeid",
        "nodeids",
        "orampath",
        "orampaths",
        "orampositionmap",
        "paths",
        "pathlabel",
        "pathlabels",
        "positionmap",
        "positionmaps",
        "payloadfetchtoken",
        "payloadfetchtokens",
        "payloadoramleaf",
        "payloadoramleaves",
        "pointtoken",
        "pointtokens",
        "readbucket",
        "readbucketid",
        "readbucketids",
        "readbucketidsequence",
        "readbucketidsequences",
        "readbuckets",
        "readpaths",
        "readsignature",
        "requestsignature",
        "resultid",
        "resultids",
        "roothash",
        "roothashes",
        "oldroothash",
        "newroothash",
        "sessionid",
        "stash",
        "tokenpositionmap",
        "topk",
        "updatedbucket",
        "updatedbuckets",
        "unknownfield",
        "visitednode",
        "visitednodes",
        "visitednodeid",
        "visitednodeids",
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

    #[test]
    fn test_build_report_payload_redacts_aws_and_auth_spellings() {
        for secret in [
            "Authorization: Bearer authorization-sentinel",
            "Bearer bearer-token-sentinel",
            "api_key=api-key-sentinel",
            "apiKey=api-key-sentinel",
            "X-Amz-Security-Token: aws-token-sentinel",
            "session_token=session-token-sentinel",
            "sessionToken=session-token-sentinel",
            "cryptoContextB64=crypto-context-sentinel",
            "publicKeyB64=public-key-sentinel",
            "signature.sig=sig-sentinel",
            "AWS_ACCESS_KEY_ID=access-key-sentinel",
            "AWS_SECRET_ACCESS_KEY=secret-key-sentinel",
            "X-Amz-Credential=credential-sentinel",
            "X-Amz-Signature=signature-sentinel",
            "Security-Token: security-token-sentinel",
        ] {
            let payload = ErrorReporter::build_report_payload(secret, "node-4", Some(secret));

            assert!(payload.contains("crypto material omitted"), "{payload}");
            assert!(!payload.contains("sentinel"), "{payload}");
        }
    }

    #[test]
    fn test_build_report_payload_redacts_private_oram_access_pattern_fields() {
        for secret in [
            "session_id=private-session-sentinel",
            "sessionId=private-session-camel-sentinel",
            "path_label=private-path-label-sentinel",
            "paths=[private-raw-path-sentinel]",
            "access_path=[private-access-path-sentinel]",
            "accessPaths=[private-access-path-camel-sentinel]",
            "read_paths=[private-read-path-sentinel]",
            "read_buckets=[private-read-bucket-sentinel]",
            "readBuckets=[private-read-bucket-camel-sentinel]",
            "read_bucket_id=private-single-read-bucket-sentinel",
            "readBucketId=private-single-read-bucket-camel-sentinel",
            "read_bucket_ids=[private-read-bucket-id-sentinel]",
            "readBucketIds=[private-read-bucket-id-camel-sentinel]",
            "read_bucket_id_sequence=[private-read-bucket-sequence-sentinel]",
            "read_bucket_id_sequences=[private-read-bucket-sequences-sentinel]",
            "bucketIdSequence=[private-bucket-sequence-camel-sentinel]",
            "bucketIdSequences=[private-bucket-sequences-camel-sentinel]",
            "pathLabels=[private-path-labels-camel-sentinel]",
            "readPathLabels=[private-read-path-labels-camel-sentinel]",
            "leafLabels=[private-leaf-label-sentinel]",
            "leaf_commitment=private-single-leaf-commitment-sentinel",
            "leaf_commitments=[private-leaf-commitment-sentinel]",
            "leafCommitment=private-single-leaf-commitment-camel-sentinel",
            "leafCommitments=[private-leaf-commitment-camel-sentinel]",
            "accessed_leaf_labels=[private-accessed-leaf-sentinel]",
            "accessedLeafLabel=private-accessed-leaf-camel-singular-sentinel",
            "oram_path=[private-oram-path-sentinel]",
            "oramPaths=[private-oram-path-camel-sentinel]",
            "bucket_id=private-bucket-sentinel",
            "bucket_ids=[private-bucket-list-sentinel]",
            "bucketIds=[private-bucket-list-camel-sentinel]",
            "bucketId=private-bucket-camel-singular-sentinel",
            "bucket_commitment=private-bucket-commitment-sentinel",
            "bucket_commitments=[private-bucket-commitment-snake-plural-sentinel]",
            "bucketCommitments=[private-bucket-commitment-camel-sentinel]",
            "bucketCommitment=private-bucket-commitment-camel-singular-sentinel",
            "node_ids=[private-node-sentinel]",
            "nodeIds=[private-node-camel-sentinel]",
            "entry_node_id=private-entry-node-sentinel",
            "entryNodeId=private-entry-node-camel-sentinel",
            "level_mask=private-level-mask-sentinel",
            "levelMask=private-level-mask-camel-sentinel",
            "visited_node_ids=[private-visited-node-sentinel]",
            "visitedNodeIds=[private-visited-node-camel-sentinel]",
            "neighbor_ids=[private-neighbor-sentinel]",
            "neighborIds=[private-neighbor-camel-sentinel]",
            "neighborLevel=private-neighbor-level-camel-sentinel",
            "neighbor_levels=[private-neighbor-level-sentinel]",
            "neighbors=[private-neighbors-sentinel]",
            "candidate_heap=private-candidate-sentinel",
            "candidateHeap=private-candidate-camel-sentinel",
            "candidate_nodes=[private-candidate-node-sentinel]",
            "candidateNodes=[private-candidate-node-camel-sentinel]",
            "client_signature=private-client-signature-sentinel",
            "clientSignature=private-client-signature-camel-sentinel",
            "commit_signature=private-commit-signature-sentinel",
            "commitSignature=private-commit-signature-camel-sentinel",
            "manifest_signature=private-manifest-signature-sentinel",
            "manifestSignature=private-manifest-signature-camel-sentinel",
            "read_signature=private-read-signature-sentinel",
            "readSignature=private-read-signature-camel-sentinel",
            "requestSignature=private-request-signature-camel-sentinel",
            "root_hash=private-root-hash-sentinel",
            "rootHash=private-root-hash-camel-sentinel",
            "old_root_hash=private-old-root-hash-sentinel",
            "oldRootHash=private-old-root-hash-camel-sentinel",
            "new_root_hash=private-new-root-hash-sentinel",
            "newRootHash=private-new-root-hash-camel-sentinel",
            "top_k=[private-topk-sentinel]",
            "topK=[private-topk-camel-sentinel]",
            "result_ids=[private-result-id-sentinel]",
            "resultIds=[private-result-id-camel-sentinel]",
            "point_token=private-point-token-sentinel",
            "pointTokens=[private-point-token-camel-plural-sentinel]",
            "pointToken=private-point-token-camel-sentinel",
            "payload_fetch_tokens=[private-fetch-token-sentinel]",
            "payloadFetchTokens=[private-fetch-token-camel-sentinel]",
            "payloadFetchToken=private-fetch-token-camel-singular-sentinel",
            "payload_oram_leaf=private-payload-leaf-sentinel",
            "payloadOramLeaf=private-payload-leaf-camel-sentinel",
            "position_map=private-position-map-sentinel",
            "positionMap=private-position-map-camel-sentinel",
            "position_maps=[private-position-map-plural-sentinel]",
            "positionMaps=[private-position-map-camel-plural-sentinel]",
            "oram_position_map=private-position-map-sentinel",
            "oramPositionMap=private-position-map-camel-sentinel",
            "tokenPositionMap=private-token-position-map-sentinel",
            "client_state=private-client-state-sentinel",
            "clientState=private-client-state-camel-sentinel",
            "stash=private-stash-sentinel",
            "updated_bucket=private-updated-bucket-singular-sentinel",
            "updated_buckets=[private-updated-bucket-snake-sentinel]",
            "updatedBuckets=[private-updated-bucket-sentinel]",
            "unknown_field=private-unknown-field-sentinel",
            "unknownField=private-unknown-field-camel-sentinel",
        ] {
            let payload = ErrorReporter::build_report_payload(secret, "node-6", Some(secret));

            assert!(payload.contains("crypto material omitted"), "{payload}");
            assert!(!payload.contains("sentinel"), "{payload}");
        }
    }

    #[test]
    fn test_build_report_payload_preserves_non_secret_context() {
        let payload = ErrorReporter::build_report_payload(
            "ordinary panic in optimizer worker",
            "node-5",
            Some("frame: src/common/query.rs:123"),
        );

        assert!(payload.contains("ordinary panic in optimizer worker"));
        assert!(payload.contains("src/common/query.rs:123"));
        assert!(!payload.contains("crypto material omitted"));
    }
}
