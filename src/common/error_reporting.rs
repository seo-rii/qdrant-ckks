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
        "signaturepublickey",
        "signaturepublickeys",
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
        "blockplaintext",
        "blockplaintexts",
        "bucketcommitment",
        "bucketcommitments",
        "bucketid",
        "bucketids",
        "bucketidsequence",
        "bucketidsequences",
        "bucketplaintext",
        "bucketplaintexts",
        "bucketsequence",
        "bucketsequences",
        "candidateheap",
        "candidateid",
        "candidateids",
        "candidatenode",
        "candidatenodes",
        "candidatescore",
        "candidatescores",
        "candidatedistance",
        "candidatedistances",
        "clientsignature",
        "clientstate",
        "clientstatebackup",
        "clientstatebackups",
        "clientstatesnapshot",
        "clientstatesnapshots",
        "commitsignature",
        "distance",
        "distances",
        "distancescore",
        "distancescores",
        "entrynodeid",
        "entrynodeids",
        "encryptedclientstate",
        "encryptedclientstates",
        "encryptedclientstatebackup",
        "encryptedclientstatebackups",
        "encryptedclientstatesnapshot",
        "encryptedclientstatesnapshots",
        "encryptedclientstateciphertext",
        "encryptedclientstateciphertexthash",
        "fetchtoken",
        "fetchtokens",
        "leafcommitment",
        "leafcommitments",
        "leafhash",
        "leafhashes",
        "leaflabel",
        "leaflabels",
        "levelmask",
        "levelmasks",
        "manifestsignature",
        "merkleproof",
        "merkleproofs",
        "neighbor",
        "neighbors",
        "neighborid",
        "neighborids",
        "neighborlevel",
        "neighborlevels",
        "nodeblock",
        "nodeblocks",
        "nodeid",
        "nodeids",
        "nodeplaintext",
        "nodeplaintexts",
        "nodescore",
        "nodescores",
        "nodedistance",
        "nodedistances",
        "orampath",
        "orampaths",
        "orampositionmap",
        "orampositionmapbackup",
        "orampositionmapbackups",
        "ownersigningkeyid",
        "ownersigningkeyids",
        "payloadbytes",
        "payloadplaintext",
        "payloadplaintexts",
        "paths",
        "pathlabel",
        "pathlabels",
        "plaintextblock",
        "plaintextblocks",
        "plaintextbucket",
        "plaintextbuckets",
        "plaintextpayload",
        "plaintextpayloads",
        "plaintextvector",
        "plaintextvectors",
        "positionmap",
        "positionmapbackup",
        "positionmapbackups",
        "positionmaps",
        "proof",
        "proofs",
        "queryembedding",
        "queryembeddings",
        "queryplaintext",
        "queryplaintexts",
        "queryvector",
        "queryvectors",
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
        "readbucketsequence",
        "readbucketsequences",
        "readbuckets",
        "readpath",
        "readpathlabel",
        "readpaths",
        "readsignature",
        "requestsignature",
        "resultid",
        "resultids",
        "roothash",
        "roothashes",
        "oldroothash",
        "newroothash",
        "score",
        "scores",
        "sessionid",
        "signingkeyid",
        "signingkeyids",
        "sibling",
        "siblings",
        "siblinghash",
        "siblinghashes",
        "stash",
        "stashbackup",
        "stashbackups",
        "tokenpositionmap",
        "tokenpositionmapbackup",
        "tokenpositionmapbackups",
        "topk",
        "updatedbucket",
        "updatedbucketcommitment",
        "updatedbucketcommitments",
        "updatedbucketid",
        "updatedbucketids",
        "updatedbuckets",
        "unknownfield",
        "vectorbytes",
        "vectorplaintext",
        "vectorplaintexts",
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
            "session_ids=[private-session-list-sentinel]",
            "sessionIds=[private-session-list-camel-sentinel]",
            "path_label=private-path-label-sentinel",
            "pathLabel=private-path-label-camel-sentinel",
            "paths=[private-raw-path-sentinel]",
            "access_path=[private-access-path-sentinel]",
            "accessPaths=[private-access-path-camel-sentinel]",
            "read_path=[private-single-read-path-sentinel]",
            "readPath=[private-single-read-path-camel-sentinel]",
            "read_paths=[private-read-path-sentinel]",
            "read_path_label=private-read-path-label-snake-sentinel",
            "readPathLabel=private-read-path-label-camel-sentinel",
            "read_path_labels=[private-read-path-labels-snake-sentinel]",
            "read_buckets=[private-read-bucket-sentinel]",
            "readBuckets=[private-read-bucket-camel-sentinel]",
            "read_bucket_id=private-single-read-bucket-sentinel",
            "readBucketId=private-single-read-bucket-camel-sentinel",
            "read_bucket_ids=[private-read-bucket-id-sentinel]",
            "readBucketIds=[private-read-bucket-id-camel-sentinel]",
            "read_bucket_id_sequence=[private-read-bucket-sequence-sentinel]",
            "readBucketIdSequence=[private-read-bucket-sequence-camel-sentinel]",
            "read_bucket_id_sequences=[private-read-bucket-sequences-sentinel]",
            "read_bucket_sequence=[private-read-bucket-sequence-short-sentinel]",
            "readBucketSequence=[private-read-bucket-sequence-short-camel-sentinel]",
            "read_bucket_sequences=[private-read-bucket-sequences-short-sentinel]",
            "readBucketSequences=[private-read-bucket-sequences-short-camel-sentinel]",
            "bucket_id_sequence=[private-bucket-sequence-snake-sentinel]",
            "bucketIdSequence=[private-bucket-sequence-camel-sentinel]",
            "bucketIdSequences=[private-bucket-sequences-camel-sentinel]",
            "bucket_sequence=[private-bucket-sequence-short-snake-sentinel]",
            "bucketSequence=[private-bucket-sequence-short-camel-sentinel]",
            "bucket_sequences=[private-bucket-sequences-short-snake-sentinel]",
            "bucketSequences=[private-bucket-sequences-short-camel-sentinel]",
            "pathLabels=[private-path-labels-camel-sentinel]",
            "readPathLabels=[private-read-path-labels-camel-sentinel]",
            "leaf_label=private-leaf-label-snake-sentinel",
            "leafLabels=[private-leaf-label-sentinel]",
            "leaf_commitment=private-single-leaf-commitment-sentinel",
            "leaf_commitments=[private-leaf-commitment-sentinel]",
            "leafCommitment=private-single-leaf-commitment-camel-sentinel",
            "leafCommitments=[private-leaf-commitment-camel-sentinel]",
            "leaf_hash=private-leaf-hash-sentinel",
            "leafHash=private-leaf-hash-camel-sentinel",
            "merkle_proof=private-merkle-proof-sentinel",
            "merkleProof=private-merkle-proof-camel-sentinel",
            "proof=private-proof-sentinel",
            "proofs=[private-proofs-sentinel]",
            "sibling=private-sibling-sentinel",
            "siblings=[private-siblings-sentinel]",
            "sibling_hash=private-sibling-hash-sentinel",
            "siblingHash=private-sibling-hash-camel-sentinel",
            "accessed_leaf_labels=[private-accessed-leaf-sentinel]",
            "accessedLeafLabel=private-accessed-leaf-camel-singular-sentinel",
            "oram_path=[private-oram-path-sentinel]",
            "oramPaths=[private-oram-path-camel-sentinel]",
            "bucket_plaintext=private-bucket-plaintext-sentinel",
            "bucketPlaintext=private-bucket-plaintext-camel-sentinel",
            "plaintext_bucket=private-plaintext-bucket-sentinel",
            "plaintextBucket=private-plaintext-bucket-camel-sentinel",
            "bucket_id=private-bucket-sentinel",
            "bucket_ids=[private-bucket-list-sentinel]",
            "bucketIds=[private-bucket-list-camel-sentinel]",
            "bucketId=private-bucket-camel-singular-sentinel",
            "bucket_commitment=private-bucket-commitment-sentinel",
            "bucket_commitments=[private-bucket-commitment-snake-plural-sentinel]",
            "bucketCommitments=[private-bucket-commitment-camel-sentinel]",
            "bucketCommitment=private-bucket-commitment-camel-singular-sentinel",
            "block_plaintext=private-block-plaintext-sentinel",
            "blockPlaintext=private-block-plaintext-camel-sentinel",
            "plaintext_block=private-plaintext-block-sentinel",
            "plaintextBlock=private-plaintext-block-camel-sentinel",
            "node_ids=[private-node-sentinel]",
            "nodeIds=[private-node-camel-sentinel]",
            "node_block=private-node-block-sentinel",
            "nodeBlock=private-node-block-camel-sentinel",
            "node_plaintext=private-node-plaintext-sentinel",
            "nodePlaintext=private-node-plaintext-camel-sentinel",
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
            "candidate_score=private-candidate-score-sentinel",
            "candidateScores=[private-candidate-scores-camel-sentinel]",
            "candidate_distance=private-candidate-distance-sentinel",
            "candidateDistances=[private-candidate-distances-camel-sentinel]",
            "score=private-score-sentinel",
            "scores=[private-scores-sentinel]",
            "distance=private-distance-sentinel",
            "distances=[private-distances-sentinel]",
            "distance_score=private-distance-score-sentinel",
            "distanceScores=[private-distance-scores-camel-sentinel]",
            "node_score=private-node-score-sentinel",
            "nodeScores=[private-node-scores-camel-sentinel]",
            "node_distance=private-node-distance-sentinel",
            "nodeDistances=[private-node-distances-camel-sentinel]",
            "query_vector=[private-query-vector-sentinel]",
            "queryVector=[private-query-vector-camel-sentinel]",
            "query_embedding=[private-query-embedding-sentinel]",
            "queryEmbeddings=[private-query-embeddings-camel-sentinel]",
            "query_plaintext=private-query-plaintext-sentinel",
            "queryPlaintext=private-query-plaintext-camel-sentinel",
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
            "fetch_token=private-short-fetch-token-sentinel",
            "fetchTokens=[private-short-fetch-token-camel-sentinel]",
            "fetchToken=private-short-fetch-token-camel-singular-sentinel",
            "payload_fetch_tokens=[private-fetch-token-sentinel]",
            "payloadFetchTokens=[private-fetch-token-camel-sentinel]",
            "payloadFetchToken=private-fetch-token-camel-singular-sentinel",
            "payload_bytes=private-payload-bytes-sentinel",
            "payloadBytes=private-payload-bytes-camel-sentinel",
            "payload_plaintext=private-payload-plaintext-sentinel",
            "payloadPlaintext=private-payload-plaintext-camel-sentinel",
            "plaintext_payload=private-plaintext-payload-sentinel",
            "plaintextPayload=private-plaintext-payload-camel-sentinel",
            "payload_oram_leaf=private-payload-leaf-sentinel",
            "payloadOramLeaf=private-payload-leaf-camel-sentinel",
            "vector_bytes=private-vector-bytes-sentinel",
            "vectorBytes=private-vector-bytes-camel-sentinel",
            "vector_plaintext=private-vector-plaintext-sentinel",
            "vectorPlaintext=private-vector-plaintext-camel-sentinel",
            "plaintext_vector=private-plaintext-vector-sentinel",
            "plaintextVector=private-plaintext-vector-camel-sentinel",
            "position_map=private-position-map-sentinel",
            "positionMap=private-position-map-camel-sentinel",
            "positionMapBackup=private-position-map-backup-camel-sentinel",
            "positionMapBackups=[private-position-map-backups-camel-sentinel]",
            "position_map_snapshot=private-position-map-snapshot-sentinel",
            "positionMapSnapshot=private-position-map-snapshot-camel-sentinel",
            "position_maps=[private-position-map-plural-sentinel]",
            "positionMaps=[private-position-map-camel-plural-sentinel]",
            "oram_position_map=private-position-map-sentinel",
            "oramPositionMap=private-position-map-camel-sentinel",
            "oram_position_map_backup=private-oram-position-map-backup-sentinel",
            "oramPositionMapBackup=private-oram-position-map-backup-camel-sentinel",
            "oramPositionMapBackups=[private-oram-position-map-backups-camel-sentinel]",
            "oramPositionMapSnapshot=private-oram-position-map-snapshot-camel-sentinel",
            "tokenPositionMap=private-token-position-map-sentinel",
            "tokenPositionMapBackup=private-token-position-map-backup-sentinel",
            "tokenPositionMapBackups=[private-token-position-map-backups-sentinel]",
            "tokenPositionMapSnapshot=private-token-position-map-snapshot-sentinel",
            "client_state=private-client-state-sentinel",
            "clientState=private-client-state-camel-sentinel",
            "client_state_backup=private-client-state-backup-sentinel",
            "clientStateBackup=private-client-state-backup-camel-sentinel",
            "clientStateBackups=[private-client-state-backups-camel-sentinel]",
            "client_state_snapshot=private-client-state-snapshot-sentinel",
            "clientStateSnapshot=private-client-state-snapshot-camel-sentinel",
            "encrypted_client_state=private-encrypted-client-state-sentinel",
            "encryptedClientState=private-encrypted-client-state-camel-sentinel",
            "encrypted_client_state_backup=private-encrypted-client-state-backup-sentinel",
            "encryptedClientStateBackup=private-encrypted-client-state-backup-camel-sentinel",
            "encryptedClientStateBackups=[private-encrypted-client-state-backups-camel-sentinel]",
            "encrypted_client_state_snapshot=private-encrypted-client-state-snapshot-sentinel",
            "encryptedClientStateSnapshot=private-encrypted-client-state-snapshot-camel-sentinel",
            "client_state_ciphertext=private-client-state-ciphertext-sentinel",
            "clientStateCiphertext=private-client-state-ciphertext-camel-sentinel",
            "clientStateCiphertextHash=private-client-state-ciphertext-hash-camel-sentinel",
            "encryptedClientStateCiphertext=private-encrypted-client-state-ciphertext-camel-sentinel",
            "stateCiphertext=private-state-ciphertext-camel-sentinel",
            "stash=private-stash-sentinel",
            "stashBackup=private-stash-backup-sentinel",
            "stashBackups=[private-stash-backups-camel-sentinel]",
            "stashSnapshot=private-stash-snapshot-sentinel",
            "updated_bucket=private-updated-bucket-singular-sentinel",
            "updated_bucket_id=private-updated-bucket-id-sentinel",
            "updatedBucketId=private-updated-bucket-id-camel-sentinel",
            "updated_bucket_commitment=private-updated-bucket-commitment-sentinel",
            "updatedBucketCommitment=private-updated-bucket-commitment-camel-sentinel",
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
    fn test_build_report_payload_redacts_private_oram_signing_key_identifiers() {
        for secret in [
            "owner_signing_key_id=private-owner-signing-key-id-sentinel",
            "ownerSigningKeyId=private-owner-signing-key-id-camel-sentinel",
            "owner_signing_key_ids=[private-owner-signing-key-ids-sentinel]",
            "ownerSigningKeyIds=[private-owner-signing-key-ids-camel-sentinel]",
            "signing_key_id=private-signing-key-id-sentinel",
            "signingKeyId=private-signing-key-id-camel-sentinel",
            "signing_key_ids=[private-signing-key-ids-sentinel]",
            "signingKeyIds=[private-signing-key-ids-camel-sentinel]",
            "signature_public_keys={private-signing-key-registry-sentinel: public-key-sentinel}",
            "signaturePublicKeys={private-signing-key-registry-camel-sentinel: public-key-sentinel}",
        ] {
            let payload = ErrorReporter::build_report_payload(secret, "node-7", Some(secret));

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
