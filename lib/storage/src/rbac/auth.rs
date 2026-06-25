use std::collections::BTreeMap;

use chrono::Utc;

use super::{Access, AccessRequirements, AuthType, CollectionMultipass, CollectionPass};
use crate::audit::{AuditEvent, AuditResult, audit_log, is_audit_enabled};
use crate::content_manager::errors::StorageError;

/// Per-request authentication context.
///
/// Wraps the [`Access`] RBAC object together with request metadata (remote IP,
/// JWT `subject`, authentication method).  All access-check methods
/// additionally emit structured audit log entries when the global audit logger
/// is enabled.
#[derive(Clone, Debug)]
pub struct Auth {
    access: Access,
    subject: Option<String>,
    remote: Option<String>,
    auth_type: AuthType,
    tracing_id: Option<String>,
}

impl Auth {
    pub const fn new(
        access: Access,
        subject: Option<String>,
        remote: Option<String>,
        auth_type: AuthType,
        tracing_id: Option<String>,
    ) -> Self {
        Self {
            access,
            subject,
            remote,
            auth_type,
            tracing_id,
        }
    }

    pub const fn new_internal(access: Access) -> Self {
        Self {
            access,
            subject: None,
            remote: None,
            auth_type: AuthType::Internal,
            tracing_id: None,
        }
    }

    /// Borrow the inner [`Access`] object (e.g. to pass into library code that
    /// still expects `&Access`).
    ///
    /// Warn: this method is not recommended for general use, as it does not emit audit log entries.
    /// Consider using the `access()` method instead, which wraps access checks with audit logging.
    pub fn unlogged_access(&self) -> &Access {
        &self.access
    }

    /// Borrow the inner [`Access`] object (e.g. to pass into library code that
    /// still expects `&Access`).
    pub fn access(&self, method: &str) -> &Access {
        // Gives direct access to the inner `Access` object,
        // but also emits an audit log entry with "ok" status.
        self.emit_audit(method, None, &Ok(()));
        &self.access
    }

    // ------------------------------------------------------------------
    // Wrapped access-check methods with audit logging
    // ------------------------------------------------------------------

    /// Check global access and emit an audit log entry.
    pub fn check_global_access(
        &self,
        requirements: AccessRequirements,
        method: &str,
    ) -> Result<CollectionMultipass, StorageError> {
        let result = self.access.check_global_access(requirements);
        self.emit_audit(method, None, &result);
        result
    }

    /// Check collection-scoped access and emit an audit log entry.
    pub fn check_collection_access<'a>(
        &self,
        collection_name: &'a str,
        requirements: AccessRequirements,
        method: &str,
    ) -> Result<CollectionPass<'a>, StorageError> {
        let result = self
            .access
            .check_collection_access(collection_name, requirements);
        self.emit_audit(method, Some(collection_name), &result);
        result
    }

    // ------------------------------------------------------------------
    // Internal helpers
    // ------------------------------------------------------------------

    pub(crate) fn emit_audit<T>(
        &self,
        method: &str,
        collection: Option<&str>,
        result: &Result<T, StorageError>,
    ) {
        self.emit_audit_with_metadata(method, collection, result, BTreeMap::new());
    }

    pub fn emit_audit_with_metadata<T>(
        &self,
        method: &str,
        collection: Option<&str>,
        result: &Result<T, StorageError>,
        metadata: BTreeMap<String, String>,
    ) {
        if !is_audit_enabled() || self.auth_type == AuthType::Internal {
            return;
        }

        let (audit_result, error) = match result {
            Ok(_) => (AuditResult::Ok, None),
            Err(e) => (
                AuditResult::Denied,
                Some(redact_audit_error(&e.to_string())),
            ),
        };

        audit_log(AuditEvent {
            timestamp: Utc::now(),
            method: method.to_string(),
            auth_type: self.auth_type.clone(),
            subject: self.subject.clone(),
            remote: self.remote.clone(),
            collection: collection.map(String::from),
            tracing_id: self.tracing_id.clone(),
            result: audit_result,
            error,
            metadata,
        });
    }
}

fn redact_audit_error(error: &str) -> String {
    const REDACTED: &str = "[redacted: crypto material omitted from audit error]";
    const MARKERS: &[&str] = &["$qdrant_sec", "$qdrant_client_aead", "$qdrant_sec_vectors"];
    const COMPACT_KEYS: &[&str] = &[
        "authorization",
        "bearer",
        "apikey",
        "ciphertext",
        "ciphertextb64",
        "contextdigest",
        "cryptocontext",
        "encryptedquery",
        "encryptedqueryb64",
        "materialfingerprint",
        "nonce",
        "nonceb64",
        "privatekey",
        "publickey",
        "secretkey",
        "sessiontoken",
        "signature",
        "signatureb64",
        "sigb64",
        "valueb64",
        "vaulttoken",
        "wrappedkey",
        "wrappedkeyb64",
        "awssecuritytoken",
        "accessedleaflabel",
        "accesspath",
        "xamzsecuritytoken",
        "xapikey",
        "bucketcommitment",
        "bucketid",
        "bucketsequence",
        "candidateheap",
        "candidatescore",
        "candidatedistance",
        "clientstate",
        "commitsignature",
        "distance",
        "distancescore",
        "entrynodeid",
        "fetchtoken",
        "leafcommitment",
        "leafhash",
        "leaflabel",
        "levelmask",
        "manifestsignature",
        "merkleproof",
        "neighbor",
        "neighborid",
        "neighborlevel",
        "nodeid",
        "nodescore",
        "nodedistance",
        "orampath",
        "orampositionmap",
        "ownersigningkeyid",
        "ownersigningkeyids",
        "pathlabel",
        "payloadbytes",
        "payloadfetchtoken",
        "payloadoramleaf",
        "payloadplaintext",
        "plaintextbucket",
        "plaintextpayload",
        "plaintextvector",
        "pointtoken",
        "positionmap",
        "proof",
        "queryembedding",
        "queryplaintext",
        "queryvector",
        "readbucket",
        "readpath",
        "readsignature",
        "requestsignature",
        "resultid",
        "roothash",
        "score",
        "sessionid",
        "signaturepublickey",
        "signaturepublickeys",
        "signingkeyid",
        "signingkeyids",
        "siblinghash",
        "stash",
        "tokenpositionmap",
        "topk",
        "updatedbucket",
        "vectorbytes",
        "vectorplaintext",
        "visitednode",
    ];

    let lower = error.to_ascii_lowercase();
    if MARKERS.iter().any(|marker| lower.contains(marker)) {
        return REDACTED.to_string();
    }

    let compact = lower
        .chars()
        .filter(|ch| ch.is_ascii_alphanumeric())
        .collect::<String>();
    if COMPACT_KEYS.iter().any(|key| compact.contains(key)) {
        return REDACTED.to_string();
    }

    error.to_string()
}

#[cfg(test)]
mod tests {
    use super::redact_audit_error;

    #[test]
    fn audit_error_redaction_preserves_ordinary_errors() {
        let error = "Forbidden: write access denied for collection docs";

        assert_eq!(redact_audit_error(error), error);
    }

    #[test]
    fn audit_error_redaction_hides_crypto_envelope_material() {
        let error = r#"BadInput: {"$qdrant_client_aead":{"nonce":"nonce-sentinel","ciphertext":"ciphertext-sentinel","signature":{"sig":"signature-sentinel"}}}"#;
        let redacted = redact_audit_error(error);

        assert!(redacted.contains("redacted"));
        assert!(!redacted.contains("nonce-sentinel"));
        assert!(!redacted.contains("ciphertext-sentinel"));
        assert!(!redacted.contains("signature-sentinel"));
    }

    #[test]
    fn audit_error_redaction_hides_secret_like_fields() {
        for error in [
            "invalid wrappedKeyB64: wrapped-key-sentinel",
            "bridge public-key-b64 mismatch: public-key-sentinel",
            "vault x-vault-token rejected: vault-token-sentinel",
            "Bearer bearer-token-sentinel",
            "api_key rejected: api-key-sentinel",
            "apiKey rejected: api-key-sentinel",
            "Authorization header rejected: bearer-sentinel",
            "X-Amz-Security-Token rejected: aws-token-sentinel",
            "session_token rejected: session-token-sentinel",
            "sessionToken rejected: session-token-sentinel",
        ] {
            let redacted = redact_audit_error(error);

            assert!(redacted.contains("redacted"), "{redacted}");
            assert!(!redacted.contains("sentinel"), "{redacted}");
        }
    }

    #[test]
    fn audit_error_redaction_hides_private_oram_access_pattern_fields() {
        for error in [
            "private HNSW read failed path_label=private-path-label-sentinel",
            "private HNSW read failed read_path=[private-read-path-sentinel]",
            "private HNSW read failed readPath=[private-read-path-camel-sentinel]",
            "private HNSW read failed read_path_label=private-read-path-label-sentinel",
            "private HNSW read failed readPathLabel=private-read-path-label-camel-sentinel",
            "private HNSW read failed leafHash=private-leaf-hash-sentinel",
            "private HNSW read failed bucket_ids=[private-bucket-id-sentinel]",
            "private HNSW read failed root_hash=private-root-hash-sentinel",
            "private HNSW read failed node_id=private-node-id-sentinel",
            "private HNSW read failed vector_bytes=private-vector-bytes-sentinel",
            "private HNSW read failed queryVector=private-query-vector-sentinel",
            "private HNSW read failed query_embedding=private-query-embedding-sentinel",
            "private HNSW read failed query_plaintext=private-query-plaintext-sentinel",
            "private HNSW read failed score=private-score-sentinel",
            "private HNSW read failed distance=private-distance-sentinel",
            "private HNSW read failed candidateScores=private-candidate-score-sentinel",
            "private HNSW read failed candidate_distance=private-candidate-distance-sentinel",
            "private HNSW read failed nodeScores=private-node-score-sentinel",
            "private HNSW read failed node_distance=private-node-distance-sentinel",
            "private HNSW read failed neighborLevel=private-neighbor-level-sentinel",
            "private result ORAM read failed payload_fetch_token=private-fetch-token-sentinel",
            "private result ORAM read failed payload_plaintext=private-payload-sentinel",
            "private result ORAM read failed tokenPositionMap=private-token-position-sentinel",
            "private ORAM proof failed sibling_hash=private-sibling-hash-sentinel",
            "private ORAM commit failed updatedBucket=private-updated-bucket-sentinel",
            "private ORAM signature failed owner_signing_key_id=private-owner-signing-key-sentinel",
            "private ORAM signature failed ownerSigningKeyIds=private-owner-signing-key-camel-sentinel",
            "private ORAM signature failed signing_key_id=private-signing-key-sentinel",
            "private ORAM signature failed signingKeyIds=private-signing-key-camel-sentinel",
            "private ORAM signature failed signature_public_keys=private-signature-public-keys-sentinel",
            "private ORAM signature failed signaturePublicKeys=private-signature-public-keys-camel-sentinel",
        ] {
            let redacted = redact_audit_error(error);

            assert!(redacted.contains("redacted"), "{redacted}");
            assert!(!redacted.contains("sentinel"), "{redacted}");
        }
    }
}
