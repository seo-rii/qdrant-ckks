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
        "accesstoken",
        "bearer",
        "apikey",
        "ciphertext",
        "ciphertextb64",
        "clientsecret",
        "contextdigest",
        "cryptocontext",
        "cookie",
        "credential",
        "credentials",
        "encryptedquery",
        "encryptedqueryb64",
        "accesskeyid",
        "idtoken",
        "jwt",
        "materialfingerprint",
        "nonce",
        "nonceb64",
        "password",
        "privatekey",
        "publickey",
        "publickeysb64",
        "refreshtoken",
        "secretb64",
        "secretaccesskey",
        "secretkey",
        "securitytoken",
        "sessiontoken",
        "setcookie",
        "signature",
        "signatureb64",
        "sigb64",
        "valueb64",
        "valuesb64",
        "vaulttoken",
        "wrappedkey",
        "wrappedkeyb64",
        "awssecuritytoken",
        "accessedleaflabel",
        "accesscount",
        "accesscounts",
        "accesspath",
        "bucketidcount",
        "bucketidcounts",
        "xamzcredential",
        "xamzsignature",
        "xamzsecuritytoken",
        "xapikey",
        "blindresult",
        "blindresultkey",
        "bucketaead",
        "bucketaeadkey",
        "bucketcommitment",
        "bucketid",
        "bucketsequence",
        "candidateheap",
        "candidatescore",
        "candidatedistance",
        "clientstate",
        "clientstatebackup",
        "clientstatebackups",
        "clientstateciphertext",
        "clientstateciphertexts",
        "clientstateciphertexthash",
        "clientstateciphertexthashes",
        "clientstateciphertextsha256",
        "clientstateciphertextssha256",
        "clientstatekey",
        "clientstatesnapshot",
        "clientstatesnapshots",
        "commitsignature",
        "distance",
        "distancescore",
        "entrynodeid",
        "encryptedclientstate",
        "encryptedclientstates",
        "encryptedclientstatebackup",
        "encryptedclientstatebackups",
        "encryptedclientstateciphertext",
        "encryptedclientstateciphertexts",
        "encryptedclientstateciphertexthash",
        "encryptedclientstateciphertexthashes",
        "encryptedclientstateciphertextsha256",
        "encryptedclientstateciphertextssha256",
        "encryptedclientstatesnapshot",
        "encryptedclientstatesnapshots",
        "fetchtoken",
        "keymaterial",
        "keymaterialb64",
        "leafcommitment",
        "leafhash",
        "leaflabel",
        "levelmask",
        "manifestsignature",
        "masterkey",
        "masterkeyb64",
        "materialb64",
        "merkleproof",
        "neighbor",
        "neighborid",
        "neighborlevel",
        "nodeaead",
        "nodeaeadkey",
        "nodeid",
        "nodescore",
        "nodedistance",
        "orampath",
        "orampositionmap",
        "orampositionmapbackup",
        "orampositionmapbackups",
        "orampositionmaps",
        "orampositionmapsnapshot",
        "orampositionmapsnapshots",
        "ownersigningkeyid",
        "ownersigningkeyids",
        "pathlabel",
        "pathcount",
        "pathcounts",
        "payloadbytes",
        "payloadfetchtoken",
        "payloadfetchtokens",
        "payloadoramleaf",
        "payloadoramleaves",
        "payloadplaintext",
        "payloadtoken",
        "payloadtokenkey",
        "payloadtokens",
        "plaintextbucket",
        "plaintextpayload",
        "plaintextvector",
        "pointtoken",
        "pointtokens",
        "positionmap",
        "positionmapbackup",
        "positionmapbackups",
        "positionmaps",
        "positionmapsnapshot",
        "positionmapsnapshots",
        "proof",
        "queryembedding",
        "queryplaintext",
        "queryvector",
        "readbucket",
        "readbucketid",
        "readbucketidcount",
        "readbucketidcounts",
        "readbucketids",
        "readbucketidsequence",
        "readbucketidsequences",
        "readbucketsequence",
        "readbucketsequences",
        "readpath",
        "readsignature",
        "requestedbucketcount",
        "requestedbucketcounts",
        "requestedpathcount",
        "requestedpathcounts",
        "requestsignature",
        "resourcekey",
        "resourcekeyb64",
        "rootkey",
        "rootkeyb64",
        "returnedbucketcount",
        "returnedbucketcounts",
        "resultid",
        "resultids",
        "roothash",
        "score",
        "sessionid",
        "signaturepublickey",
        "signaturepublickeys",
        "signingkeyid",
        "signingkeyids",
        "siblinghash",
        "stash",
        "stashbackup",
        "stashbackups",
        "stashlen",
        "stashlength",
        "stashsnapshot",
        "stashsnapshots",
        "stateciphertext",
        "stateciphertexts",
        "stateciphertexthash",
        "stateciphertexthashes",
        "stateciphertextsha256",
        "stateciphertextssha256",
        "tokenpositionmap",
        "tokenpositionmapbackup",
        "tokenpositionmapbackups",
        "tokenpositionmaps",
        "tokenpositionmapsnapshot",
        "tokenpositionmapsnapshots",
        "topk",
        "accessedleaflabels",
        "accesspaths",
        "bucketcommitments",
        "bucketids",
        "bucketidsequence",
        "bucketidsequences",
        "bucketplaintext",
        "bucketplaintexts",
        "bucketsequences",
        "candidatedistances",
        "candidateid",
        "candidateids",
        "candidatenode",
        "candidatenodes",
        "candidatescores",
        "entrynodeids",
        "fetchtokens",
        "leafcommitments",
        "leafcount",
        "leafcounts",
        "leafhashes",
        "leaflabels",
        "levelmasks",
        "merkleproofs",
        "neighborcount",
        "neighborcounts",
        "neighborids",
        "neighborlevels",
        "neighbors",
        "nodeblock",
        "nodeblocks",
        "nodedistances",
        "nodeids",
        "nodeplaintext",
        "nodeplaintexts",
        "nodescores",
        "orampaths",
        "pathlabels",
        "paths",
        "payloadlen",
        "payloadlength",
        "payloadplaintexts",
        "plaintextblock",
        "plaintextblocks",
        "plaintextbuckets",
        "plaintextpayloads",
        "plaintextvectors",
        "positioncount",
        "positioncounts",
        "positionmaplen",
        "positionmaplength",
        "queryembeddings",
        "queryplaintexts",
        "queryvectors",
        "readbucketcount",
        "readbucketcounts",
        "readbuckets",
        "readpathlabel",
        "readpaths",
        "resultcount",
        "resultcounts",
        "roothashes",
        "scores",
        "sibling",
        "siblingcount",
        "siblingcounts",
        "siblinghashes",
        "siblings",
        "signaturepublickeyb64",
        "signaturepublickeysb64",
        "signaturesig",
        "tokencount",
        "tokencounts",
        "updatedbucketcommitment",
        "updatedbucketcommitments",
        "updatedbuckets",
        "vectorplaintexts",
        "visitednodeid",
        "visitednodeids",
        "visitednodes",
        "updatedbucket",
        "updatedbucketcount",
        "updatedbucketcounts",
        "updatedbucketid",
        "updatedbucketids",
        "writebackbucketcount",
        "writebackbucketcounts",
        "vectorbytes",
        "vectorplaintext",
        "visitednode",
        "wrappedresourcekey",
        "wrappedresourcekeyb64",
        "wrappingkey",
        "wrappingkeyb64",
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
            "access_token rejected: access-token-sentinel",
            "refreshToken rejected: refresh-token-camel-sentinel",
            "id_token rejected: id-token-sentinel",
            "jwt rejected: jwt-sentinel",
            "Cookie rejected: cookie-sentinel",
            "set_cookie rejected: set-cookie-sentinel",
            "Set-Cookie rejected: set-cookie-header-sentinel",
            "X-Amz-Security-Token rejected: aws-token-sentinel",
            "AWS_ACCESS_KEY_ID rejected: access-key-sentinel",
            "AWS_SECRET_ACCESS_KEY rejected: secret-access-key-sentinel",
            "X-Amz-Credential rejected: credential-sentinel",
            "X-Amz-Signature rejected: signature-sentinel",
            "Security-Token rejected: security-token-sentinel",
            "client_secret rejected: client-secret-sentinel",
            "credential rejected: generic-credential-sentinel",
            "credentials rejected: generic-credentials-sentinel",
            "password rejected: password-sentinel",
            "publicKeysB64 rejected: public-key-b64-list-sentinel",
            "secret_b64 rejected: generic-secret-b64-sentinel",
            "values_b64 rejected: inline-values-b64-sentinel",
            "session_token rejected: session-token-sentinel",
            "sessionToken rejected: session-token-sentinel",
            "key_material rejected: key-material-sentinel",
            "keyMaterialB64 rejected: key-material-b64-camel-sentinel",
            "master_key rejected: master-key-sentinel",
            "masterKeyB64 rejected: master-key-b64-camel-sentinel",
            "material_b64 rejected: material-b64-sentinel",
            "resource_key rejected: resource-key-sentinel",
            "resourceKeyB64 rejected: resource-key-b64-camel-sentinel",
            "root_key rejected: root-key-sentinel",
            "rootKeyB64 rejected: root-key-b64-camel-sentinel",
            "wrapped_resource_key rejected: wrapped-resource-key-sentinel",
            "wrappedResourceKeyB64 rejected: wrapped-resource-key-b64-camel-sentinel",
            "wrapping_key rejected: wrapping-key-sentinel",
            "wrappingKeyB64 rejected: wrapping-key-b64-camel-sentinel",
            "node_aead rejected: node-aead-key-sentinel",
            "nodeAeadKey rejected: node-aead-key-camel-sentinel",
            "bucket_aead rejected: bucket-aead-key-sentinel",
            "bucketAeadKey rejected: bucket-aead-key-camel-sentinel",
            "payload_token rejected: payload-token-key-sentinel",
            "payloadTokenKey rejected: payload-token-key-camel-sentinel",
            "blind_result rejected: blind-result-key-sentinel",
            "blindResultKey rejected: blind-result-key-camel-sentinel",
            "client_state_key rejected: client-state-key-sentinel",
            "clientStateKey rejected: client-state-key-camel-sentinel",
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
            "private HNSW read failed bucket_id=private-bucket-id-singular-sentinel",
            "private HNSW read failed bucket_ids=[private-bucket-id-sentinel]",
            "private HNSW read failed bucketIdCount=private-bucket-id-count-sentinel",
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
            "private HNSW read failed accessCount=private-access-count-sentinel",
            "private HNSW read failed accessCounts=private-access-counts-sentinel",
            "private HNSW read failed path_counts=private-path-count-sentinel",
            "private HNSW read failed pathCounts=private-path-counts-sentinel",
            "private HNSW read failed requestedPathCount=private-requested-path-count-sentinel",
            "private HNSW read failed requestedPathCounts=private-requested-path-counts-sentinel",
            "private result ORAM read failed payload_fetch_token=private-fetch-token-sentinel",
            "private result ORAM read failed payload_fetch_tokens=private-fetch-tokens-sentinel",
            "private result ORAM read failed point_token=private-point-token-sentinel",
            "private result ORAM read failed point_tokens=private-point-tokens-sentinel",
            "private result ORAM read failed payload_plaintext=private-payload-sentinel",
            "private result ORAM read failed tokenPositionMap=private-token-position-sentinel",
            "private result ORAM read failed tokenPositionMapBackup=private-token-position-backup-singular-sentinel",
            "private result ORAM read failed tokenPositionMapBackups=private-token-position-backup-sentinel",
            "private result ORAM read failed token_position_maps=private-token-position-maps-sentinel",
            "private result ORAM read failed token_position_map_snapshots=private-token-position-map-snapshots-sentinel",
            "private result ORAM read failed readBucketId=private-read-bucket-id-singular-sentinel",
            "private result ORAM read failed readBucketIds=private-read-bucket-ids-sentinel",
            "private result ORAM read failed readBucketIdCounts=private-read-bucket-id-counts-sentinel",
            "private result ORAM read failed read_bucket_id_sequence=private-read-bucket-sequence-sentinel",
            "private result ORAM read failed requestedBucketCount=private-requested-bucket-count-sentinel",
            "private result ORAM read failed requestedBucketCounts=private-requested-bucket-counts-sentinel",
            "private result ORAM read failed returned_bucket_counts=private-returned-bucket-count-sentinel",
            "private result ORAM read failed returnedBucketCounts=private-returned-bucket-counts-sentinel",
            "private ORAM proof failed sibling_hash=private-sibling-hash-sentinel",
            "private ORAM commit failed updatedBucket=private-updated-bucket-sentinel",
            "private ORAM commit failed updated_bucket=private-updated-bucket-snake-sentinel",
            "private ORAM commit failed updated_bucket_ids=private-updated-bucket-id-sentinel",
            "private ORAM commit failed updatedBucketCount=private-updated-bucket-count-sentinel",
            "private ORAM commit failed updatedBucketCounts=private-updated-bucket-counts-sentinel",
            "private ORAM commit failed writeback_bucket_counts=private-writeback-bucket-count-sentinel",
            "private ORAM commit failed writebackBucketCounts=private-writeback-bucket-counts-sentinel",
            "private ORAM signature failed owner_signing_key_id=private-owner-signing-key-sentinel",
            "private ORAM signature failed ownerSigningKeyIds=private-owner-signing-key-camel-sentinel",
            "private ORAM signature failed signing_key_id=private-signing-key-sentinel",
            "private ORAM signature failed signingKeyIds=private-signing-key-camel-sentinel",
            "private ORAM signature failed signature_public_keys=private-signature-public-keys-sentinel",
            "private ORAM signature failed signaturePublicKeys=private-signature-public-keys-camel-sentinel",
            "private ORAM client backup failed clientStateSnapshot=private-client-state-snapshot-camel-sentinel",
            "private ORAM client backup failed clientStateSnapshots=private-client-state-snapshots-camel-sentinel",
            "private ORAM client backup failed client_state_snapshot=private-client-state-snapshot-snake-sentinel",
            "private ORAM client backup failed client_state_snapshots=private-client-state-snapshots-snake-sentinel",
            "private ORAM client backup failed clientStateBackup=private-client-state-backup-camel-sentinel",
            "private ORAM client backup failed client_state_backup=private-client-state-backup-snake-sentinel",
            "private ORAM client backup failed clientStateBackups=private-client-state-backups-sentinel",
            "private ORAM client backup failed encryptedClientStateSnapshot=private-encrypted-client-state-snapshot-camel-sentinel",
            "private ORAM client backup failed encryptedClientStateSnapshots=private-encrypted-client-state-snapshots-camel-sentinel",
            "private ORAM client backup failed encrypted_client_state_snapshot=private-encrypted-client-state-snapshot-snake-sentinel",
            "private ORAM client backup failed encrypted_client_state_snapshots=private-encrypted-client-state-snapshots-snake-sentinel",
            "private ORAM client backup failed encryptedClientStateBackup=private-encrypted-client-state-backup-camel-sentinel",
            "private ORAM client backup failed encrypted_client_state_backup=private-encrypted-client-state-backup-snake-sentinel",
            "private ORAM client backup failed clientStateCiphertext=private-client-state-ciphertext-sentinel",
            "private ORAM client backup failed client_state_ciphertexts=private-client-state-ciphertexts-sentinel",
            "private ORAM client backup failed client_state_ciphertext_sha256=private-client-state-ciphertext-sha256-sentinel",
            "private ORAM client backup failed client_state_ciphertexts_sha256=private-client-state-ciphertexts-sha256-sentinel",
            "private ORAM client backup failed clientStateCiphertextSha256=private-client-state-ciphertext-sha256-camel-sentinel",
            "private ORAM client backup failed clientStateCiphertextsSha256=private-client-state-ciphertexts-sha256-camel-sentinel",
            "private ORAM client backup failed clientStateCiphertextHash=private-client-state-ciphertext-hash-sentinel",
            "private ORAM client backup failed clientStateCiphertextHashes=private-client-state-ciphertext-hashes-sentinel",
            "private ORAM client backup failed client_state_ciphertext_hashes=private-client-state-ciphertext-hashes-snake-sentinel",
            "private ORAM client backup failed encryptedClientStateCiphertext=private-encrypted-client-state-ciphertext-sentinel",
            "private ORAM client backup failed encrypted_client_state_ciphertexts=private-encrypted-client-state-ciphertexts-sentinel",
            "private ORAM client backup failed encrypted_client_state_ciphertext_sha256=private-encrypted-client-state-ciphertext-sha256-sentinel",
            "private ORAM client backup failed encrypted_client_state_ciphertexts_sha256=private-encrypted-client-state-ciphertexts-sha256-sentinel",
            "private ORAM client backup failed encryptedClientStateCiphertextSha256=private-encrypted-client-state-ciphertext-sha256-camel-sentinel",
            "private ORAM client backup failed encryptedClientStateCiphertextsSha256=private-encrypted-client-state-ciphertexts-sha256-camel-sentinel",
            "private ORAM client backup failed encrypted_client_state_ciphertext_hash=private-encrypted-client-state-ciphertext-hash-snake-sentinel",
            "private ORAM client backup failed encrypted_client_state_ciphertext_hashes=private-encrypted-client-state-ciphertext-hashes-snake-sentinel",
            "private ORAM client backup failed encryptedClientStateCiphertextHash=private-encrypted-client-state-ciphertext-hash-sentinel",
            "private ORAM client backup failed encryptedClientStateCiphertextHashes=private-encrypted-client-state-ciphertext-hashes-sentinel",
            "private ORAM client backup failed stateCiphertext=private-state-ciphertext-sentinel",
            "private ORAM client backup failed state_ciphertext=private-state-ciphertext-snake-sentinel",
            "private ORAM client backup failed state_ciphertexts=private-state-ciphertexts-sentinel",
            "private ORAM client backup failed state_ciphertext_sha256=private-state-ciphertext-sha256-sentinel",
            "private ORAM client backup failed state_ciphertexts_sha256=private-state-ciphertexts-sha256-sentinel",
            "private ORAM client backup failed stateCiphertextSha256=private-state-ciphertext-sha256-camel-sentinel",
            "private ORAM client backup failed stateCiphertextsSha256=private-state-ciphertexts-sha256-camel-sentinel",
            "private ORAM client backup failed stateCiphertextHash=private-state-ciphertext-hash-sentinel",
            "private ORAM client backup failed stateCiphertextHashes=private-state-ciphertext-hashes-sentinel",
            "private ORAM client backup failed state_ciphertext_hash=private-state-ciphertext-hash-snake-sentinel",
            "private ORAM client backup failed state_ciphertext_hashes=private-state-ciphertext-hashes-snake-sentinel",
            "private ORAM client backup failed oram_position_maps=private-oram-position-maps-sentinel",
            "private ORAM client backup failed oram_position_map_snapshots=private-oram-position-map-snapshots-sentinel",
            "private ORAM client backup failed position_maps=private-position-maps-sentinel",
            "private ORAM client backup failed position_map_snapshots=private-position-map-snapshots-sentinel",
            "private ORAM client backup failed stash_snapshots=private-stash-snapshots-sentinel",
            "private ORAM client backup failed stashBackup=private-stash-backup-sentinel",
            "private ORAM client backup failed stashBackups=private-stash-backups-sentinel",
        ] {
            let redacted = redact_audit_error(error);

            assert!(redacted.contains("redacted"), "{redacted}");
            assert!(!redacted.contains("sentinel"), "{redacted}");
        }

        for marker in [
            "accessed_leaf_labels",
            "access_paths",
            "bucket_commitment",
            "bucket_commitments",
            "bucket_plaintexts",
            "candidate_nodes",
            "candidate_distances",
            "entry_node_id",
            "entry_node_ids",
            "leaf_commitment",
            "leaf_commitments",
            "leaf_counts",
            "level_masks",
            "merkle_proofs",
            "neighbor_counts",
            "node_plaintexts",
            "read_buckets",
            "result_counts",
            "root_hashes",
            "sibling_hashes",
            "updated_bucket",
            "updated_bucket_commitments",
            "updated_buckets",
            "visited_node_id",
            "visited_node_ids",
        ] {
            let redacted = redact_audit_error(&format!("{marker}=private-{marker}-sentinel"));

            assert!(redacted.contains("redacted"), "{redacted}");
            assert!(!redacted.contains("sentinel"), "{redacted}");
        }
    }
}
