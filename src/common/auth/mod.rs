use std::fmt::Display;
use std::sync::Arc;

use chrono::Utc;
use collection::operations::shard_selector_internal::ShardSelectorInternal;
use common::counter::hardware_accumulator::HwMeasurementAcc;
use itertools::Itertools;
use segment::types::{WithPayloadInterface, WithVector};
use shard::scroll::ScrollRequestInternal;
use storage::audit::{AuditEvent, AuditResult, audit_log, is_audit_enabled};
use storage::content_manager::errors::StorageError;
use storage::content_manager::toc::TableOfContent;
use storage::rbac::Access;

use self::claims::{Claims, ValueExists};
use self::jwt_parser::JwtParser;
use super::error_reporting::redact_crypto_material_for_report;
use super::strings::ct_eq;
use crate::common::inference::api_keys::InferenceToken;
use crate::settings::ServiceConfig;
pub mod claims;
pub mod jwt_parser;

// Re-export Auth and AuthType from storage crate.
pub use storage::rbac::AuthType;
pub use storage::rbac::auth::Auth;

pub const HTTP_HEADER_API_KEY: &str = "api-key";

/// The API keys used for auth
#[derive(Clone)]
pub struct AuthKeys {
    /// A key allowing Read or Write operations
    read_write: Option<String>,

    /// Alternative to `read_write` key
    alt_read_write: Option<String>,

    /// A key allowing Read operations
    read_only: Option<String>,

    /// A JWT parser, based on the read_write key
    jwt_parser: Option<JwtParser>,

    /// Alternative JWT parser, based on the alt_read_write key
    alt_jwt_parser: Option<JwtParser>,

    /// Table of content, needed to do stateful validation of JWT
    toc: Arc<TableOfContent>,
}

#[derive(Debug)]
pub enum AuthError {
    Unauthorized(String),
    Forbidden(String),
    StorageError(StorageError),
}

impl Display for AuthError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AuthError::Unauthorized(msg) => write!(f, "Unauthorized: {msg}"),
            AuthError::Forbidden(msg) => write!(f, "Forbidden: {msg}"),
            AuthError::StorageError(e) => write!(f, "Storage error: {e}"),
        }
    }
}

/// Log a denied authentication attempt to the audit log when audit is enabled.
/// Used by both REST (actix) and gRPC (tonic) auth middlewares.
pub fn log_denied_auth(
    method: &str,
    remote: Option<String>,
    tracing_id: Option<String>,
    error: &AuthError,
) {
    if is_audit_enabled() {
        audit_log(AuditEvent {
            timestamp: Utc::now(),
            method: method.to_string(),
            auth_type: AuthType::None,
            subject: None,
            remote,
            collection: None,
            tracing_id,
            result: AuditResult::Denied,
            error: Some(redacted_denied_auth_error(error)),
            metadata: Default::default(),
        });
    }
}

fn redacted_denied_auth_error(error: &AuthError) -> String {
    let rendered = error.to_string();
    let redacted = redact_crypto_material_for_report(&rendered);
    if redacted == rendered {
        redacted
    } else {
        "[redacted: crypto material omitted from audit error]".to_string()
    }
}

impl AuthKeys {
    fn get_jwt_parser(service_config: &ServiceConfig) -> (Option<JwtParser>, Option<JwtParser>) {
        if service_config.jwt_rbac.unwrap_or_default() {
            (
                service_config
                    .api_key
                    .as_ref()
                    .map(|secret| JwtParser::new(secret)),
                service_config
                    .alt_api_key
                    .as_ref()
                    .map(|secret| JwtParser::new(secret)),
            )
        } else {
            (None, None)
        }
    }

    /// Defines the auth scheme given the service config
    ///
    /// Returns None if no scheme is specified.
    pub fn try_create(service_config: &ServiceConfig, toc: Arc<TableOfContent>) -> Option<Self> {
        match (
            service_config.api_key.clone(),
            service_config.alt_api_key.clone(),
            service_config.read_only_api_key.clone(),
        ) {
            (None, None, None) => None,
            (read_write, alt_read_write, read_only) => {
                let (jwt_parser, alt_jwt_parser) = Self::get_jwt_parser(service_config);

                Some(Self {
                    read_write,
                    alt_read_write,
                    read_only,
                    jwt_parser,
                    alt_jwt_parser,
                    toc,
                })
            }
        }
    }

    /// Validate that the specified request is allowed for given keys.
    ///
    /// Returns `(Access, InferenceToken, AuthType, Option<subject>)`.
    pub async fn validate_request<'a>(
        &self,
        get_header: impl Fn(&'a str) -> Option<&'a str>,
    ) -> Result<(Access, InferenceToken, AuthType, Option<String>), AuthError> {
        let Some(key) = get_header(HTTP_HEADER_API_KEY)
            .or_else(|| get_header("authorization").and_then(|v| v.strip_prefix("Bearer ")))
        else {
            return Err(AuthError::Unauthorized(
                "Must provide an API key or an Authorization bearer token".to_string(),
            ));
        };

        if self.can_write(key) {
            return Ok((
                Access::full("Read-write access by key"),
                InferenceToken(None),
                AuthType::ApiKey,
                None,
            ));
        }

        if self.can_read(key) {
            return Ok((
                Access::full_ro("Read-only access by key"),
                InferenceToken(None),
                AuthType::ApiKey,
                None,
            ));
        }

        let (claims, errors): (Vec<_>, Vec<_>) =
            [self.jwt_parser.as_ref(), self.alt_jwt_parser.as_ref()]
                .into_iter()
                .flatten()
                .filter_map(|p| p.decode(key))
                .partition_result();

        if let Some(claims) = claims.into_iter().next() {
            let Claims {
                sub,
                exp: _, // already validated on decoding
                access,
                value_exists,
                subject,
            } = claims;

            if let Some(value_exists) = value_exists {
                self.validate_value_exists(&value_exists).await?;
            }

            return Ok((access, InferenceToken(sub), AuthType::Jwt, subject));
        }

        // JTW parser exists, but can't decode the token
        if let Some(error) = errors.into_iter().next() {
            return Err(error);
        }

        // No JTW parser configured
        Err(AuthError::Unauthorized(
            "Invalid API key or JWT".to_string(),
        ))
    }

    async fn validate_value_exists(&self, value_exists: &ValueExists) -> Result<(), AuthError> {
        let scroll_req = ScrollRequestInternal {
            offset: None,
            limit: Some(1),
            filter: Some(value_exists.to_filter()),
            with_payload: Some(WithPayloadInterface::Bool(false)),
            with_vector: WithVector::Bool(false),
            order_by: None,
        };

        let res = self
            .toc
            .scroll(
                value_exists.get_collection(),
                scroll_req,
                None,
                None, // no timeout
                ShardSelectorInternal::All,
                Auth::new_internal(Access::full("JWT stateful validation")),
                HwMeasurementAcc::disposable(),
            )
            .await
            .map_err(|e| match e {
                StorageError::NotFound { .. } => {
                    AuthError::Forbidden("Invalid JWT, stateful validation failed".to_string())
                }
                _ => AuthError::StorageError(e),
            })?;

        if res.points.is_empty() {
            return Err(AuthError::Unauthorized(
                "Invalid JWT, stateful validation failed".to_string(),
            ));
        };

        Ok(())
    }

    /// Check if a key is allowed to read
    #[inline]
    fn can_read(&self, key: &str) -> bool {
        self.read_only
            .as_ref()
            .is_some_and(|ro_key| ct_eq(ro_key, key))
    }

    /// Check if a key is allowed to write
    #[inline]
    fn can_write(&self, key: &str) -> bool {
        let can_write = self
            .read_write
            .as_ref()
            .is_some_and(|rw_key| ct_eq(rw_key, key));
        let alt_can_write = self
            .alt_read_write
            .as_ref()
            .is_some_and(|alt_rw_key| ct_eq(alt_rw_key, key));
        can_write || alt_can_write
    }
}

#[cfg(test)]
mod tests {
    use super::{AuthError, redacted_denied_auth_error};

    #[test]
    fn denied_auth_audit_error_redacts_private_oram_key_ids() {
        let error = AuthError::Forbidden(
            "private ORAM signature failed owner_signing_key_id=owner-signing-key-sentinel \
             signingKeyIds=signing-key-camel-sentinel \
             signature_public_keys=signature-public-keys-sentinel"
                .to_string(),
        );

        let redacted = redacted_denied_auth_error(&error);

        assert_eq!(
            redacted,
            "[redacted: crypto material omitted from audit error]"
        );
        assert!(!redacted.contains("owner-signing-key-sentinel"));
        assert!(!redacted.contains("signing-key-camel-sentinel"));
        assert!(!redacted.contains("signature-public-keys-sentinel"));
    }

    #[test]
    fn denied_auth_audit_error_redacts_private_oram_access_pattern_aliases() {
        let error = AuthError::Forbidden(
            "private HNSW read failed readPath=read-path-camel-sentinel \
             readPathLabel=read-path-label-camel-sentinel \
             accessCount=access-count-camel-sentinel \
             accessCounts=access-counts-camel-sentinel \
             access_count=access-count-snake-sentinel \
             access_counts=access-counts-snake-sentinel \
             accessVolume=access-volume-camel-sentinel \
             accessVolumes=access-volumes-camel-sentinel \
             accessVolumeCount=access-volume-count-camel-sentinel \
             accessVolumeCounts=access-volume-counts-camel-sentinel \
             accessVolumeLength=access-volume-length-camel-sentinel \
             accessVolumeLengths=access-volume-lengths-camel-sentinel \
             access_volume=access-volume-snake-sentinel \
             access_volumes=access-volumes-snake-sentinel \
             access_volume_len=access-volume-len-snake-sentinel \
             access_volume_count=access-volume-count-snake-sentinel \
             access_volume_counts=access-volume-counts-snake-sentinel \
             access_volume_length=access-volume-length-snake-sentinel \
             access_volume_lengths=access-volume-lengths-snake-sentinel \
             proof_value=proof-value-snake-sentinel \
             proofValue=proof-value-camel-sentinel \
             proof_values=proof-values-snake-sentinel \
             proofValues=proof-values-camel-sentinel \
             pathCount=path-count-camel-sentinel \
             pathCounts=path-counts-camel-sentinel \
             bucketIdCounts=bucket-id-counts-camel-sentinel \
             readBucketCount=read-bucket-count-camel-sentinel \
             readBucketCounts=read-bucket-counts-camel-sentinel \
             readBucketIdCount=read-bucket-id-count-camel-sentinel \
             requestedPathCount=requested-path-count-camel-sentinel \
             requestedPathCounts=requested-path-counts-camel-sentinel \
             requestedBucketCount=requested-bucket-count-camel-sentinel \
             requestedBucketCounts=requested-bucket-counts-camel-sentinel \
             readBucketId=read-bucket-id-camel-singular-sentinel \
             readBucketIdCounts=read-bucket-id-counts-camel-sentinel \
             readBucketIds=read-bucket-ids-camel-sentinel \
             ciphertextSha256=ciphertext-sha256-camel-sentinel \
             ciphertext_sha256=ciphertext-sha256-snake-sentinel \
             ciphertext_sha256_b64=ciphertext-sha256-b64-snake-sentinel \
             ciphertextsSha256=ciphertexts-sha256-camel-sentinel \
             ciphertexts_sha256=ciphertexts-sha256-snake-sentinel \
             bucketCommitment=bucket-commitment-camel-sentinel \
             bucketCommitments=bucket-commitments-camel-sentinel \
             bucket_commitment=bucket-commitment-snake-sentinel \
             bucket_commitments=bucket-commitments-snake-sentinel \
             updatedBucketCommitment=updated-bucket-commitment-camel-sentinel \
             updatedBucketCommitments=updated-bucket-commitments-camel-sentinel \
             updated_bucket_commitment=updated-bucket-commitment-snake-sentinel \
             updated_bucket_commitments=updated-bucket-commitments-snake-sentinel \
             returnedBucketCount=returned-bucket-count-camel-sentinel \
             returnedBucketCounts=returned-bucket-counts-camel-sentinel \
             updatedBucketCount=updated-bucket-count-camel-sentinel \
             updatedBucketCounts=updated-bucket-counts-camel-sentinel \
             writebackBucketCount=writeback-bucket-count-camel-sentinel \
             writebackBucketCounts=writeback-bucket-counts-camel-sentinel \
             clientStateSnapshot=client-state-snapshot-camel-sentinel \
             clientStateSnapshots=client-state-snapshots-camel-sentinel \
             client_state_snapshot=client-state-snapshot-snake-sentinel \
             client_state_snapshots=client-state-snapshots-snake-sentinel \
             clientStates=client-states-camel-sentinel \
             client_states=client-states-snake-sentinel \
             clientStateBackup=client-state-backup-camel-sentinel \
             client_state_backup=client-state-backup-snake-sentinel \
             clientStateBackups=client-state-backups-camel-sentinel \
             client_state_backups=client-state-backups-snake-sentinel \
             encryptedClientStateSnapshot=encrypted-client-state-snapshot-camel-sentinel \
             encryptedClientStateSnapshots=encrypted-client-state-snapshots-camel-sentinel \
             encryptedClientStateBackup=encrypted-client-state-backup-camel-sentinel \
             encryptedClientStateBackups=encrypted-client-state-backups-camel-sentinel \
             encrypted_client_state_backups=encrypted-client-state-backups-snake-sentinel \
             encrypted_client_state_snapshot.bin=encrypted-client-state-snapshot-bin-sentinel \
             encrypted_client_state_snapshot.json=encrypted-client-state-snapshot-json-sentinel \
             encrypted_client_state_snapshots.json=encrypted-client-state-snapshots-json-sentinel \
             clientStateCiphertext=client-state-ciphertext-camel-sentinel \
             clientStateCiphertextHash=client-state-ciphertext-hash-camel-sentinel \
             clientStateCiphertextHashes=client-state-ciphertext-hashes-camel-sentinel \
             client_state_ciphertexts=client-state-ciphertexts-snake-sentinel \
             client_state_ciphertext_sha256=client-state-ciphertext-sha256-snake-sentinel \
             client_state_ciphertext_sha256.bin=client-state-ciphertext-sha256-bin-sentinel \
             client_state_ciphertext_sha256.json=client-state-ciphertext-sha256-json-sentinel \
             client_state_ciphertexts_sha256=client-state-ciphertexts-sha256-snake-sentinel \
             client_state_ciphertexts_sha256.bin=client-state-ciphertexts-sha256-bin-sentinel \
             client_state_ciphertexts_sha256.json=client-state-ciphertexts-sha256-json-sentinel \
             clientStateCiphertextSha256=client-state-ciphertext-sha256-camel-sentinel \
             clientStateCiphertextsSha256=client-state-ciphertexts-sha256-camel-sentinel \
             client_state_ciphertext=client-state-ciphertext-snake-sentinel \
             client_state_ciphertext_hash=client-state-ciphertext-hash-snake-sentinel \
             client_state_ciphertext_hash.bin=client-state-ciphertext-hash-bin-sentinel \
             client_state_ciphertext_hash.json=client-state-ciphertext-hash-json-sentinel \
             client_state_ciphertext_hashes.bin=client-state-ciphertext-hashes-bin-sentinel \
             client_state_ciphertext_hashes.json=client-state-ciphertext-hashes-json-sentinel \
             client_state_ciphertext_hashes=client-state-ciphertext-hashes-snake-sentinel \
             encrypted_client_state=encrypted-client-state-snake-sentinel \
             encrypted.client.state=encrypted-client-state-dotted-sentinel \
             encrypted_client_state.json=encrypted-client-state-json-sentinel \
             encrypted_client_state_backup=encrypted-client-state-backup-snake-sentinel \
             encrypted_client_state_snapshot=encrypted-client-state-snapshot-snake-sentinel \
             encrypted_client_state_snapshots=encrypted-client-state-snapshots-snake-sentinel \
             encrypted_client_state_ciphertext=encrypted-client-state-ciphertext-snake-sentinel \
             encrypted_client_state_ciphertexts=encrypted-client-state-ciphertexts-snake-sentinel \
             encrypted_client_state_ciphertext_sha256=encrypted-client-state-ciphertext-sha256-snake-sentinel \
             encrypted_client_state_ciphertext_sha256.bin=encrypted-client-state-ciphertext-sha256-bin-sentinel \
             encrypted_client_state_ciphertext_sha256.json=encrypted-client-state-ciphertext-sha256-json-sentinel \
             encrypted_client_state_ciphertexts_sha256=encrypted-client-state-ciphertexts-sha256-snake-sentinel \
             encrypted_client_state_ciphertexts_sha256.bin=encrypted-client-state-ciphertexts-sha256-bin-sentinel \
             encrypted_client_state_ciphertexts_sha256.json=encrypted-client-state-ciphertexts-sha256-json-sentinel \
             encryptedClientStateCiphertextSha256=encrypted-client-state-ciphertext-sha256-camel-sentinel \
             encryptedClientStateCiphertextsSha256=encrypted-client-state-ciphertexts-sha256-camel-sentinel \
             encryptedClientStateCiphertext=encrypted-client-state-ciphertext-camel-sentinel \
             encrypted_client_state_ciphertext_hash=encrypted-client-state-ciphertext-hash-snake-sentinel \
             encrypted_client_state_ciphertext_hash.bin=encrypted-client-state-ciphertext-hash-bin-sentinel \
             encrypted_client_state_ciphertext_hash.json=encrypted-client-state-ciphertext-hash-json-sentinel \
             encrypted_client_state_ciphertext_hashes.bin=encrypted-client-state-ciphertext-hashes-bin-sentinel \
             encrypted_client_state_ciphertext_hashes.json=encrypted-client-state-ciphertext-hashes-json-sentinel \
             encrypted_client_state_ciphertext_hashes=encrypted-client-state-ciphertext-hashes-snake-sentinel \
             encryptedClientStateCiphertextHash=encrypted-client-state-ciphertext-hash-camel-sentinel \
             encryptedClientStateCiphertextHashes=encrypted-client-state-ciphertext-hashes-camel-sentinel \
             oramPositionMapBackup=oram-position-map-backup-camel-sentinel \
             oram_position_map_backup=oram-position-map-backup-snake-sentinel \
             oramPositionMapBackups=oram-position-map-backups-camel-sentinel \
             oram_position_maps=oram-position-maps-snake-sentinel \
             oram_position_map_snapshots=oram-position-map-snapshots-snake-sentinel \
             positionMapBackup=position-map-backup-camel-sentinel \
             position_map_backup=position-map-backup-snake-sentinel \
             positionMapBackups=position-map-backups-camel-sentinel \
             position_map_backups=position-map-backups-snake-sentinel \
             position_maps=position-maps-snake-sentinel \
             position_map_snapshots=position-map-snapshots-snake-sentinel \
             stashBackup=stash-backup-camel-sentinel \
             stashBackup.json=stash-backup-json-sentinel \
             stashBackups=stash-backups-camel-sentinel \
             stashBackups.json=stash-backups-json-sentinel \
             stash_snapshots=stash-snapshots-snake-sentinel \
             stateCiphertext=state-ciphertext-camel-sentinel \
             state_ciphertexts=state-ciphertexts-snake-sentinel \
             state_ciphertext_sha256=state-ciphertext-sha256-snake-sentinel \
             state_ciphertext_sha256.bin=state-ciphertext-sha256-bin-sentinel \
             state_ciphertext_sha256.json=state-ciphertext-sha256-json-sentinel \
             state_ciphertexts_sha256=state-ciphertexts-sha256-snake-sentinel \
             state_ciphertexts_sha256.bin=state-ciphertexts-sha256-bin-sentinel \
             state_ciphertexts_sha256.json=state-ciphertexts-sha256-json-sentinel \
             stateCiphertextSha256=state-ciphertext-sha256-camel-sentinel \
             stateCiphertextsSha256=state-ciphertexts-sha256-camel-sentinel \
             stateCiphertextHash=state-ciphertext-hash-camel-sentinel \
             stateCiphertextHashes=state-ciphertext-hashes-camel-sentinel \
             state_ciphertext=state-ciphertext-snake-sentinel \
             state_ciphertext_hash=state-ciphertext-hash-snake-sentinel \
             state_ciphertext_hash.bin=state-ciphertext-hash-bin-sentinel \
             state_ciphertext_hash.json=state-ciphertext-hash-json-sentinel \
             state_ciphertext_hashes=state-ciphertext-hashes-snake-sentinel \
             state_ciphertext_hashes.bin=state-ciphertext-hashes-bin-sentinel \
             state_ciphertext_hashes.json=state-ciphertext-hashes-json-sentinel \
             token_maps=token-maps-snake-sentinel \
             token_map_snapshots=token-map-snapshots-snake-sentinel \
             tokenMapBackup=token-map-backup-camel-singular-sentinel \
             token_map_backup=token-map-backup-snake-singular-sentinel \
             token_map_backups=token-map-backups-snake-sentinel \
             tokenMapBackups=token-map-backups-camel-sentinel \
             token_position_maps=token-position-maps-snake-sentinel \
             token_position_map_snapshots=token-position-map-snapshots-snake-sentinel \
             tokenPositionMapBackup=token-position-map-backup-camel-singular-sentinel \
             token_position_map_backup=token-position-map-backup-snake-singular-sentinel \
             token_position_map_backups=token-position-map-backups-snake-sentinel \
             tokenPositionMapBackups=token-position-map-backups-camel-sentinel"
                .to_string(),
        );

        let redacted = redacted_denied_auth_error(&error);

        assert_eq!(
            redacted,
            "[redacted: crypto material omitted from audit error]"
        );
        assert!(!redacted.contains("read-path-camel-sentinel"));
        assert!(!redacted.contains("read-path-label-camel-sentinel"));
        assert!(!redacted.contains("access-count-camel-sentinel"));
        assert!(!redacted.contains("access-counts-camel-sentinel"));
        assert!(!redacted.contains("access-count-snake-sentinel"));
        assert!(!redacted.contains("access-counts-snake-sentinel"));
        assert!(!redacted.contains("access-volume-camel-sentinel"));
        assert!(!redacted.contains("access-volume-count-camel-sentinel"));
        assert!(!redacted.contains("access-volume-counts-camel-sentinel"));
        assert!(!redacted.contains("access-volume-length-camel-sentinel"));
        assert!(!redacted.contains("access-volume-lengths-camel-sentinel"));
        assert!(!redacted.contains("access-volume-snake-sentinel"));
        assert!(!redacted.contains("access-volume-len-snake-sentinel"));
        assert!(!redacted.contains("access-volume-count-snake-sentinel"));
        assert!(!redacted.contains("access-volume-counts-snake-sentinel"));
        assert!(!redacted.contains("access-volume-length-snake-sentinel"));
        assert!(!redacted.contains("proof-value-snake-sentinel"));
        assert!(!redacted.contains("proof-value-camel-sentinel"));
        assert!(!redacted.contains("proof-values-snake-sentinel"));
        assert!(!redacted.contains("path-count-camel-sentinel"));
        assert!(!redacted.contains("path-counts-camel-sentinel"));
        assert!(!redacted.contains("bucket-id-counts-camel-sentinel"));
        assert!(!redacted.contains("read-bucket-count-camel-sentinel"));
        assert!(!redacted.contains("read-bucket-counts-camel-sentinel"));
        assert!(!redacted.contains("read-bucket-id-count-camel-sentinel"));
        assert!(!redacted.contains("requested-path-count-camel-sentinel"));
        assert!(!redacted.contains("requested-path-counts-camel-sentinel"));
        assert!(!redacted.contains("requested-bucket-count-camel-sentinel"));
        assert!(!redacted.contains("requested-bucket-counts-camel-sentinel"));
        assert!(!redacted.contains("read-bucket-id-counts-camel-sentinel"));
        assert!(!redacted.contains("read-bucket-ids-camel-sentinel"));
        assert!(!redacted.contains("ciphertext-sha256-camel-sentinel"));
        assert!(!redacted.contains("ciphertext-sha256-snake-sentinel"));
        assert!(!redacted.contains("ciphertext-sha256-b64-snake-sentinel"));
        assert!(!redacted.contains("ciphertexts-sha256-camel-sentinel"));
        assert!(!redacted.contains("ciphertexts-sha256-snake-sentinel"));
        assert!(!redacted.contains("bucket-commitment-camel-sentinel"));
        assert!(!redacted.contains("bucket-commitments-camel-sentinel"));
        assert!(!redacted.contains("bucket-commitment-snake-sentinel"));
        assert!(!redacted.contains("bucket-commitments-snake-sentinel"));
        assert!(!redacted.contains("updated-bucket-commitment-camel-sentinel"));
        assert!(!redacted.contains("updated-bucket-commitments-camel-sentinel"));
        assert!(!redacted.contains("updated-bucket-commitment-snake-sentinel"));
        assert!(!redacted.contains("updated-bucket-commitments-snake-sentinel"));
        assert!(!redacted.contains("returned-bucket-count-camel-sentinel"));
        assert!(!redacted.contains("returned-bucket-counts-camel-sentinel"));
        assert!(!redacted.contains("updated-bucket-count-camel-sentinel"));
        assert!(!redacted.contains("updated-bucket-counts-camel-sentinel"));
        assert!(!redacted.contains("writeback-bucket-count-camel-sentinel"));
        assert!(!redacted.contains("writeback-bucket-counts-camel-sentinel"));
        assert!(!redacted.contains("client-state-snapshot-camel-sentinel"));
        assert!(!redacted.contains("client-state-snapshots-camel-sentinel"));
        assert!(!redacted.contains("client-state-snapshot-snake-sentinel"));
        assert!(!redacted.contains("client-state-snapshots-snake-sentinel"));
        assert!(!redacted.contains("client-state-backup-camel-sentinel"));
        assert!(!redacted.contains("client-state-backup-snake-sentinel"));
        assert!(!redacted.contains("client-state-backups-camel-sentinel"));
        assert!(!redacted.contains("client-state-backups-snake-sentinel"));
        assert!(!redacted.contains("encrypted-client-state-snapshot-camel-sentinel"));
        assert!(!redacted.contains("encrypted-client-state-snapshots-camel-sentinel"));
        assert!(!redacted.contains("encrypted-client-state-backup-camel-sentinel"));
        assert!(!redacted.contains("encrypted-client-state-backups-camel-sentinel"));
        assert!(!redacted.contains("encrypted-client-state-backups-snake-sentinel"));
        assert!(!redacted.contains("encrypted-client-state-snapshot-bin-sentinel"));
        assert!(!redacted.contains("encrypted-client-state-snapshot-json-sentinel"));
        assert!(!redacted.contains("encrypted-client-state-snapshots-json-sentinel"));
        assert!(!redacted.contains("client-state-ciphertext-camel-sentinel"));
        assert!(!redacted.contains("client-state-ciphertexts-snake-sentinel"));
        assert!(!redacted.contains("client-state-ciphertext-sha256-snake-sentinel"));
        assert!(!redacted.contains("client-state-ciphertext-sha256-bin-sentinel"));
        assert!(!redacted.contains("client-state-ciphertext-sha256-json-sentinel"));
        assert!(!redacted.contains("client-state-ciphertexts-sha256-snake-sentinel"));
        assert!(!redacted.contains("client-state-ciphertexts-sha256-json-sentinel"));
        assert!(!redacted.contains("client-state-ciphertext-sha256-camel-sentinel"));
        assert!(!redacted.contains("client-state-ciphertexts-sha256-camel-sentinel"));
        assert!(!redacted.contains("client-state-ciphertext-hash-camel-sentinel"));
        assert!(!redacted.contains("client-state-ciphertext-hashes-camel-sentinel"));
        assert!(!redacted.contains("client-state-ciphertext-snake-sentinel"));
        assert!(!redacted.contains("client-state-ciphertext-hash-snake-sentinel"));
        assert!(!redacted.contains("client-state-ciphertext-hash-bin-sentinel"));
        assert!(!redacted.contains("client-state-ciphertext-hash-json-sentinel"));
        assert!(!redacted.contains("client-state-ciphertext-hashes-bin-sentinel"));
        assert!(!redacted.contains("client-state-ciphertext-hashes-snake-sentinel"));
        assert!(!redacted.contains("encrypted-client-state-snake-sentinel"));
        assert!(!redacted.contains("encrypted-client-state-dotted-sentinel"));
        assert!(!redacted.contains("encrypted-client-state-json-sentinel"));
        assert!(!redacted.contains("encrypted-client-state-backup-snake-sentinel"));
        assert!(!redacted.contains("encrypted-client-state-snapshot-snake-sentinel"));
        assert!(!redacted.contains("encrypted-client-state-snapshots-snake-sentinel"));
        assert!(!redacted.contains("encrypted-client-state-ciphertext-snake-sentinel"));
        assert!(!redacted.contains("encrypted-client-state-ciphertexts-snake-sentinel"));
        assert!(!redacted.contains("encrypted-client-state-ciphertext-sha256-snake-sentinel"));
        assert!(!redacted.contains("encrypted-client-state-ciphertext-sha256-bin-sentinel"));
        assert!(!redacted.contains("encrypted-client-state-ciphertext-sha256-json-sentinel"));
        assert!(!redacted.contains("encrypted-client-state-ciphertexts-sha256-snake-sentinel"));
        assert!(!redacted.contains("encrypted-client-state-ciphertexts-sha256-bin-sentinel"));
        assert!(!redacted.contains("encrypted-client-state-ciphertexts-sha256-json-sentinel"));
        assert!(!redacted.contains("encrypted-client-state-ciphertext-sha256-camel-sentinel"));
        assert!(!redacted.contains("encrypted-client-state-ciphertexts-sha256-camel-sentinel"));
        assert!(!redacted.contains("encrypted-client-state-ciphertext-camel-sentinel"));
        assert!(!redacted.contains("encrypted-client-state-ciphertext-hash-snake-sentinel"));
        assert!(!redacted.contains("encrypted-client-state-ciphertext-hash-bin-sentinel"));
        assert!(!redacted.contains("encrypted-client-state-ciphertext-hash-json-sentinel"));
        assert!(!redacted.contains("encrypted-client-state-ciphertext-hashes-bin-sentinel"));
        assert!(!redacted.contains("encrypted-client-state-ciphertext-hashes-snake-sentinel"));
        assert!(!redacted.contains("encrypted-client-state-ciphertext-hash-camel-sentinel"));
        assert!(!redacted.contains("encrypted-client-state-ciphertext-hashes-camel-sentinel"));
        assert!(!redacted.contains("oram-position-map-backup-camel-sentinel"));
        assert!(!redacted.contains("oram-position-map-backup-snake-sentinel"));
        assert!(!redacted.contains("oram-position-map-backups-camel-sentinel"));
        assert!(!redacted.contains("oram-position-maps-snake-sentinel"));
        assert!(!redacted.contains("oram-position-map-snapshots-snake-sentinel"));
        assert!(!redacted.contains("position-map-backup-camel-sentinel"));
        assert!(!redacted.contains("position-map-backup-snake-sentinel"));
        assert!(!redacted.contains("position-map-backups-camel-sentinel"));
        assert!(!redacted.contains("position-map-backups-snake-sentinel"));
        assert!(!redacted.contains("position-maps-snake-sentinel"));
        assert!(!redacted.contains("position-map-snapshots-snake-sentinel"));
        assert!(!redacted.contains("stash-backup-camel-sentinel"));
        assert!(!redacted.contains("stash-backup-json-sentinel"));
        assert!(!redacted.contains("stash-backups-camel-sentinel"));
        assert!(!redacted.contains("stash-backups-json-sentinel"));
        assert!(!redacted.contains("stash-snapshots-snake-sentinel"));
        assert!(!redacted.contains("state-ciphertext-camel-sentinel"));
        assert!(!redacted.contains("state-ciphertexts-snake-sentinel"));
        assert!(!redacted.contains("state-ciphertext-sha256-snake-sentinel"));
        assert!(!redacted.contains("state-ciphertext-sha256-bin-sentinel"));
        assert!(!redacted.contains("state-ciphertext-sha256-json-sentinel"));
        assert!(!redacted.contains("state-ciphertexts-sha256-snake-sentinel"));
        assert!(!redacted.contains("state-ciphertexts-sha256-bin-sentinel"));
        assert!(!redacted.contains("state-ciphertexts-sha256-json-sentinel"));
        assert!(!redacted.contains("state-ciphertext-sha256-camel-sentinel"));
        assert!(!redacted.contains("state-ciphertexts-sha256-camel-sentinel"));
        assert!(!redacted.contains("state-ciphertext-hash-camel-sentinel"));
        assert!(!redacted.contains("state-ciphertext-hashes-camel-sentinel"));
        assert!(!redacted.contains("state-ciphertext-snake-sentinel"));
        assert!(!redacted.contains("state-ciphertext-hash-snake-sentinel"));
        assert!(!redacted.contains("state-ciphertext-hash-bin-sentinel"));
        assert!(!redacted.contains("state-ciphertext-hash-json-sentinel"));
        assert!(!redacted.contains("state-ciphertext-hashes-snake-sentinel"));
        assert!(!redacted.contains("state-ciphertext-hashes-bin-sentinel"));
        assert!(!redacted.contains("token-maps-snake-sentinel"));
        assert!(!redacted.contains("token-map-snapshots-snake-sentinel"));
        assert!(!redacted.contains("token-map-backup-camel-singular-sentinel"));
        assert!(!redacted.contains("token-map-backup-snake-singular-sentinel"));
        assert!(!redacted.contains("token-map-backups-snake-sentinel"));
        assert!(!redacted.contains("token-map-backups-camel-sentinel"));
        assert!(!redacted.contains("token-position-maps-snake-sentinel"));
        assert!(!redacted.contains("token-position-map-snapshots-snake-sentinel"));
        assert!(!redacted.contains("token-position-map-backup-camel-singular-sentinel"));
        assert!(!redacted.contains("token-position-map-backup-snake-singular-sentinel"));
        assert!(!redacted.contains("token-position-map-backups-snake-sentinel"));
        assert!(!redacted.contains("token-position-map-backups-camel-sentinel"));
    }

    #[test]
    fn denied_auth_audit_error_preserves_ordinary_denials() {
        let error = AuthError::Forbidden("collection access denied".to_string());

        assert_eq!(
            redacted_denied_auth_error(&error),
            "Forbidden: collection access denied",
        );
    }
}
