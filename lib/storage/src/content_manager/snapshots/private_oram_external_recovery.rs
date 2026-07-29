use std::fmt;
use std::fs::DirBuilder;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use data_encoding::{BASE64URL_NOPAD, HEXLOWER};
use fs_err as fs;
use fs_err::{File, OpenOptions};
use fs4::fs_std::FileExt;
use qdrant_sec::{
    PrivateOramExternalRecoveryCheckpointBundle,
    try_private_oram_external_recovery_checkpoint_signature_message,
    validate_private_oram_external_recovery_checkpoint_shape,
    validate_private_oram_recovery_signature_shape,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::StorageError;

pub const PRIVATE_ORAM_EXTERNAL_RECOVERY_CHUNK_SIZE_BYTES: u64 = 8 * 1024 * 1024;

const PRIVATE_ORAM_EXTERNAL_RECOVERY_DIR: &str = "private_oram_external_recovery";
const PRIVATE_ORAM_EXTERNAL_RECOVERY_STATE_FILE: &str = "state.json";
const PRIVATE_ORAM_EXTERNAL_RECOVERY_SNAPSHOT_FILE: &str = "snapshot.upload";
const PRIVATE_ORAM_EXTERNAL_RECOVERY_LOCK_FILE: &str = "recovery.lock";
const PRIVATE_ORAM_EXTERNAL_RECOVERY_VERIFIED_DIR: &str = "verified_collection";
const PRIVATE_ORAM_EXTERNAL_RECOVERY_VERIFY_TEMP_DIR: &str = "verified_collection.pending";
const PRIVATE_ORAM_EXTERNAL_RECOVERY_STATE_VERSION: u16 = 1;
const PRIVATE_ORAM_EXTERNAL_RECOVERY_STATE_MAX_BYTES: u64 = 16 * 1024 * 1024;
const PRIVATE_ORAM_EXTERNAL_RECOVERY_MAX_SNAPSHOT_BYTES: u64 = 1 << 40;
const PRIVATE_ORAM_SHA256_BASE64URL_LEN: usize = 43;
const PRIVATE_ORAM_SHA256_HEX_LEN: usize = 64;
const PRIVATE_ORAM_OPERATION_TOKEN_BYTES: usize = 32;
const PRIVATE_ORAM_OPERATION_TOKEN_LEN: usize = 43;
const PRIVATE_ORAM_EXTERNAL_RECOVERY_COLLECTION_KEY_DOMAIN: &[u8] =
    b"qdrant-sec/private-oram-external-recovery-staging-key/v1";
const PRIVATE_ORAM_EXTERNAL_RECOVERY_OPERATION_ID_DOMAIN: &[u8] =
    b"qdrant-sec/private-oram-external-recovery-operation-id/v1";
const PRIVATE_ORAM_EXTERNAL_RECOVERY_CHECKPOINT_DIGEST_DOMAIN: &[u8] =
    b"qdrant-sec/private-oram-external-recovery-checkpoint-digest/v1";

#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PrivateOramExternalRecoveryStagingPhase {
    Uploading,
    Verified,
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize)]
pub struct PrivateOramExternalRecoveryStagingStatus {
    pub phase: PrivateOramExternalRecoveryStagingPhase,
    pub backup_generation: u64,
    pub bytes_received: u64,
    pub snapshot_size_bytes: u64,
    pub next_chunk_index: u64,
    pub chunk_size_bytes: u64,
    pub lease_expires_at_unix: u64,
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct PrivateOramExternalRecoveryStagingState {
    version: u16,
    operation_id_hash: String,
    checkpoint_digest: String,
    checkpoint_bundle: PrivateOramExternalRecoveryCheckpointBundle,
    lease_expires_at_unix: u64,
    bytes_received: u64,
    next_chunk_index: u64,
    phase: PrivateOramExternalRecoveryStagingPhase,
}

impl fmt::Debug for PrivateOramExternalRecoveryStagingState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateOramExternalRecoveryStagingState")
            .field("version", &self.version)
            .field("operation_id_hash", &"[redacted]")
            .field("checkpoint_digest", &"[redacted]")
            .field("checkpoint_bundle", &"[redacted]")
            .field("lease_expires_at_unix", &self.lease_expires_at_unix)
            .field("bytes_received", &self.bytes_received)
            .field("next_chunk_index", &self.next_chunk_index)
            .field("phase", &self.phase)
            .finish()
    }
}

impl PrivateOramExternalRecoveryStagingState {
    fn status(&self) -> PrivateOramExternalRecoveryStagingStatus {
        PrivateOramExternalRecoveryStagingStatus {
            phase: self.phase,
            backup_generation: self.checkpoint_bundle.checkpoint.backup_generation,
            bytes_received: self.bytes_received,
            snapshot_size_bytes: self.checkpoint_bundle.checkpoint.snapshot_size_bytes,
            next_chunk_index: self.next_chunk_index,
            chunk_size_bytes: PRIVATE_ORAM_EXTERNAL_RECOVERY_CHUNK_SIZE_BYTES,
            lease_expires_at_unix: self.lease_expires_at_unix,
        }
    }
}

#[derive(Clone)]
pub struct PrivateOramExternalRecoveryStaging {
    storage_path: PathBuf,
    collection_id: String,
    operation_id_hash: String,
}

impl fmt::Debug for PrivateOramExternalRecoveryStaging {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateOramExternalRecoveryStaging")
            .field("storage_path", &"[redacted]")
            .field("collection_id", &"[redacted]")
            .field("operation_id_hash", &"[redacted]")
            .finish()
    }
}

pub struct PrivateOramExternalRecoveryVerification {
    checkpoint_bundle: PrivateOramExternalRecoveryCheckpointBundle,
    snapshot_path: PathBuf,
    verified_collection_path: PathBuf,
    verify_temp_collection_path: PathBuf,
    operation_id_hash: String,
    checkpoint_digest: String,
    archive_identity: FileIdentity,
    _collection_lock: PrivateOramExternalRecoveryLock,
}

impl fmt::Debug for PrivateOramExternalRecoveryVerification {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateOramExternalRecoveryVerification")
            .field("checkpoint_bundle", &"[redacted]")
            .field("snapshot_path", &"[redacted]")
            .field("verified_collection_path", &"[redacted]")
            .field("verify_temp_collection_path", &"[redacted]")
            .field("operation_id_hash", &"[redacted]")
            .field("checkpoint_digest", &"[redacted]")
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct FileIdentity {
    len: u64,
    #[cfg(unix)]
    device: u64,
    #[cfg(unix)]
    inode: u64,
}

struct PrivateOramExternalRecoveryLock {
    _file: std::fs::File,
}

impl PrivateOramExternalRecoveryVerification {
    pub fn checkpoint_bundle(&self) -> &PrivateOramExternalRecoveryCheckpointBundle {
        &self.checkpoint_bundle
    }

    pub fn snapshot_path(&self) -> &Path {
        &self.snapshot_path
    }

    pub fn verified_collection_path(&self) -> &Path {
        &self.verified_collection_path
    }

    pub fn verify_temp_collection_path(&self) -> &Path {
        &self.verify_temp_collection_path
    }

    pub fn reset_verification_output(&self) -> Result<(), StorageError> {
        remove_secure_directory_if_exists(&self.verify_temp_collection_path)?;
        remove_secure_directory_if_exists(&self.verified_collection_path)?;
        ensure_secure_directory(&self.verify_temp_collection_path)
    }

    pub fn promote_verification_output(&self) -> Result<(), StorageError> {
        validate_secure_directory(&self.verify_temp_collection_path)?;
        match fs::symlink_metadata(&self.verified_collection_path) {
            Ok(_) => return Err(invalid_staging_state()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return Err(invalid_staging_state()),
        }
        fs::rename(
            &self.verify_temp_collection_path,
            &self.verified_collection_path,
        )
        .map_err(|_| invalid_staging_state())?;
        common::fs::sync_parent_dir(&self.verified_collection_path)
            .map_err(|_| invalid_staging_state())
    }
}

impl PrivateOramExternalRecoveryStaging {
    pub fn new(
        storage_path: impl Into<PathBuf>,
        collection_id: &str,
        operation_id_hash: &str,
    ) -> Result<Self, StorageError> {
        if collection_id.is_empty() || collection_id.len() > 1024 {
            return Err(invalid_staging_request());
        }
        validate_base64url_sha256(operation_id_hash)?;
        Ok(Self {
            storage_path: storage_path.into(),
            collection_id: collection_id.to_string(),
            operation_id_hash: operation_id_hash.to_string(),
        })
    }

    pub fn begin(
        &self,
        checkpoint_digest: &str,
        checkpoint_bundle: PrivateOramExternalRecoveryCheckpointBundle,
        lease_expires_at_unix: u64,
    ) -> Result<PrivateOramExternalRecoveryStagingStatus, StorageError> {
        validate_base64url_sha256(checkpoint_digest)?;
        validate_private_oram_external_recovery_checkpoint_shape(&checkpoint_bundle.checkpoint)
            .map_err(|_| invalid_staging_request())?;
        validate_private_oram_recovery_signature_shape(&checkpoint_bundle.signature)
            .map_err(|_| invalid_staging_request())?;
        if checkpoint_bundle.checkpoint.collection_id != self.collection_id
            || checkpoint_bundle.checkpoint.snapshot_size_bytes
                > PRIVATE_ORAM_EXTERNAL_RECOVERY_MAX_SNAPSHOT_BYTES
            || checkpoint_bundle.checkpoint.snapshot_size_bytes == 0
            || lease_expires_at_unix == 0
            || private_oram_external_recovery_checkpoint_digest(&checkpoint_bundle)?
                != checkpoint_digest
        {
            return Err(invalid_staging_request());
        }

        self.ensure_collection_directories()?;
        let _collection_lock = self.acquire_collection_lock(true)?;
        ensure_secure_directory(&self.operation_path())?;
        let desired = PrivateOramExternalRecoveryStagingState {
            version: PRIVATE_ORAM_EXTERNAL_RECOVERY_STATE_VERSION,
            operation_id_hash: self.operation_id_hash.clone(),
            checkpoint_digest: checkpoint_digest.to_string(),
            checkpoint_bundle,
            lease_expires_at_unix,
            bytes_received: 0,
            next_chunk_index: 0,
            phase: PrivateOramExternalRecoveryStagingPhase::Uploading,
        };
        validate_state(&desired)?;

        if let Some(mut existing) = self.read_state()? {
            let same_recovery = existing.version == desired.version
                && existing.operation_id_hash == desired.operation_id_hash
                && existing.checkpoint_digest == desired.checkpoint_digest
                && existing.checkpoint_bundle == desired.checkpoint_bundle;
            if !same_recovery || lease_expires_at_unix < existing.lease_expires_at_unix {
                return Err(invalid_staging_state());
            }
            self.reconcile_snapshot_file(&existing)?;
            if lease_expires_at_unix > existing.lease_expires_at_unix {
                existing.lease_expires_at_unix = lease_expires_at_unix;
                self.write_state(&existing)?;
            }
            return Ok(existing.status());
        }

        self.create_empty_snapshot_file()?;
        self.write_state(&desired)?;
        Ok(desired.status())
    }

    pub fn status(&self) -> Result<PrivateOramExternalRecoveryStagingStatus, StorageError> {
        let _collection_lock = self.acquire_collection_lock(false)?;
        let state = self
            .read_state()?
            .ok_or_else(|| StorageError::not_found("private ORAM external recovery not found"))?;
        self.reconcile_snapshot_file(&state)?;
        Ok(state.status())
    }

    pub fn status_for_consensus_lease(
        &self,
        checkpoint_digest: &str,
        backup_generation: u64,
        lease_expires_at_unix: u64,
    ) -> Result<PrivateOramExternalRecoveryStagingStatus, StorageError> {
        validate_base64url_sha256(checkpoint_digest)?;
        let _collection_lock = self.acquire_collection_lock(false)?;
        let mut state = self
            .read_state()?
            .ok_or_else(|| StorageError::not_found("private ORAM external recovery not found"))?;
        self.reconcile_snapshot_file(&state)?;
        if state.checkpoint_digest != checkpoint_digest
            || state.checkpoint_bundle.checkpoint.backup_generation != backup_generation
            || lease_expires_at_unix < state.lease_expires_at_unix
        {
            return Err(invalid_staging_state());
        }
        if lease_expires_at_unix > state.lease_expires_at_unix {
            state.lease_expires_at_unix = lease_expires_at_unix;
            self.write_state(&state)?;
        }
        Ok(state.status())
    }

    pub fn append_chunk(
        &self,
        chunk_index: u64,
        chunk_path: &Path,
        chunk_sha256: &str,
    ) -> Result<PrivateOramExternalRecoveryStagingStatus, StorageError> {
        validate_lowercase_sha256(chunk_sha256)?;
        let _collection_lock = self.acquire_collection_lock(false)?;
        let mut state = self
            .read_state()?
            .ok_or_else(|| StorageError::not_found("private ORAM external recovery not found"))?;
        self.reconcile_snapshot_file(&state)?;
        let total_size = state.checkpoint_bundle.checkpoint.snapshot_size_bytes;
        let expected_offset = chunk_index
            .checked_mul(PRIVATE_ORAM_EXTERNAL_RECOVERY_CHUNK_SIZE_BYTES)
            .ok_or_else(invalid_staging_request)?;
        if expected_offset >= total_size {
            return Err(invalid_staging_request());
        }
        let expected_len =
            (total_size - expected_offset).min(PRIVATE_ORAM_EXTERNAL_RECOVERY_CHUNK_SIZE_BYTES);
        let mut chunk = open_regular_file(chunk_path, false, None)?;
        let chunk_identity = file_identity(&chunk)?;
        if chunk_identity.len != expected_len {
            return Err(invalid_staging_request());
        }
        let actual_chunk_sha256 = lowercase_sha256_reader(&mut chunk)?;
        if actual_chunk_sha256 != chunk_sha256 {
            return Err(StorageError::bad_request(
                "private ORAM external recovery chunk hash mismatch",
            ));
        }

        if chunk_index < state.next_chunk_index {
            let mut snapshot = self.open_snapshot_file(false)?;
            snapshot.seek(SeekFrom::Start(expected_offset))?;
            let existing_sha256 = lowercase_sha256_reader_limited(&mut snapshot, expected_len)?;
            if existing_sha256 != chunk_sha256 {
                return Err(StorageError::bad_request(
                    "private ORAM external recovery duplicate chunk does not match",
                ));
            }
            return Ok(state.status());
        }
        if chunk_index != state.next_chunk_index
            || expected_offset != state.bytes_received
            || state.phase != PrivateOramExternalRecoveryStagingPhase::Uploading
        {
            return Err(StorageError::bad_request(
                "private ORAM external recovery chunk is out of order",
            ));
        }

        let mut snapshot = self.open_snapshot_file(true)?;
        let snapshot_identity = file_identity(&snapshot)?;
        if snapshot_identity.len != state.bytes_received {
            return Err(invalid_staging_state());
        }
        snapshot.seek(SeekFrom::Start(state.bytes_received))?;
        chunk.seek(SeekFrom::Start(0))?;
        let copied = std::io::copy(&mut chunk.take(expected_len + 1), &mut snapshot)?;
        if copied != expected_len {
            snapshot.set_len(state.bytes_received)?;
            snapshot.sync_all()?;
            return Err(invalid_staging_state());
        }
        snapshot.sync_all()?;

        state.bytes_received = state
            .bytes_received
            .checked_add(expected_len)
            .ok_or_else(invalid_staging_state)?;
        state.next_chunk_index = state
            .next_chunk_index
            .checked_add(1)
            .ok_or_else(invalid_staging_state)?;
        validate_state(&state)?;
        self.write_state(&state)?;
        Ok(state.status())
    }

    pub fn prepare_verification(
        &self,
    ) -> Result<PrivateOramExternalRecoveryVerification, StorageError> {
        let collection_lock = self.acquire_collection_lock(false)?;
        let state = self
            .read_state()?
            .ok_or_else(|| StorageError::not_found("private ORAM external recovery not found"))?;
        self.reconcile_snapshot_file(&state)?;
        if state.bytes_received != state.checkpoint_bundle.checkpoint.snapshot_size_bytes {
            return Err(StorageError::bad_request(
                "private ORAM external recovery upload is incomplete",
            ));
        }
        let snapshot_path = self.snapshot_path();
        let mut snapshot = self.open_snapshot_file(false)?;
        let archive_identity = file_identity(&snapshot)?;
        let snapshot_sha256 = lowercase_sha256_reader(&mut snapshot)?;
        if snapshot_sha256 != state.checkpoint_bundle.checkpoint.snapshot_sha256 {
            return Err(StorageError::bad_request(
                "private ORAM external recovery snapshot hash mismatch",
            ));
        }
        Ok(PrivateOramExternalRecoveryVerification {
            checkpoint_bundle: state.checkpoint_bundle,
            snapshot_path,
            verified_collection_path: self
                .operation_path()
                .join(PRIVATE_ORAM_EXTERNAL_RECOVERY_VERIFIED_DIR),
            verify_temp_collection_path: self
                .operation_path()
                .join(PRIVATE_ORAM_EXTERNAL_RECOVERY_VERIFY_TEMP_DIR),
            operation_id_hash: self.operation_id_hash.clone(),
            checkpoint_digest: state.checkpoint_digest,
            archive_identity,
            _collection_lock: collection_lock,
        })
    }

    pub fn mark_verified(
        &self,
        verification: PrivateOramExternalRecoveryVerification,
    ) -> Result<PrivateOramExternalRecoveryStagingStatus, StorageError> {
        if verification.operation_id_hash != self.operation_id_hash {
            return Err(invalid_staging_request());
        }
        if verification.snapshot_path != self.snapshot_path()
            || verification.verified_collection_path
                != self
                    .operation_path()
                    .join(PRIVATE_ORAM_EXTERNAL_RECOVERY_VERIFIED_DIR)
            || verification.verify_temp_collection_path
                != self
                    .operation_path()
                    .join(PRIVATE_ORAM_EXTERNAL_RECOVERY_VERIFY_TEMP_DIR)
        {
            return Err(invalid_staging_request());
        }
        let mut state = self
            .read_state()?
            .ok_or_else(|| StorageError::not_found("private ORAM external recovery not found"))?;
        let mut snapshot = self.open_snapshot_file(false)?;
        let archive_identity = file_identity(&snapshot)?;
        let archive_sha256 = lowercase_sha256_reader(&mut snapshot)?;
        if state.checkpoint_digest != verification.checkpoint_digest
            || state.checkpoint_bundle != verification.checkpoint_bundle
            || archive_identity != verification.archive_identity
            || archive_sha256 != state.checkpoint_bundle.checkpoint.snapshot_sha256
            || !secure_directory_exists(&verification.verified_collection_path)?
        {
            return Err(invalid_staging_state());
        }
        state.phase = PrivateOramExternalRecoveryStagingPhase::Verified;
        validate_state(&state)?;
        self.write_state(&state)?;
        Ok(state.status())
    }

    pub fn abort(&self) -> Result<(), StorageError> {
        let _collection_lock = self.acquire_collection_lock(false)?;
        let operation_path = self.operation_path();
        match fs::symlink_metadata(&operation_path) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(_) => return Err(invalid_staging_state()),
            Ok(_) => validate_secure_directory(&operation_path)?,
        }
        let state = self.read_state()?.ok_or_else(invalid_staging_state)?;
        if state.operation_id_hash != self.operation_id_hash
            || state.checkpoint_bundle.checkpoint.collection_id != self.collection_id
        {
            return Err(invalid_staging_state());
        }
        fs::remove_dir_all(&operation_path).map_err(|_| invalid_staging_state())?;
        common::fs::sync_parent_dir(&operation_path).map_err(|_| invalid_staging_state())?;
        Ok(())
    }

    fn ensure_collection_directories(&self) -> Result<(), StorageError> {
        if !self.storage_path.is_dir() {
            return Err(invalid_staging_state());
        }
        ensure_secure_directory(&self.base_path())?;
        ensure_secure_directory(&self.collection_path())
    }

    fn acquire_collection_lock(
        &self,
        create: bool,
    ) -> Result<PrivateOramExternalRecoveryLock, StorageError> {
        let lock_path = self.collection_lock_path();
        let mut options = std::fs::OpenOptions::new();
        options.read(true).write(true).create(create);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;

            options
                .custom_flags(nix::libc::O_CLOEXEC | nix::libc::O_NOFOLLOW)
                .mode(0o600);
        }
        let file = options.open(&lock_path).map_err(|error| {
            if error.kind() == std::io::ErrorKind::NotFound {
                StorageError::not_found("private ORAM external recovery not found")
            } else {
                invalid_staging_state()
            }
        })?;
        let opened = file.metadata().map_err(|_| invalid_staging_state())?;
        validate_secure_file_metadata(&opened, 0)?;
        FileExt::lock_exclusive(&file).map_err(|_| invalid_staging_state())?;
        let current = fs::symlink_metadata(&lock_path).map_err(|_| invalid_staging_state())?;
        ensure_same_file(&opened, &current)?;
        validate_secure_file_metadata(&current, 0)?;
        if create {
            file.sync_all().map_err(|_| invalid_staging_state())?;
            common::fs::sync_parent_dir(&lock_path).map_err(|_| invalid_staging_state())?;
        }
        Ok(PrivateOramExternalRecoveryLock { _file: file })
    }

    fn create_empty_snapshot_file(&self) -> Result<(), StorageError> {
        let snapshot_path = self.snapshot_path();
        match fs::symlink_metadata(&snapshot_path) {
            Ok(_) => {
                let file = self.open_snapshot_file(true)?;
                if file_identity(&file)?.len != 0 {
                    return Err(invalid_staging_state());
                }
                return Ok(());
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return Err(invalid_staging_state()),
        }
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        secure_open_options(&mut options, true);
        let file = options
            .open(&snapshot_path)
            .map_err(|_| invalid_staging_state())?;
        file.sync_all().map_err(|_| invalid_staging_state())?;
        common::fs::sync_parent_dir(&snapshot_path).map_err(|_| invalid_staging_state())
    }

    fn reconcile_snapshot_file(
        &self,
        state: &PrivateOramExternalRecoveryStagingState,
    ) -> Result<(), StorageError> {
        let file = self.open_snapshot_file(true)?;
        let identity = file_identity(&file)?;
        if identity.len < state.bytes_received
            || identity.len > state.checkpoint_bundle.checkpoint.snapshot_size_bytes
        {
            return Err(invalid_staging_state());
        }
        if identity.len > state.bytes_received {
            file.set_len(state.bytes_received)
                .map_err(|_| invalid_staging_state())?;
            file.sync_all().map_err(|_| invalid_staging_state())?;
        }
        Ok(())
    }

    fn read_state(&self) -> Result<Option<PrivateOramExternalRecoveryStagingState>, StorageError> {
        let state_path = self.state_path();
        let metadata = match fs::symlink_metadata(&state_path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(_) => return Err(invalid_staging_state()),
        };
        validate_secure_file_metadata(&metadata, PRIVATE_ORAM_EXTERNAL_RECOVERY_STATE_MAX_BYTES)?;
        let file = open_regular_file(
            &state_path,
            true,
            Some(PRIVATE_ORAM_EXTERNAL_RECOVERY_STATE_MAX_BYTES),
        )?;
        let opened = file.metadata().map_err(|_| invalid_staging_state())?;
        ensure_same_file(&metadata, &opened)?;
        let mut bytes = Vec::with_capacity(opened.len() as usize);
        file.take(PRIVATE_ORAM_EXTERNAL_RECOVERY_STATE_MAX_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| invalid_staging_state())?;
        if bytes.len() as u64 != opened.len() {
            return Err(invalid_staging_state());
        }
        let state = serde_json::from_slice(&bytes).map_err(|_| invalid_staging_state())?;
        validate_state(&state)?;
        if state.operation_id_hash != self.operation_id_hash
            || state.checkpoint_bundle.checkpoint.collection_id != self.collection_id
        {
            return Err(invalid_staging_state());
        }
        Ok(Some(state))
    }

    fn write_state(
        &self,
        state: &PrivateOramExternalRecoveryStagingState,
    ) -> Result<(), StorageError> {
        validate_state(state)?;
        let bytes = serde_json::to_vec(state).map_err(|_| invalid_staging_state())?;
        if bytes.is_empty() || bytes.len() as u64 > PRIVATE_ORAM_EXTERNAL_RECOVERY_STATE_MAX_BYTES {
            return Err(invalid_staging_state());
        }
        let temp_path = self
            .operation_path()
            .join(format!(".state-{}.tmp", uuid::Uuid::new_v4()));
        let state_path = self.state_path();
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        secure_open_options(&mut options, true);
        let result = (|| {
            let mut file = options
                .open(&temp_path)
                .map_err(|_| invalid_staging_state())?;
            file.write_all(&bytes)
                .map_err(|_| invalid_staging_state())?;
            file.sync_all().map_err(|_| invalid_staging_state())?;
            fs::rename(&temp_path, &state_path).map_err(|_| invalid_staging_state())?;
            common::fs::sync_parent_dir(&state_path).map_err(|_| invalid_staging_state())
        })();
        if result.is_err() {
            let _ = fs::remove_file(&temp_path);
        }
        result
    }

    fn open_snapshot_file(&self, write: bool) -> Result<File, StorageError> {
        open_regular_file(
            &self.snapshot_path(),
            true,
            Some(PRIVATE_ORAM_EXTERNAL_RECOVERY_MAX_SNAPSHOT_BYTES),
        )
        .and_then(|file| {
            if write {
                let original = file.metadata().map_err(|_| invalid_staging_state())?;
                drop(file);
                let mut options = OpenOptions::new();
                options.read(true).write(true);
                secure_open_options(&mut options, false);
                let reopened = options
                    .open(self.snapshot_path())
                    .map_err(|_| invalid_staging_state())?;
                let reopened_metadata = reopened.metadata().map_err(|_| invalid_staging_state())?;
                ensure_same_file(&original, &reopened_metadata)?;
                validate_secure_file_metadata(
                    &reopened_metadata,
                    PRIVATE_ORAM_EXTERNAL_RECOVERY_MAX_SNAPSHOT_BYTES,
                )?;
                Ok(reopened)
            } else {
                Ok(file)
            }
        })
    }

    fn base_path(&self) -> PathBuf {
        self.storage_path.join(PRIVATE_ORAM_EXTERNAL_RECOVERY_DIR)
    }

    fn collection_path(&self) -> PathBuf {
        let mut hasher = Sha256::new();
        hasher.update(PRIVATE_ORAM_EXTERNAL_RECOVERY_COLLECTION_KEY_DOMAIN);
        hasher.update((self.collection_id.len() as u64).to_be_bytes());
        hasher.update(self.collection_id.as_bytes());
        self.base_path()
            .join(BASE64URL_NOPAD.encode(&hasher.finalize()))
    }

    fn operation_path(&self) -> PathBuf {
        self.collection_path().join(&self.operation_id_hash)
    }

    fn collection_lock_path(&self) -> PathBuf {
        self.collection_path()
            .join(PRIVATE_ORAM_EXTERNAL_RECOVERY_LOCK_FILE)
    }

    fn state_path(&self) -> PathBuf {
        self.operation_path()
            .join(PRIVATE_ORAM_EXTERNAL_RECOVERY_STATE_FILE)
    }

    fn snapshot_path(&self) -> PathBuf {
        self.operation_path()
            .join(PRIVATE_ORAM_EXTERNAL_RECOVERY_SNAPSHOT_FILE)
    }
}

pub fn new_private_oram_external_recovery_operation_token() -> String {
    BASE64URL_NOPAD.encode(&rand::random::<[u8; PRIVATE_ORAM_OPERATION_TOKEN_BYTES]>())
}

pub fn private_oram_external_recovery_operation_id_hash(
    operation_token: &str,
) -> Result<String, StorageError> {
    if operation_token.len() != PRIVATE_ORAM_OPERATION_TOKEN_LEN {
        return Err(invalid_staging_request());
    }
    let decoded = BASE64URL_NOPAD
        .decode(operation_token.as_bytes())
        .map_err(|_| invalid_staging_request())?;
    if decoded.len() != PRIVATE_ORAM_OPERATION_TOKEN_BYTES
        || BASE64URL_NOPAD.encode(&decoded) != operation_token
    {
        return Err(invalid_staging_request());
    }
    let mut hasher = Sha256::new();
    hasher.update(PRIVATE_ORAM_EXTERNAL_RECOVERY_OPERATION_ID_DOMAIN);
    hasher.update((decoded.len() as u64).to_be_bytes());
    hasher.update(decoded);
    Ok(BASE64URL_NOPAD.encode(&hasher.finalize()))
}

pub fn private_oram_external_recovery_checkpoint_digest(
    bundle: &PrivateOramExternalRecoveryCheckpointBundle,
) -> Result<String, StorageError> {
    validate_private_oram_recovery_signature_shape(&bundle.signature)
        .map_err(|_| invalid_staging_request())?;
    let message =
        try_private_oram_external_recovery_checkpoint_signature_message(&bundle.checkpoint)
            .map_err(|_| invalid_staging_request())?;
    let mut hasher = Sha256::new();
    hasher.update(PRIVATE_ORAM_EXTERNAL_RECOVERY_CHECKPOINT_DIGEST_DOMAIN);
    update_length_prefixed(&mut hasher, &message);
    update_length_prefixed(&mut hasher, bundle.signature.alg.as_bytes());
    update_length_prefixed(&mut hasher, bundle.signature.key_id.as_bytes());
    update_length_prefixed(&mut hasher, bundle.signature.sig.as_bytes());
    Ok(BASE64URL_NOPAD.encode(&hasher.finalize()))
}

fn validate_state(state: &PrivateOramExternalRecoveryStagingState) -> Result<(), StorageError> {
    validate_private_oram_external_recovery_checkpoint_shape(&state.checkpoint_bundle.checkpoint)
        .map_err(|_| invalid_staging_state())?;
    validate_private_oram_recovery_signature_shape(&state.checkpoint_bundle.signature)
        .map_err(|_| invalid_staging_state())?;
    validate_base64url_sha256(&state.operation_id_hash)?;
    validate_base64url_sha256(&state.checkpoint_digest)?;
    if state.version != PRIVATE_ORAM_EXTERNAL_RECOVERY_STATE_VERSION
        || state.lease_expires_at_unix == 0
        || state.checkpoint_bundle.checkpoint.snapshot_size_bytes == 0
        || state.checkpoint_bundle.checkpoint.snapshot_size_bytes
            > PRIVATE_ORAM_EXTERNAL_RECOVERY_MAX_SNAPSHOT_BYTES
        || state.bytes_received > state.checkpoint_bundle.checkpoint.snapshot_size_bytes
        || state.bytes_received < state.checkpoint_bundle.checkpoint.snapshot_size_bytes
            && state.bytes_received % PRIVATE_ORAM_EXTERNAL_RECOVERY_CHUNK_SIZE_BYTES != 0
        || state.next_chunk_index
            != state
                .bytes_received
                .div_ceil(PRIVATE_ORAM_EXTERNAL_RECOVERY_CHUNK_SIZE_BYTES)
        || state.phase == PrivateOramExternalRecoveryStagingPhase::Verified
            && state.bytes_received != state.checkpoint_bundle.checkpoint.snapshot_size_bytes
        || private_oram_external_recovery_checkpoint_digest(&state.checkpoint_bundle)?
            != state.checkpoint_digest
    {
        return Err(invalid_staging_state());
    }
    Ok(())
}

fn ensure_secure_directory(path: &Path) -> Result<(), StorageError> {
    match fs::symlink_metadata(path) {
        Ok(_) => validate_secure_directory(path),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let mut builder = DirBuilder::new();
            #[cfg(unix)]
            {
                use std::os::unix::fs::DirBuilderExt as _;

                builder.mode(0o700);
            }
            match builder.create(path) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(_) => return Err(invalid_staging_state()),
            }
            validate_secure_directory(path)?;
            common::fs::sync_parent_dir(path).map_err(|_| invalid_staging_state())
        }
        Err(_) => Err(invalid_staging_state()),
    }
}

fn secure_directory_exists(path: &Path) -> Result<bool, StorageError> {
    match fs::symlink_metadata(path) {
        Ok(_) => {
            validate_secure_directory(path)?;
            Ok(true)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(_) => Err(invalid_staging_state()),
    }
}

fn remove_secure_directory_if_exists(path: &Path) -> Result<(), StorageError> {
    match fs::symlink_metadata(path) {
        Ok(_) => {
            validate_secure_directory(path)?;
            fs::remove_dir_all(path).map_err(|_| invalid_staging_state())?;
            common::fs::sync_parent_dir(path).map_err(|_| invalid_staging_state())
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err(invalid_staging_state()),
    }
}

fn validate_secure_directory(path: &Path) -> Result<(), StorageError> {
    let metadata = fs::symlink_metadata(path).map_err(|_| invalid_staging_state())?;
    if !metadata.file_type().is_dir() {
        return Err(invalid_staging_state());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

        if metadata.uid() != nix::unistd::Uid::effective().as_raw()
            || metadata.permissions().mode() & 0o077 != 0
        {
            return Err(invalid_staging_state());
        }
    }
    Ok(())
}

fn open_regular_file(
    path: &Path,
    require_private: bool,
    max_bytes: Option<u64>,
) -> Result<File, StorageError> {
    let metadata = fs::symlink_metadata(path).map_err(|_| invalid_staging_state())?;
    if let Some(max_bytes) = max_bytes {
        validate_file_metadata(&metadata, require_private, max_bytes)?;
    } else if !metadata.file_type().is_file() {
        return Err(invalid_staging_state());
    }
    let mut options = OpenOptions::new();
    options.read(true);
    secure_open_options(&mut options, false);
    let file = options.open(path).map_err(|_| invalid_staging_state())?;
    let opened = file.metadata().map_err(|_| invalid_staging_state())?;
    ensure_same_file(&metadata, &opened)?;
    if let Some(max_bytes) = max_bytes {
        validate_file_metadata(&opened, require_private, max_bytes)?;
    }
    Ok(file)
}

fn secure_open_options(options: &mut OpenOptions, create_private: bool) {
    #[cfg(unix)]
    {
        use fs_err::os::unix::fs::OpenOptionsExt as _;

        options.custom_flags(nix::libc::O_CLOEXEC | nix::libc::O_NOFOLLOW);
        if create_private {
            options.mode(0o600);
        }
    }
}

fn validate_secure_file_metadata(
    metadata: &std::fs::Metadata,
    max_bytes: u64,
) -> Result<(), StorageError> {
    validate_file_metadata(metadata, true, max_bytes)
}

fn validate_file_metadata(
    metadata: &std::fs::Metadata,
    require_private: bool,
    max_bytes: u64,
) -> Result<(), StorageError> {
    if !metadata.file_type().is_file() || metadata.len() > max_bytes {
        return Err(invalid_staging_state());
    }
    #[cfg(unix)]
    if require_private {
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

        if metadata.uid() != nix::unistd::Uid::effective().as_raw()
            || metadata.permissions().mode() & 0o077 != 0
        {
            return Err(invalid_staging_state());
        }
    }
    Ok(())
}

fn ensure_same_file(
    before: &std::fs::Metadata,
    after: &std::fs::Metadata,
) -> Result<(), StorageError> {
    if before.len() != after.len() || before.file_type().is_file() != after.file_type().is_file() {
        return Err(invalid_staging_state());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;

        if before.dev() != after.dev() || before.ino() != after.ino() {
            return Err(invalid_staging_state());
        }
    }
    Ok(())
}

fn file_identity(file: &File) -> Result<FileIdentity, StorageError> {
    let metadata = file.metadata().map_err(|_| invalid_staging_state())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;

        Ok(FileIdentity {
            len: metadata.len(),
            device: metadata.dev(),
            inode: metadata.ino(),
        })
    }
    #[cfg(not(unix))]
    {
        Ok(FileIdentity {
            len: metadata.len(),
        })
    }
}

fn lowercase_sha256_reader(reader: &mut impl Read) -> Result<String, StorageError> {
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = reader.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(HEXLOWER.encode(&hasher.finalize()))
}

fn lowercase_sha256_reader_limited(
    reader: &mut impl Read,
    expected_len: u64,
) -> Result<String, StorageError> {
    let mut limited = reader.take(expected_len);
    let digest = lowercase_sha256_reader(&mut limited)?;
    if limited.limit() != 0 {
        return Err(invalid_staging_state());
    }
    Ok(digest)
}

fn validate_base64url_sha256(value: &str) -> Result<(), StorageError> {
    if value.len() != PRIVATE_ORAM_SHA256_BASE64URL_LEN {
        return Err(invalid_staging_request());
    }
    let decoded = BASE64URL_NOPAD
        .decode(value.as_bytes())
        .map_err(|_| invalid_staging_request())?;
    if decoded.len() != 32 || BASE64URL_NOPAD.encode(&decoded) != value {
        return Err(invalid_staging_request());
    }
    Ok(())
}

fn validate_lowercase_sha256(value: &str) -> Result<(), StorageError> {
    if value.len() != PRIVATE_ORAM_SHA256_HEX_LEN {
        return Err(invalid_staging_request());
    }
    let decoded = HEXLOWER
        .decode(value.as_bytes())
        .map_err(|_| invalid_staging_request())?;
    if decoded.len() != 32 || HEXLOWER.encode(&decoded) != value {
        return Err(invalid_staging_request());
    }
    Ok(())
}

fn update_length_prefixed(hasher: &mut Sha256, value: &[u8]) {
    hasher.update((value.len() as u64).to_be_bytes());
    hasher.update(value);
}

fn invalid_staging_request() -> StorageError {
    StorageError::bad_request("private ORAM external recovery request is invalid")
}

fn invalid_staging_state() -> StorageError {
    StorageError::service_error("private ORAM external recovery staging state is invalid")
}

#[cfg(test)]
mod tests {
    use std::io::Write as _;

    use qdrant_sec::{
        PRIVATE_ORAM_EXTERNAL_RECOVERY_CHECKPOINT_VERSION, PrivateOramExternalRecoveryCheckpoint,
        PrivateOramRecoverySignature,
    };

    use super::*;

    fn bundle(snapshot: &[u8]) -> PrivateOramExternalRecoveryCheckpointBundle {
        PrivateOramExternalRecoveryCheckpointBundle {
            checkpoint: PrivateOramExternalRecoveryCheckpoint {
                version: PRIVATE_ORAM_EXTERNAL_RECOVERY_CHECKPOINT_VERSION,
                collection_id: "collection-uuid-1".to_string(),
                backup_generation: 7,
                source_peer_id: 11,
                source_shard_ids: vec![1],
                layout_generation: 3,
                owner_peer_ids: vec![11],
                layout_digest: BASE64URL_NOPAD.encode(&[1; 32]),
                index_state_digest: BASE64URL_NOPAD.encode(&[2; 32]),
                snapshot_size_bytes: snapshot.len() as u64,
                snapshot_sha256: HEXLOWER.encode(&Sha256::digest(snapshot)),
                client_recovery_state_digest: BASE64URL_NOPAD.encode(&[3; 32]),
                owner_signing_key_id: "owner-key-1".to_string(),
                created_at_unix: 100,
            },
            signature: PrivateOramRecoverySignature {
                alg: "ed25519".to_string(),
                key_id: "owner-key-1".to_string(),
                sig: BASE64URL_NOPAD.encode(&[4; 64]),
            },
        }
    }

    fn chunk_file(path: &Path, bytes: &[u8]) -> String {
        let mut file = fs::File::create(path).unwrap();
        file.write_all(bytes).unwrap();
        file.sync_all().unwrap();
        HEXLOWER.encode(&Sha256::digest(bytes))
    }

    #[test]
    fn staged_chunks_are_ordered_idempotent_and_verified() {
        let temp = tempfile::tempdir().unwrap();
        let mut snapshot = vec![7_u8; PRIVATE_ORAM_EXTERNAL_RECOVERY_CHUNK_SIZE_BYTES as usize];
        snapshot.extend_from_slice(b"tail");
        let bundle = bundle(&snapshot);
        let checkpoint_digest = private_oram_external_recovery_checkpoint_digest(&bundle).unwrap();
        let token = new_private_oram_external_recovery_operation_token();
        let operation_hash = private_oram_external_recovery_operation_id_hash(&token).unwrap();
        let staging = PrivateOramExternalRecoveryStaging::new(
            temp.path(),
            &bundle.checkpoint.collection_id,
            &operation_hash,
        )
        .unwrap();

        let initial = staging
            .begin(&checkpoint_digest, bundle.clone(), 1_000)
            .unwrap();
        assert_eq!(initial.bytes_received, 0);
        assert_eq!(initial.next_chunk_index, 0);
        assert_eq!(
            staging
                .status_for_consensus_lease(&checkpoint_digest, 7, 1_100)
                .unwrap()
                .lease_expires_at_unix,
            1_100
        );
        assert!(
            staging
                .status_for_consensus_lease(&checkpoint_digest, 7, 1_000)
                .is_err()
        );

        let first_path = temp.path().join("first.chunk");
        let first_hash = chunk_file(
            &first_path,
            &snapshot[..PRIVATE_ORAM_EXTERNAL_RECOVERY_CHUNK_SIZE_BYTES as usize],
        );
        let tail_path = temp.path().join("tail.chunk");
        let tail_hash = chunk_file(
            &tail_path,
            &snapshot[PRIVATE_ORAM_EXTERNAL_RECOVERY_CHUNK_SIZE_BYTES as usize..],
        );

        let out_of_order = staging
            .append_chunk(1, &tail_path, &tail_hash)
            .unwrap_err()
            .to_string();
        assert!(out_of_order.contains("out of order"));
        let first = staging.append_chunk(0, &first_path, &first_hash).unwrap();
        assert_eq!(
            first.bytes_received,
            PRIVATE_ORAM_EXTERNAL_RECOVERY_CHUNK_SIZE_BYTES
        );
        assert_eq!(
            staging.append_chunk(0, &first_path, &first_hash).unwrap(),
            first
        );
        let complete = staging.append_chunk(1, &tail_path, &tail_hash).unwrap();
        assert_eq!(complete.bytes_received, snapshot.len() as u64);

        let verification = staging.prepare_verification().unwrap();
        verification.reset_verification_output().unwrap();
        fs::write(
            verification.verify_temp_collection_path().join("marker"),
            b"verified",
        )
        .unwrap();
        verification.promote_verification_output().unwrap();
        assert_eq!(
            fs::read(verification.verified_collection_path().join("marker")).unwrap(),
            b"verified"
        );
        let verified = staging.mark_verified(verification).unwrap();
        assert_eq!(
            verified.phase,
            PrivateOramExternalRecoveryStagingPhase::Verified
        );
        assert_eq!(staging.status().unwrap(), verified);

        staging.abort().unwrap();
        assert!(matches!(
            staging.status(),
            Err(StorageError::NotFound { .. })
        ));
    }

    #[test]
    fn uncommitted_archive_suffix_is_truncated_before_retry() {
        let temp = tempfile::tempdir().unwrap();
        let snapshot = b"snapshot".to_vec();
        let bundle = bundle(&snapshot);
        let checkpoint_digest = private_oram_external_recovery_checkpoint_digest(&bundle).unwrap();
        let operation_hash = private_oram_external_recovery_operation_id_hash(
            &new_private_oram_external_recovery_operation_token(),
        )
        .unwrap();
        let staging = PrivateOramExternalRecoveryStaging::new(
            temp.path(),
            &bundle.checkpoint.collection_id,
            &operation_hash,
        )
        .unwrap();
        staging.begin(&checkpoint_digest, bundle, 1_000).unwrap();

        let mut archive = OpenOptions::new()
            .append(true)
            .open(staging.snapshot_path())
            .unwrap();
        archive.write_all(b"partial").unwrap();
        archive.sync_all().unwrap();
        assert_eq!(fs::metadata(staging.snapshot_path()).unwrap().len(), 7);

        let chunk_path = temp.path().join("snapshot.chunk");
        let chunk_hash = chunk_file(&chunk_path, &snapshot);
        staging.append_chunk(0, &chunk_path, &chunk_hash).unwrap();
        assert_eq!(
            fs::read(staging.snapshot_path()).unwrap(),
            snapshot.as_slice()
        );
    }

    #[test]
    fn collection_lock_serializes_staging_mutations() {
        let temp = tempfile::tempdir().unwrap();
        let snapshot = b"snapshot".to_vec();
        let bundle = bundle(&snapshot);
        let checkpoint_digest = private_oram_external_recovery_checkpoint_digest(&bundle).unwrap();
        let operation_hash = private_oram_external_recovery_operation_id_hash(
            &new_private_oram_external_recovery_operation_token(),
        )
        .unwrap();
        let staging = PrivateOramExternalRecoveryStaging::new(
            temp.path(),
            &bundle.checkpoint.collection_id,
            &operation_hash,
        )
        .unwrap();
        staging.begin(&checkpoint_digest, bundle, 1_000).unwrap();

        let _first = staging.acquire_collection_lock(false).unwrap();
        let second = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(staging.collection_lock_path())
            .unwrap();
        assert!(!FileExt::try_lock_exclusive(&second).unwrap());
    }

    #[test]
    fn mark_verified_rejects_archive_tampering_after_preflight() {
        let temp = tempfile::tempdir().unwrap();
        let snapshot = b"snapshot".to_vec();
        let bundle = bundle(&snapshot);
        let checkpoint_digest = private_oram_external_recovery_checkpoint_digest(&bundle).unwrap();
        let operation_hash = private_oram_external_recovery_operation_id_hash(
            &new_private_oram_external_recovery_operation_token(),
        )
        .unwrap();
        let staging = PrivateOramExternalRecoveryStaging::new(
            temp.path(),
            &bundle.checkpoint.collection_id,
            &operation_hash,
        )
        .unwrap();
        staging.begin(&checkpoint_digest, bundle, 1_000).unwrap();
        let chunk_path = temp.path().join("snapshot.chunk");
        let chunk_hash = chunk_file(&chunk_path, &snapshot);
        staging.append_chunk(0, &chunk_path, &chunk_hash).unwrap();
        let verification = staging.prepare_verification().unwrap();
        fs::create_dir(&verification.verified_collection_path).unwrap();
        fs::write(&verification.snapshot_path, b"tampered").unwrap();

        assert!(staging.mark_verified(verification).is_err());
        assert_eq!(
            staging.status().unwrap().phase,
            PrivateOramExternalRecoveryStagingPhase::Uploading
        );
    }

    #[test]
    fn mark_verified_rejects_a_substituted_verified_directory() {
        let temp = tempfile::tempdir().unwrap();
        let snapshot = b"snapshot".to_vec();
        let bundle = bundle(&snapshot);
        let checkpoint_digest = private_oram_external_recovery_checkpoint_digest(&bundle).unwrap();
        let operation_hash = private_oram_external_recovery_operation_id_hash(
            &new_private_oram_external_recovery_operation_token(),
        )
        .unwrap();
        let staging = PrivateOramExternalRecoveryStaging::new(
            temp.path(),
            &bundle.checkpoint.collection_id,
            &operation_hash,
        )
        .unwrap();
        staging.begin(&checkpoint_digest, bundle, 1_000).unwrap();
        let chunk_path = temp.path().join("snapshot.chunk");
        let chunk_hash = chunk_file(&chunk_path, &snapshot);
        staging.append_chunk(0, &chunk_path, &chunk_hash).unwrap();
        let mut verification = staging.prepare_verification().unwrap();
        let substituted = temp.path().join("substituted");
        fs::create_dir(&substituted).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;

            fs::set_permissions(&substituted, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        verification.verified_collection_path = substituted;

        assert!(staging.mark_verified(verification).is_err());
    }

    #[test]
    fn staging_debug_and_errors_redact_recovery_values() {
        let temp = tempfile::tempdir().unwrap();
        let collection = "private-oram-recovery-collection-sentinel";
        let operation_hash = BASE64URL_NOPAD.encode(&[9; 32]);
        let staging =
            PrivateOramExternalRecoveryStaging::new(temp.path(), collection, &operation_hash)
                .unwrap();
        let rendered = format!("{staging:?}");
        assert!(!rendered.contains(collection));
        assert!(!rendered.contains(&operation_hash));
        assert!(!rendered.contains(&temp.path().display().to_string()));

        let malformed = staging
            .append_chunk(
                0,
                Path::new("private-oram-recovery-path-sentinel"),
                "private-oram-recovery-hash-sentinel",
            )
            .unwrap_err()
            .to_string();
        assert!(!malformed.contains("private-oram-recovery"));
    }

    #[cfg(unix)]
    #[test]
    fn staging_rejects_symlinked_state() {
        use std::os::unix::fs::symlink;

        let temp = tempfile::tempdir().unwrap();
        let snapshot = b"snapshot".to_vec();
        let bundle = bundle(&snapshot);
        let checkpoint_digest = private_oram_external_recovery_checkpoint_digest(&bundle).unwrap();
        let operation_hash = private_oram_external_recovery_operation_id_hash(
            &new_private_oram_external_recovery_operation_token(),
        )
        .unwrap();
        let staging = PrivateOramExternalRecoveryStaging::new(
            temp.path(),
            &bundle.checkpoint.collection_id,
            &operation_hash,
        )
        .unwrap();
        staging.begin(&checkpoint_digest, bundle, 1_000).unwrap();
        fs::remove_file(staging.state_path()).unwrap();
        let target = temp.path().join("state-target");
        fs::write(&target, b"{}").unwrap();
        symlink(&target, staging.state_path()).unwrap();

        assert!(staging.status().is_err());
    }
}
