use std::collections::HashSet;
use std::io::{self, BufReader, Read, Write};
use std::num::NonZeroUsize;
#[cfg(target_os = "linux")]
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock, mpsc};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use data_encoding::BASE64URL_NOPAD;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::vector::{
    CKKS_SCHEME, CkksBatchEncryptionInput, CkksEncryptedQueryScoreBatchInput,
    CkksEncryptedQueryScoreInput, CkksEncryptionInput, CkksError, CkksParameters,
    CkksPlaintextQueryScoreBatchInput, CkksPlaintextQueryScoreInput, CkksQueryEncryptionInput,
    CkksVectorBackend,
};

/// How long a request waits for a busy bridge worker before failing.
const WORKER_RESERVATION_WAIT: Duration = Duration::from_secs(5);
/// Poll interval while waiting for a bridge worker.
const WORKER_RESERVATION_POLL: Duration = Duration::from_millis(5);

const DEFAULT_BRIDGE_TIMEOUT: Duration = Duration::from_secs(30);
/// Per-line stdout (and total stderr) budget for a bridge worker. Sized so a batch of
/// `MAX_BRIDGE_CIPHERTEXT_BYTES` ciphertexts fits; the previous 1 MiB default truncated any
/// response carrying a full-size CKKS ciphertext and killed the worker.
const DEFAULT_MAX_OUTPUT_BYTES: usize = 64 * 1024 * 1024;
const MIN_OPENFHE_SECURITY_LEVEL_BITS: u16 = 128;
const BASE64URL_NOPAD_32_BYTE_LEN: usize = 43;
const MAX_BRIDGE_PROGRAM_SHA256_BYTES: u64 = 64 * 1024 * 1024;
const MAX_BRIDGE_CIPHERTEXT_BYTES: usize = 16 * 1024 * 1024;
const MAX_BRIDGE_CIPHERTEXT_B64_LEN: usize = (MAX_BRIDGE_CIPHERTEXT_BYTES + 2) / 3 * 4;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum BridgeSandbox {
    ProcessHardening,
    LinuxLandlockWriteDeny,
    LinuxLandlockWriteDenyNetworkNamespace,
}

#[derive(Clone)]
pub struct CommandOpenFheBackend {
    program: PathBuf,
    args: Vec<String>,
    timeout: Duration,
    max_output_bytes: usize,
    pool_size: NonZeroUsize,
    checked_program: bool,
    expected_sha256_b64: Option<String>,
    sandbox: BridgeSandbox,
    sensitive_env_names: Vec<String>,
    workers: Arc<Mutex<Vec<Arc<WorkerProcess>>>>,
    /// Workers being spawned outside the `workers` lock; counted against `pool_size`.
    spawning: Arc<AtomicUsize>,
}

impl std::fmt::Debug for CommandOpenFheBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CommandOpenFheBackend")
            .field("program", &"[redacted]")
            .field("args_count", &self.args.len())
            .field("timeout", &self.timeout)
            .field("max_output_bytes", &self.max_output_bytes)
            .field("pool_size", &self.pool_size)
            .field("checked_program", &self.checked_program)
            .field(
                "expected_sha256_b64",
                &self.expected_sha256_b64.as_ref().map(|_| "<configured>"),
            )
            .field("sandbox", &self.sandbox)
            .field("sensitive_env_names_count", &self.sensitive_env_names.len())
            .finish()
    }
}

impl PartialEq for CommandOpenFheBackend {
    fn eq(&self, other: &Self) -> bool {
        self.program == other.program
            && self.args == other.args
            && self.timeout == other.timeout
            && self.max_output_bytes == other.max_output_bytes
            && self.pool_size == other.pool_size
            && self.checked_program == other.checked_program
            && self.expected_sha256_b64 == other.expected_sha256_b64
            && self.sandbox == other.sandbox
            && self.sensitive_env_names == other.sensitive_env_names
    }
}

impl Eq for CommandOpenFheBackend {}

struct WorkerProcess {
    child: Mutex<Child>,
    stdin: Mutex<ChildStdin>,
    stdout_rx: Mutex<mpsc::Receiver<BridgeStdoutEvent>>,
    stderr_truncated: Arc<AtomicBool>,
    registered_contexts: Mutex<HashSet<String>>,
    terminated: AtomicBool,
    reserved: AtomicBool,
    reader_threads: Mutex<WorkerReaderThreads>,
}

#[derive(Default)]
struct WorkerReaderThreads {
    stdout: Option<JoinHandle<()>>,
    stderr: Option<JoinHandle<io::Result<()>>>,
}

struct WorkerReservation {
    worker_process: Arc<WorkerProcess>,
}

enum BridgeStdoutEvent {
    Response { bytes: Vec<u8>, truncated: bool },
    Eof,
    Error(io::Error),
    StderrExceeded,
}

impl WorkerProcess {
    fn try_reserve_request(&self) -> bool {
        self.reserved
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
    }

    fn release_request(&self) {
        self.reserved.store(false, Ordering::Release);
    }

    fn try_wait(&self) -> Result<Option<ExitStatus>, CkksError> {
        self.child
            .lock()
            .map_err(|_| CkksError::Backend("OpenFHE bridge child mutex was poisoned".to_string()))?
            .try_wait()
            .map_err(|err| {
                CkksError::Backend(format!("failed to poll OpenFHE bridge status: {err}"))
            })
    }

    fn shutdown(&self, join_readers: bool) -> Result<(), CkksError> {
        if !self.terminated.swap(true, Ordering::SeqCst) {
            let mut child = self.child.lock().map_err(|_| {
                CkksError::Backend("OpenFHE bridge child mutex was poisoned".to_string())
            })?;
            let _ = child.kill();
            let _ = child.wait();
        }

        if join_readers {
            let WorkerReaderThreads {
                stdout: stdout_thread,
                stderr: stderr_thread,
            } = self.take_reader_threads()?;
            if let Some(stdout_thread) = stdout_thread {
                stdout_thread
                    .join()
                    .map_err(|_| CkksError::Backend("bridge stdout reader panicked".to_string()))?;
            }
            if let Some(stderr_thread) = stderr_thread {
                stderr_thread
                    .join()
                    .map_err(|_| CkksError::Backend("bridge stderr reader panicked".to_string()))?
                    .map_err(|err| {
                        CkksError::Backend(format!("failed to drain OpenFHE bridge stderr: {err}"))
                    })?;
            }
        } else if let Ok(mut reader_threads) = self.reader_threads.lock() {
            let _ = std::mem::take(&mut *reader_threads);
        }

        Ok(())
    }

    fn take_reader_threads(&self) -> Result<WorkerReaderThreads, CkksError> {
        let mut reader_threads = self.reader_threads.lock().map_err(|_| {
            CkksError::Backend("OpenFHE bridge reader thread mutex was poisoned".to_string())
        })?;
        Ok(std::mem::take(&mut *reader_threads))
    }
}

/// Releases a reserved-but-not-yet-pushed pool slot when the spawn finishes or fails.
struct SpawnSlot(Arc<AtomicUsize>);

impl Drop for SpawnSlot {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

impl WorkerReservation {
    fn reserved(worker_process: Arc<WorkerProcess>) -> Self {
        Self { worker_process }
    }

    fn worker(&self) -> &Arc<WorkerProcess> {
        &self.worker_process
    }
}

impl Drop for WorkerReservation {
    fn drop(&mut self) {
        self.worker_process.release_request();
    }
}

impl CommandOpenFheBackend {
    fn new_unchecked(program: impl Into<PathBuf>) -> Self {
        Self {
            program: program.into(),
            args: Vec::new(),
            timeout: DEFAULT_BRIDGE_TIMEOUT,
            max_output_bytes: DEFAULT_MAX_OUTPUT_BYTES,
            pool_size: NonZeroUsize::MIN,
            checked_program: false,
            expected_sha256_b64: None,
            sandbox: BridgeSandbox::ProcessHardening,
            sensitive_env_names: Vec::new(),
            workers: Arc::new(Mutex::new(Vec::new())),
            spawning: Arc::new(AtomicUsize::new(0)),
        }
    }

    pub fn new_checked(program: impl Into<PathBuf>) -> Result<Self, CkksError> {
        let program = program.into();
        validate_checked_bridge_program(&program)?;
        ensure_checked_bridge_spawn_supported()?;

        let mut backend = Self::new_unchecked(program);
        backend.checked_program = true;
        Ok(backend)
    }

    pub fn new_checked_with_sha256_b64(
        program: impl Into<PathBuf>,
        expected_sha256_b64: impl AsRef<str>,
    ) -> Result<Self, CkksError> {
        let program = program.into();
        let expected_sha256_b64 = expected_sha256_b64.as_ref().to_string();
        validate_checked_bridge_program(&program)?;
        validate_bridge_program_sha256_b64(&program, &expected_sha256_b64)?;
        ensure_checked_bridge_spawn_supported()?;

        let mut backend = Self::new_unchecked(program);
        backend.checked_program = true;
        backend.expected_sha256_b64 = Some(expected_sha256_b64);
        Ok(backend)
    }

    pub fn with_args<I, S>(mut self, args: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.args.extend(args.into_iter().map(Into::into));
        self.reset_worker_pool_after_policy_change();
        self
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self.reset_worker_pool_after_policy_change();
        self
    }

    pub fn with_max_output_bytes(mut self, max_output_bytes: usize) -> Self {
        self.max_output_bytes = max_output_bytes;
        self.reset_worker_pool_after_policy_change();
        self
    }

    pub fn with_pool_size(mut self, pool_size: NonZeroUsize) -> Self {
        self.pool_size = pool_size;
        self.reset_worker_pool_after_policy_change();
        self
    }

    pub fn with_linux_landlock_write_deny_sandbox(mut self) -> Self {
        self.sandbox = BridgeSandbox::LinuxLandlockWriteDeny;
        self.reset_worker_pool_after_policy_change();
        self
    }

    pub fn with_linux_landlock_write_deny_network_namespace_sandbox(mut self) -> Self {
        self.sandbox = BridgeSandbox::LinuxLandlockWriteDenyNetworkNamespace;
        self.reset_worker_pool_after_policy_change();
        self
    }

    pub fn with_sensitive_env_names<I, S>(mut self, env_names: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.sensitive_env_names = env_names
            .into_iter()
            .map(Into::into)
            .filter(|name| !name.is_empty())
            .collect();
        self.reset_worker_pool_after_policy_change();
        self
    }

    fn reset_worker_pool_after_policy_change(&mut self) {
        self.workers = Arc::new(Mutex::new(Vec::new()));
    }
}

#[cfg(target_os = "linux")]
fn ensure_checked_bridge_spawn_supported() -> Result<(), CkksError> {
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn ensure_checked_bridge_spawn_supported() -> Result<(), CkksError> {
    Err(CkksError::Backend(
        "OpenFHE checked bridge spawn requires Linux fd-backed /proc/self/fd execution".to_string(),
    ))
}

fn validate_checked_bridge_program(path: &Path) -> Result<(), CkksError> {
    if !path.is_absolute() {
        return Err(CkksError::Backend(
            "OpenFHE bridge program must be an absolute path".to_string(),
        ));
    }

    let link_metadata = std::fs::symlink_metadata(path).map_err(|err| {
        CkksError::Backend(format!("failed to inspect OpenFHE bridge program: {err}"))
    })?;
    if link_metadata.file_type().is_symlink() || !link_metadata.is_file() {
        return Err(CkksError::Backend(
            "OpenFHE bridge program must be a regular non-symlink file".to_string(),
        ));
    }

    let metadata = std::fs::metadata(path).map_err(|err| {
        CkksError::Backend(format!("failed to inspect OpenFHE bridge program: {err}"))
    })?;
    if !metadata.is_file() {
        return Err(CkksError::Backend(
            "OpenFHE bridge program must be a regular file".to_string(),
        ));
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};

        unsafe extern "C" {
            fn geteuid() -> u32;
        }

        let mode = metadata.permissions().mode();
        if mode & 0o111 == 0 || mode & 0o022 != 0 {
            return Err(CkksError::Backend(
                "OpenFHE bridge program must be executable and not group/world-writable"
                    .to_string(),
            ));
        }

        let effective_uid = unsafe { geteuid() };
        let owner = metadata.uid();
        if owner != 0 && owner != effective_uid {
            return Err(CkksError::Backend(
                "OpenFHE bridge program must be owned by root or the qdrant process user"
                    .to_string(),
            ));
        }

        let mut parent = path.parent();
        while let Some(directory) = parent {
            let directory_metadata = std::fs::symlink_metadata(directory).map_err(|err| {
                CkksError::Backend(format!(
                    "failed to inspect OpenFHE bridge parent directory: {err}"
                ))
            })?;
            if directory_metadata.file_type().is_symlink() || !directory_metadata.is_dir() {
                return Err(CkksError::Backend(
                    "OpenFHE bridge parent path must be a regular directory".to_string(),
                ));
            }
            if directory_metadata.permissions().mode() & 0o022 != 0 {
                return Err(CkksError::Backend(
                    "OpenFHE bridge parent directory must not be group/world-writable".to_string(),
                ));
            }
            let owner = directory_metadata.uid();
            if owner != 0 && owner != effective_uid {
                return Err(CkksError::Backend(
                    "OpenFHE bridge parent directory must be owned by root or the qdrant process user".to_string(),
                ));
            }
            parent = directory.parent();
        }
    }

    Ok(())
}

fn validate_bridge_program_sha256_b64(
    path: &Path,
    expected_sha256_b64: &str,
) -> Result<(), CkksError> {
    let expected = decode_bridge_sha256_pin(path, expected_sha256_b64)?;
    let actual = hash_bridge_program_for_sha256(path)?;
    validate_bridge_sha256_digest(path, &expected, &actual)
}

fn decode_bridge_sha256_pin(_path: &Path, expected_sha256_b64: &str) -> Result<Vec<u8>, CkksError> {
    if expected_sha256_b64.len() != BASE64URL_NOPAD_32_BYTE_LEN {
        return Err(CkksError::Backend(
            "OpenFHE bridge sha256 pin must decode to 32 bytes".to_string(),
        ));
    }
    let expected = BASE64URL_NOPAD
        .decode(expected_sha256_b64.as_bytes())
        .map_err(|_| {
            CkksError::Backend("OpenFHE bridge sha256 pin must be base64url-no-padding".to_string())
        })?;
    if expected.len() != 32 {
        return Err(CkksError::Backend(
            "OpenFHE bridge sha256 pin must decode to 32 bytes".to_string(),
        ));
    }

    Ok(expected)
}

fn validate_bridge_sha256_digest(
    _path: &Path,
    expected: &[u8],
    actual: &[u8],
) -> Result<(), CkksError> {
    if !constant_time_eq::constant_time_eq(actual, expected) {
        return Err(CkksError::Backend(
            "OpenFHE bridge sha256 pin does not match".to_string(),
        ));
    }

    Ok(())
}

struct BridgeSpawnProgram {
    path: PathBuf,
    _fd: Option<std::fs::File>,
}

impl BridgeSpawnProgram {
    fn path(&self) -> &Path {
        &self.path
    }
}

fn bridge_spawn_program(
    program: &Path,
    checked_program: bool,
    expected_sha256_b64: Option<&str>,
) -> Result<BridgeSpawnProgram, CkksError> {
    if !checked_program {
        return Ok(BridgeSpawnProgram {
            path: program.to_path_buf(),
            _fd: None,
        });
    }

    checked_bridge_spawn_program(program, expected_sha256_b64)
}

#[cfg(target_os = "linux")]
fn checked_bridge_spawn_program(
    program: &Path,
    expected_sha256_b64: Option<&str>,
) -> Result<BridgeSpawnProgram, CkksError> {
    use std::fs::OpenOptions;
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::OpenOptionsExt;

    validate_checked_bridge_program(program)?;

    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_CLOEXEC | nix::libc::O_NOFOLLOW)
        .open(program)
        .map_err(|err| {
            CkksError::Backend(format!(
                "failed to open OpenFHE bridge program for checked spawn: {err}"
            ))
        })?;
    let metadata = file.metadata().map_err(|err| {
        CkksError::Backend(format!(
            "failed to inspect OpenFHE bridge program for checked spawn: {err}"
        ))
    })?;
    if !metadata.is_file() {
        return Err(CkksError::Backend(
            "OpenFHE bridge program must remain a regular file for checked spawn".to_string(),
        ));
    }
    validate_bridge_program_size(program, metadata.len())?;

    let mut prefix = [0u8; 2];
    let prefix_len = file.read(&mut prefix).map_err(|err| {
        CkksError::Backend(format!(
            "failed to read OpenFHE bridge program for checked spawn: {err}"
        ))
    })?;
    let is_shebang_script = prefix_len == 2 && prefix == *b"#!";

    if let Some(expected_sha256_b64) = expected_sha256_b64 {
        let expected = decode_bridge_sha256_pin(program, expected_sha256_b64)?;
        let actual = hash_bridge_program_reader(program, &mut file, &prefix[..prefix_len])?;
        validate_bridge_sha256_digest(program, &expected, &actual)?;
    }
    if is_shebang_script {
        // Shebang interpreters reopen /proc/self/fd/<fd> after exec. Keep the
        // script fd inherited only for scripts; production bridge binaries keep
        // FD_CLOEXEC and do not inherit the checked executable fd.
        let flags = unsafe { nix::libc::fcntl(file.as_raw_fd(), nix::libc::F_GETFD) };
        if flags < 0 {
            return Err(CkksError::Backend(
                "failed to inspect OpenFHE bridge executable fd for checked spawn".to_string(),
            ));
        }
        let result = unsafe {
            nix::libc::fcntl(
                file.as_raw_fd(),
                nix::libc::F_SETFD,
                flags & !nix::libc::FD_CLOEXEC,
            )
        };
        if result < 0 {
            return Err(CkksError::Backend(
                "failed to prepare OpenFHE bridge script fd for checked spawn".to_string(),
            ));
        }
    }

    Ok(BridgeSpawnProgram {
        path: PathBuf::from(format!("/proc/self/fd/{}", file.as_raw_fd())),
        _fd: Some(file),
    })
}

#[cfg(not(target_os = "linux"))]
fn checked_bridge_spawn_program(
    program: &Path,
    expected_sha256_b64: Option<&str>,
) -> Result<BridgeSpawnProgram, CkksError> {
    validate_checked_bridge_program(program)?;
    if let Some(expected_sha256_b64) = expected_sha256_b64 {
        validate_bridge_program_sha256_b64(program, expected_sha256_b64)?;
    }
    Err(CkksError::Backend(
        "OpenFHE checked bridge spawn requires Linux fd-backed /proc/self/fd execution".to_string(),
    ))
}

#[cfg(unix)]
fn hash_bridge_program_for_sha256(path: &Path) -> Result<[u8; 32], CkksError> {
    use std::fs::OpenOptions;
    use std::os::unix::fs::OpenOptionsExt;

    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_CLOEXEC | nix::libc::O_NOFOLLOW)
        .open(path)
        .map_err(|err| {
            CkksError::Backend(format!(
                "failed to open OpenFHE bridge program for sha256 pinning: {err}"
            ))
        })?;
    let metadata = file.metadata().map_err(|err| {
        CkksError::Backend(format!(
            "failed to inspect OpenFHE bridge program for sha256 pinning: {err}"
        ))
    })?;
    if !metadata.is_file() {
        return Err(CkksError::Backend(
            "OpenFHE bridge program must remain a regular file while hashing sha256 pin"
                .to_string(),
        ));
    }
    validate_bridge_program_size(path, metadata.len())?;

    hash_bridge_program_reader(path, &mut file, &[])
}

#[cfg(not(unix))]
fn hash_bridge_program_for_sha256(path: &Path) -> Result<[u8; 32], CkksError> {
    let mut file = std::fs::File::open(path).map_err(|err| {
        CkksError::Backend(format!(
            "failed to read OpenFHE bridge program for sha256 pinning: {err}"
        ))
    })?;
    let metadata = file.metadata().map_err(|err| {
        CkksError::Backend(format!(
            "failed to inspect OpenFHE bridge program for sha256 pinning: {err}"
        ))
    })?;
    if !metadata.is_file() {
        return Err(CkksError::Backend(
            "OpenFHE bridge program must remain a regular file while hashing sha256 pin"
                .to_string(),
        ));
    }
    validate_bridge_program_size(path, metadata.len())?;
    hash_bridge_program_reader(path, &mut file, &[])
}

fn validate_bridge_program_size(_path: &Path, size: u64) -> Result<(), CkksError> {
    if size > MAX_BRIDGE_PROGRAM_SHA256_BYTES {
        return Err(CkksError::Backend(format!(
            "OpenFHE bridge program exceeds {MAX_BRIDGE_PROGRAM_SHA256_BYTES} bytes while hashing sha256 pin",
        )));
    }
    Ok(())
}

fn hash_bridge_program_reader(
    _path: &Path,
    reader: &mut impl Read,
    initial_bytes: &[u8],
) -> Result<[u8; 32], CkksError> {
    let mut hasher = Sha256::new();
    let mut total_read = initial_bytes.len() as u64;
    if total_read > MAX_BRIDGE_PROGRAM_SHA256_BYTES {
        return Err(CkksError::Backend(format!(
            "OpenFHE bridge program exceeds {MAX_BRIDGE_PROGRAM_SHA256_BYTES} bytes while hashing sha256 pin",
        )));
    }
    hasher.update(initial_bytes);

    let mut buffer = [0u8; 16 * 1024];
    loop {
        let read = reader.read(&mut buffer).map_err(|err| {
            CkksError::Backend(format!(
                "failed to read OpenFHE bridge program for sha256 pinning: {err}"
            ))
        })?;
        if read == 0 {
            break;
        }
        total_read = total_read.checked_add(read as u64).ok_or_else(|| {
            CkksError::Backend(format!(
                "OpenFHE bridge program exceeds {MAX_BRIDGE_PROGRAM_SHA256_BYTES} bytes while hashing sha256 pin",
            ))
        })?;
        if total_read > MAX_BRIDGE_PROGRAM_SHA256_BYTES {
            return Err(CkksError::Backend(format!(
                "OpenFHE bridge program exceeds {MAX_BRIDGE_PROGRAM_SHA256_BYTES} bytes while hashing sha256 pin",
            )));
        }
        hasher.update(&buffer[..read]);
    }

    Ok(hasher.finalize().into())
}

impl Drop for CommandOpenFheBackend {
    fn drop(&mut self) {
        if Arc::strong_count(&self.workers) != 1 {
            return;
        }
        if let Ok(mut workers) = self.workers.lock() {
            for worker in workers.drain(..) {
                let _ = worker.shutdown(false);
            }
        }
    }
}

impl CkksVectorBackend for CommandOpenFheBackend {
    fn encrypt(&self, input: CkksEncryptionInput<'_>) -> Result<Vec<u8>, CkksError> {
        let context_id = input.public_material.digest_for(input.parameters);
        let request = CommandOpenFheRequest {
            version: 1,
            operation: "encrypt",
            scheme: CKKS_SCHEME,
            collection: input.collection,
            point_id: input.point_id,
            vector_name: input.vector_name,
            context_id: context_id.clone(),
            parameters: Some(input.parameters),
            crypto_context: Some(BASE64URL_NOPAD.encode(input.public_material.crypto_context())),
            public_key: Some(BASE64URL_NOPAD.encode(input.public_material.public_key())),
            values: input.values,
        };
        let request_bytes = serialize_bridge_request(&request, "OpenFHE bridge request")?;
        let cached_request_bytes =
            serialize_bridge_request_without_public_material(&request, "OpenFHE bridge request")?;

        let expected_security_profile = expected_security_profile(input.parameters)?;
        self.send_bridge_request_with_context(
            &context_id,
            &request_bytes,
            &cached_request_bytes,
            |response_bytes| {
                decode_single_bridge_response(response_bytes, expected_security_profile)
            },
        )
    }

    fn encrypt_batch(
        &self,
        input: CkksBatchEncryptionInput<'_>,
    ) -> Result<Vec<Vec<u8>>, CkksError> {
        if input.items.is_empty() {
            return Ok(Vec::new());
        }
        if input.items.len() == 1 {
            let item = input.items[0];
            return self
                .encrypt(CkksEncryptionInput {
                    parameters: input.parameters,
                    public_material: input.public_material,
                    collection: input.collection,
                    point_id: item.point_id,
                    vector_name: input.vector_name,
                    values: item.values,
                })
                .map(|ciphertext| vec![ciphertext]);
        }

        let items: Vec<_> = input
            .items
            .iter()
            .map(|item| CommandOpenFheBatchItem {
                point_id: item.point_id,
                values: item.values,
            })
            .collect();
        let context_id = input.public_material.digest_for(input.parameters);
        let request = CommandOpenFheBatchRequest {
            version: 1,
            operation: "encrypt_batch",
            scheme: CKKS_SCHEME,
            collection: input.collection,
            vector_name: input.vector_name,
            context_id: context_id.clone(),
            parameters: Some(input.parameters),
            crypto_context: Some(BASE64URL_NOPAD.encode(input.public_material.crypto_context())),
            public_key: Some(BASE64URL_NOPAD.encode(input.public_material.public_key())),
            items,
        };
        let request_bytes = serialize_bridge_request(&request, "OpenFHE bridge batch request")?;
        let cached_request_bytes = serialize_bridge_request_without_public_material(
            &request,
            "OpenFHE bridge batch request",
        )?;

        let expected_security_profile = expected_security_profile(input.parameters)?;
        self.send_bridge_request_with_context(
            &context_id,
            &request_bytes,
            &cached_request_bytes,
            |response_bytes| {
                decode_batch_bridge_response(
                    response_bytes,
                    input.items.len(),
                    expected_security_profile,
                )
            },
        )
    }

    fn encrypt_query(&self, input: CkksQueryEncryptionInput<'_>) -> Result<Vec<u8>, CkksError> {
        let context_id = input.public_material.digest_for(input.parameters);
        let request = CommandOpenFheQueryRequest {
            version: 1,
            operation: "encrypt_query",
            scheme: CKKS_SCHEME,
            collection: input.collection,
            vector_name: input.vector_name,
            context_id: context_id.clone(),
            parameters: Some(input.parameters),
            crypto_context: Some(BASE64URL_NOPAD.encode(input.public_material.crypto_context())),
            public_key: Some(BASE64URL_NOPAD.encode(input.public_material.public_key())),
            values: input.values,
        };
        let request_bytes =
            serialize_bridge_request(&request, "OpenFHE bridge query encryption request")?;
        let cached_request_bytes = serialize_bridge_request_without_public_material(
            &request,
            "OpenFHE bridge query encryption request",
        )?;

        let expected_security_profile = expected_security_profile(input.parameters)?;
        self.send_bridge_request_with_context(
            &context_id,
            &request_bytes,
            &cached_request_bytes,
            |response_bytes| {
                decode_single_bridge_response(response_bytes, expected_security_profile)
            },
        )
    }

    fn score_plaintext_query(
        &self,
        input: CkksPlaintextQueryScoreInput<'_>,
    ) -> Result<f64, CkksError> {
        let context_id = input.public_material.digest_for(input.parameters);
        let request = CommandOpenFheScoreRequest {
            version: 1,
            operation: "score_plaintext_query",
            scheme: CKKS_SCHEME,
            collection: input.collection,
            point_id: input.point_id,
            vector_name: input.vector_name,
            distance: input.distance,
            context_id: context_id.clone(),
            parameters: Some(input.parameters),
            crypto_context: Some(BASE64URL_NOPAD.encode(input.public_material.crypto_context())),
            public_key: Some(BASE64URL_NOPAD.encode(input.public_material.public_key())),
            query_values: input.query_values,
            ciphertext: BASE64URL_NOPAD.encode(input.ciphertext),
        };
        let request_bytes = serialize_bridge_request(&request, "OpenFHE bridge score request")?;
        let cached_request_bytes = serialize_bridge_request_without_public_material(
            &request,
            "OpenFHE bridge score request",
        )?;

        let expected_security_profile = expected_security_profile(input.parameters)?;
        self.send_bridge_request_with_context(
            &context_id,
            &request_bytes,
            &cached_request_bytes,
            |response_bytes| {
                decode_score_bridge_response(response_bytes, expected_security_profile)
            },
        )
    }

    fn score_plaintext_query_batch(
        &self,
        input: CkksPlaintextQueryScoreBatchInput<'_>,
    ) -> Result<Vec<f64>, CkksError> {
        if input.items.is_empty() {
            return Ok(Vec::new());
        }
        if input.items.len() == 1 {
            let item = input.items[0];
            return self
                .score_plaintext_query(CkksPlaintextQueryScoreInput {
                    parameters: input.parameters,
                    public_material: input.public_material,
                    collection: input.collection,
                    point_id: item.point_id,
                    vector_name: input.vector_name,
                    distance: input.distance,
                    query_values: input.query_values,
                    ciphertext: item.ciphertext,
                })
                .map(|score| vec![score]);
        }

        let items = input
            .items
            .iter()
            .map(|item| CommandOpenFheScoreBatchItem {
                point_id: item.point_id,
                ciphertext: BASE64URL_NOPAD.encode(item.ciphertext),
            })
            .collect::<Vec<_>>();
        let context_id = input.public_material.digest_for(input.parameters);
        let request = CommandOpenFheScoreBatchRequest {
            version: 1,
            operation: "score_plaintext_query_batch",
            scheme: CKKS_SCHEME,
            collection: input.collection,
            vector_name: input.vector_name,
            distance: input.distance,
            context_id: context_id.clone(),
            parameters: Some(input.parameters),
            crypto_context: Some(BASE64URL_NOPAD.encode(input.public_material.crypto_context())),
            public_key: Some(BASE64URL_NOPAD.encode(input.public_material.public_key())),
            query_values: input.query_values,
            items,
        };
        let request_bytes =
            serialize_bridge_request(&request, "OpenFHE bridge score batch request")?;
        let cached_request_bytes = serialize_bridge_request_without_public_material(
            &request,
            "OpenFHE bridge score batch request",
        )?;

        let expected_security_profile = expected_security_profile(input.parameters)?;
        self.send_bridge_request_with_context(
            &context_id,
            &request_bytes,
            &cached_request_bytes,
            |response_bytes| {
                decode_score_batch_bridge_response(
                    response_bytes,
                    input.items.len(),
                    expected_security_profile,
                )
            },
        )
    }

    fn score_encrypted_query(
        &self,
        input: CkksEncryptedQueryScoreInput<'_>,
    ) -> Result<f64, CkksError> {
        let context_id = input.public_material.digest_for(input.parameters);
        let request = CommandOpenFheEncryptedScoreRequest {
            version: 1,
            operation: "score_encrypted_query",
            scheme: CKKS_SCHEME,
            collection: input.collection,
            point_id: input.point_id,
            vector_name: input.vector_name,
            distance: input.distance,
            context_id: context_id.clone(),
            parameters: Some(input.parameters),
            crypto_context: Some(BASE64URL_NOPAD.encode(input.public_material.crypto_context())),
            public_key: Some(BASE64URL_NOPAD.encode(input.public_material.public_key())),
            encrypted_query: BASE64URL_NOPAD.encode(input.encrypted_query),
            ciphertext: BASE64URL_NOPAD.encode(input.ciphertext),
        };
        let request_bytes =
            serialize_bridge_request(&request, "OpenFHE bridge encrypted-query score request")?;
        let cached_request_bytes = serialize_bridge_request_without_public_material(
            &request,
            "OpenFHE bridge encrypted-query score request",
        )?;

        let expected_security_profile = expected_security_profile(input.parameters)?;
        self.send_bridge_request_with_context(
            &context_id,
            &request_bytes,
            &cached_request_bytes,
            |response_bytes| {
                decode_score_bridge_response(response_bytes, expected_security_profile)
            },
        )
    }

    fn score_encrypted_query_batch(
        &self,
        input: CkksEncryptedQueryScoreBatchInput<'_>,
    ) -> Result<Vec<f64>, CkksError> {
        if input.items.is_empty() {
            return Ok(Vec::new());
        }
        if input.items.len() == 1 {
            let item = input.items[0];
            return self
                .score_encrypted_query(CkksEncryptedQueryScoreInput {
                    parameters: input.parameters,
                    public_material: input.public_material,
                    collection: input.collection,
                    point_id: item.point_id,
                    vector_name: input.vector_name,
                    distance: input.distance,
                    encrypted_query: input.encrypted_query,
                    ciphertext: item.ciphertext,
                })
                .map(|score| vec![score]);
        }

        let items = input
            .items
            .iter()
            .map(|item| CommandOpenFheScoreBatchItem {
                point_id: item.point_id,
                ciphertext: BASE64URL_NOPAD.encode(item.ciphertext),
            })
            .collect::<Vec<_>>();
        let context_id = input.public_material.digest_for(input.parameters);
        let request = CommandOpenFheEncryptedScoreBatchRequest {
            version: 1,
            operation: "score_encrypted_query_batch",
            scheme: CKKS_SCHEME,
            collection: input.collection,
            vector_name: input.vector_name,
            distance: input.distance,
            context_id: context_id.clone(),
            parameters: Some(input.parameters),
            crypto_context: Some(BASE64URL_NOPAD.encode(input.public_material.crypto_context())),
            public_key: Some(BASE64URL_NOPAD.encode(input.public_material.public_key())),
            encrypted_query: BASE64URL_NOPAD.encode(input.encrypted_query),
            items,
        };
        let request_bytes = serialize_bridge_request(
            &request,
            "OpenFHE bridge encrypted-query score batch request",
        )?;
        let cached_request_bytes = serialize_bridge_request_without_public_material(
            &request,
            "OpenFHE bridge encrypted-query score batch request",
        )?;

        let expected_security_profile = expected_security_profile(input.parameters)?;
        self.send_bridge_request_with_context(
            &context_id,
            &request_bytes,
            &cached_request_bytes,
            |response_bytes| {
                decode_score_batch_bridge_response(
                    response_bytes,
                    input.items.len(),
                    expected_security_profile,
                )
            },
        )
    }
}

impl CommandOpenFheBackend {
    fn send_bridge_request_with_context<T>(
        &self,
        context_id: &str,
        request_with_public_material: &[u8],
        request_with_registered_context: &[u8],
        decode_response: impl Fn(&[u8]) -> Result<T, CkksError>,
    ) -> Result<T, CkksError> {
        self.send_bridge_request_impl(
            Some(context_id),
            request_with_public_material,
            Some(request_with_registered_context),
            decode_response,
        )
    }

    fn send_bridge_request_impl<T>(
        &self,
        context_id: Option<&str>,
        request_with_public_material: &[u8],
        request_with_registered_context: Option<&[u8]>,
        decode_response: impl Fn(&[u8]) -> Result<T, CkksError>,
    ) -> Result<T, CkksError> {
        for attempt in 0..=1 {
            // `worker_process` returns only after atomically reserving a worker.
            // The reservation is held for the whole request, so stdin/stdout
            // access does not need a second worker-local request mutex.
            let worker_reservation = self.worker_process()?;
            let worker_process = Arc::clone(worker_reservation.worker());
            if worker_process.stderr_truncated.load(Ordering::Relaxed) {
                self.discard_worker(&worker_process, false)?;
                return Err(CkksError::Backend(format!(
                    "OpenFHE bridge stderr exceeded {} bytes",
                    self.max_output_bytes,
                )));
            }

            let context_registered = if let Some(context_id) = context_id {
                worker_process
                    .registered_contexts
                    .lock()
                    .map_err(|_| {
                        CkksError::Backend(
                            "OpenFHE bridge context cache mutex was poisoned".to_string(),
                        )
                    })?
                    .contains(context_id)
            } else {
                false
            };
            let selected_request = if context_registered {
                request_with_registered_context.unwrap_or(request_with_public_material)
            } else {
                request_with_public_material
            };
            let mut request_bytes = Zeroizing::new(selected_request.to_vec());
            request_bytes.push(b'\n');

            let timeout = self.timeout;
            match write_bridge_request_with_deadline(&worker_process, request_bytes, timeout) {
                Ok(()) => {}
                Err(BridgeWriteError::Timeout) => {
                    // A bridge that stopped draining stdin would otherwise park this thread and
                    // its worker reservation forever once the request exceeded the pipe buffer.
                    self.discard_worker(&worker_process, false)?;
                    return Err(CkksError::Backend(format!(
                        "OpenFHE bridge did not accept the request within {} ms",
                        timeout.as_millis(),
                    )));
                }
                Err(BridgeWriteError::Io(err)) => {
                    let retry = attempt == 0
                        && matches!(
                            err.kind(),
                            io::ErrorKind::BrokenPipe | io::ErrorKind::UnexpectedEof
                        );
                    self.discard_worker(&worker_process, false)?;
                    if retry {
                        continue;
                    }
                    return Err(CkksError::Backend(format!(
                        "failed to write OpenFHE bridge request: {err}",
                    )));
                }
            }

            let response = worker_process
                .stdout_rx
                .lock()
                .map_err(|_| {
                    CkksError::Backend(
                        "OpenFHE bridge stdout receiver mutex was poisoned".to_string(),
                    )
                })?
                .recv_timeout(timeout);
            let (response_bytes, truncated) = match response {
                Ok(BridgeStdoutEvent::Response {
                    mut bytes,
                    truncated,
                }) => {
                    if bytes.last() == Some(&b'\n') {
                        bytes.pop();
                        if bytes.last() == Some(&b'\r') {
                            bytes.pop();
                        }
                    }
                    (bytes, truncated)
                }
                Ok(BridgeStdoutEvent::Eof) => {
                    if worker_process.stderr_truncated.load(Ordering::Relaxed) {
                        self.discard_worker(&worker_process, false)?;
                        return Err(CkksError::Backend(format!(
                            "OpenFHE bridge stderr exceeded {} bytes",
                            self.max_output_bytes,
                        )));
                    }
                    let retry = attempt == 0;
                    self.discard_worker(&worker_process, false)?;
                    if retry {
                        continue;
                    }
                    return Err(CkksError::Backend(
                        "OpenFHE bridge returned an empty response".to_string(),
                    ));
                }
                Ok(BridgeStdoutEvent::Error(err)) => {
                    let retry = attempt == 0
                        && matches!(
                            err.kind(),
                            io::ErrorKind::BrokenPipe | io::ErrorKind::UnexpectedEof
                        );
                    self.discard_worker(&worker_process, false)?;
                    if retry {
                        continue;
                    }
                    return Err(CkksError::Backend(format!(
                        "failed to read OpenFHE bridge response: {err}",
                    )));
                }
                Ok(BridgeStdoutEvent::StderrExceeded) => {
                    self.discard_worker(&worker_process, false)?;
                    return Err(CkksError::Backend(format!(
                        "OpenFHE bridge stderr exceeded {} bytes",
                        self.max_output_bytes,
                    )));
                }
                Err(mpsc::RecvTimeoutError::Timeout) => {
                    self.discard_worker(&worker_process, false)?;
                    return Err(CkksError::Backend(format!(
                        "OpenFHE bridge timed out after {} ms",
                        timeout.as_millis(),
                    )));
                }
                Err(mpsc::RecvTimeoutError::Disconnected) => {
                    let retry = attempt == 0;
                    self.discard_worker(&worker_process, false)?;
                    if retry {
                        continue;
                    }
                    return Err(CkksError::Backend(
                        "bridge stdout reader disconnected".to_string(),
                    ));
                }
            };
            if truncated {
                self.discard_worker(&worker_process, false)?;
                return Err(CkksError::Backend(format!(
                    "OpenFHE bridge stdout exceeded {} bytes",
                    self.max_output_bytes,
                )));
            }
            if response_bytes.is_empty() {
                if worker_process.stderr_truncated.load(Ordering::Relaxed) {
                    self.discard_worker(&worker_process, false)?;
                    return Err(CkksError::Backend(format!(
                        "OpenFHE bridge stderr exceeded {} bytes",
                        self.max_output_bytes,
                    )));
                }
                let retry = attempt == 0;
                self.discard_worker(&worker_process, false)?;
                if retry {
                    continue;
                }
                return Err(CkksError::Backend(
                    "OpenFHE bridge returned an empty response".to_string(),
                ));
            }
            if worker_process.stderr_truncated.load(Ordering::Relaxed) {
                self.discard_worker(&worker_process, false)?;
                return Err(CkksError::Backend(format!(
                    "OpenFHE bridge stderr exceeded {} bytes",
                    self.max_output_bytes,
                )));
            }
            let bridge_status = worker_process.try_wait()?;
            match bridge_status {
                Some(status) => {
                    self.discard_worker(&worker_process, false)?;
                    if !status.success() {
                        return Err(CkksError::Backend(format!(
                            "OpenFHE bridge exited with status {}",
                            status,
                        )));
                    }
                }
                None => {}
            }

            return match decode_response(&response_bytes) {
                Ok(response) => {
                    if let Some(context_id) = context_id
                        && !context_registered
                    {
                        worker_process
                            .registered_contexts
                            .lock()
                            .map_err(|_| {
                                CkksError::Backend(
                                    "OpenFHE bridge context cache mutex was poisoned".to_string(),
                                )
                            })?
                            .insert(context_id.to_string());
                    }
                    Ok(response)
                }
                Err(err) => {
                    self.discard_worker(&worker_process, false)?;
                    Err(err)
                }
            };
        }

        Err(CkksError::Backend(
            "OpenFHE bridge retry budget was exhausted".to_string(),
        ))
    }

    fn worker_process(&self) -> Result<WorkerReservation, CkksError> {
        // A momentarily saturated pool must not fail requests outright: sandboxed bridge kinds
        // run a single worker, so back-to-back searches would otherwise error instead of
        // queueing briefly. Wait a bounded time for a worker to free up before giving up.
        let deadline = std::time::Instant::now() + WORKER_RESERVATION_WAIT;
        loop {
            let mut workers = self.workers.lock().map_err(|_| {
                CkksError::Backend("OpenFHE bridge workers mutex was poisoned".to_string())
            })?;

            let mut worker_index = 0;
            while worker_index < workers.len() {
                let worker_process = &workers[worker_index];
                if worker_process.stderr_truncated.load(Ordering::Relaxed) {
                    let worker_process = workers.swap_remove(worker_index);
                    worker_process.shutdown(false)?;
                    continue;
                }
                if worker_process.try_wait()?.is_some() {
                    let worker_process = workers.swap_remove(worker_index);
                    worker_process.shutdown(false)?;
                    continue;
                }
                worker_index += 1;
            }

            for worker_process in workers.iter() {
                if worker_process.try_reserve_request() {
                    return Ok(WorkerReservation::reserved(Arc::clone(worker_process)));
                }
            }

            let spawning = self.spawning.load(Ordering::Acquire);
            if workers.len().saturating_add(spawning) < self.pool_size.get() {
                // Reserve a pool slot and spawn without holding the lock: hashing the bridge
                // binary and starting the process took long enough to stall every request
                // that only needed an idle worker.
                self.spawning.fetch_add(1, Ordering::AcqRel);
                drop(workers);
                break;
            }
            if std::time::Instant::now() >= deadline {
                return Err(CkksError::Backend(format!(
                    "OpenFHE bridge worker pool is exhausted; all {} workers stayed busy for {:?}",
                    self.pool_size.get(),
                    WORKER_RESERVATION_WAIT,
                )));
            }
            drop(workers);
            std::thread::sleep(WORKER_RESERVATION_POLL);
        }
        let spawn_slot = SpawnSlot(Arc::clone(&self.spawning));

        let spawn_program = bridge_spawn_program(
            &self.program,
            self.checked_program,
            self.expected_sha256_b64.as_deref(),
        )?;

        let mut command = Command::new(spawn_program.path());
        command
            .args(&self.args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        if self.checked_program {
            command.env_clear();
            command.current_dir("/");
            // Preserve only a fixed search path for shebangs that use
            // `/usr/bin/env`. Production bridge binaries should not depend on
            // ambient service environment.
            command.env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin");
        } else {
            for (name, _) in std::env::vars_os() {
                let name_string = name.to_string_lossy();
                if name_string == "QDRANT" || name_string.starts_with("QDRANT_") {
                    command.env_remove(name);
                }
            }
        }
        for name in &self.sensitive_env_names {
            command.env_remove(name);
        }
        configure_bridge_command_sandbox(&mut command, self.checked_program, self.sandbox);

        let mut child = spawn_bridge_child(command)
            .map_err(|err| CkksError::Backend(format!("failed to start OpenFHE bridge: {err}")))?;
        let stdin = child
            .stdin
            .take()
            .ok_or_else(|| CkksError::Backend("failed to open bridge stdin".to_string()))?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| CkksError::Backend("failed to open bridge stdout".to_string()))?;
        let stderr = child
            .stderr
            .take()
            .ok_or_else(|| CkksError::Backend("failed to open bridge stderr".to_string()))?;

        let (stdout_tx, stdout_rx) = mpsc::channel();
        let stderr_tx = stdout_tx.clone();
        let max_output_bytes = self.max_output_bytes;
        let stdout_thread = thread::spawn(move || {
            let mut stdout = BufReader::new(stdout);
            loop {
                let mut bytes = Vec::new();
                let mut truncated = false;
                let mut byte = [0u8; 1];
                loop {
                    match stdout.read(&mut byte) {
                        Ok(0) => {
                            if stdout_tx.send(BridgeStdoutEvent::Eof).is_err() {
                                return;
                            }
                            return;
                        }
                        Ok(_) => {
                            if bytes.len() == max_output_bytes {
                                truncated = true;
                                break;
                            }
                            bytes.push(byte[0]);
                            if byte[0] == b'\n' {
                                break;
                            }
                        }
                        Err(err) => {
                            let _ = stdout_tx.send(BridgeStdoutEvent::Error(err));
                            return;
                        }
                    }
                }
                if stdout_tx
                    .send(BridgeStdoutEvent::Response { bytes, truncated })
                    .is_err()
                {
                    return;
                }
            }
        });

        let stderr_truncated = Arc::new(AtomicBool::new(false));
        let stderr_truncated_thread = Arc::clone(&stderr_truncated);
        let max_output_bytes = self.max_output_bytes;
        let stderr_thread = thread::spawn(move || {
            let mut stderr = stderr;
            let mut buffer = [0u8; 4096];
            let mut total = 0usize;
            loop {
                let read = stderr.read(&mut buffer)?;
                if read == 0 {
                    return Ok(());
                }
                total = total.saturating_add(read);
                if total > max_output_bytes {
                    stderr_truncated_thread.store(true, Ordering::Relaxed);
                    let _ = stderr_tx.send(BridgeStdoutEvent::StderrExceeded);
                    return Ok(());
                }
            }
        });

        let worker_process = Arc::new(WorkerProcess {
            child: Mutex::new(child),
            stdin: Mutex::new(stdin),
            stdout_rx: Mutex::new(stdout_rx),
            stderr_truncated,
            registered_contexts: Mutex::new(HashSet::new()),
            terminated: AtomicBool::new(false),
            reserved: AtomicBool::new(true),
            reader_threads: Mutex::new(WorkerReaderThreads {
                stdout: Some(stdout_thread),
                stderr: Some(stderr_thread),
            }),
        });
        let mut workers = self.workers.lock().map_err(|_| {
            CkksError::Backend("OpenFHE bridge workers mutex was poisoned".to_string())
        })?;
        workers.push(Arc::clone(&worker_process));
        // Release the spawn slot while the pool lock is still held: otherwise another caller
        // briefly counts this worker twice (pushed and still spawning) and may report the pool
        // as exhausted although a slot is free.
        drop(spawn_slot);
        drop(workers);
        Ok(WorkerReservation::reserved(worker_process))
    }

    fn discard_worker(
        &self,
        worker_process: &Arc<WorkerProcess>,
        join_readers: bool,
    ) -> Result<(), CkksError> {
        worker_process.shutdown(join_readers)?;
        let mut workers = self.workers.lock().map_err(|_| {
            CkksError::Backend("OpenFHE bridge workers mutex was poisoned".to_string())
        })?;
        if let Some(index) = workers
            .iter()
            .position(|current| Arc::ptr_eq(current, worker_process))
        {
            workers.swap_remove(index);
        }
        Ok(())
    }
}

enum BridgeWriteError {
    Timeout,
    Io(io::Error),
}

/// Writes one request line to the bridge from a helper thread and waits at most `timeout` for
/// the write to complete. On timeout the caller kills the worker, which closes the pipe and
/// unblocks the helper; the request bytes stay zeroized on every path.
/// Spawns a bridge child from a thread that lives as long as the process.
///
/// The child asks for `PR_SET_PDEATHSIG`, and Linux delivers that signal when the *thread* that
/// spawned the child exits, not when the process does. Request threads come from pools that
/// recycle idle threads, so a worker spawned on one of them was killed mid-flight for every other
/// caller as soon as that thread was reaped. One dedicated spawner thread keeps the parent-death
/// signal meaning what it was meant to mean: the bridge dies with Qdrant.
fn spawn_bridge_child(command: Command) -> io::Result<Child> {
    type SpawnJob = (Command, mpsc::Sender<io::Result<Child>>);
    static SPAWNER: OnceLock<Option<Mutex<mpsc::Sender<SpawnJob>>>> = OnceLock::new();
    let spawner = SPAWNER
        .get_or_init(|| {
            let (job_tx, job_rx) = mpsc::channel::<SpawnJob>();
            thread::Builder::new()
                .name("openfhe-bridge-spawner".to_string())
                .spawn(move || {
                    for (mut command, reply) in job_rx {
                        let _ = reply.send(command.spawn());
                    }
                })
                .ok()
                .map(|_| Mutex::new(job_tx))
        })
        .as_ref()
        .ok_or_else(|| io::Error::other("failed to start the OpenFHE bridge spawner thread"))?;
    let (reply_tx, reply_rx) = mpsc::channel();
    spawner
        .lock()
        .map_err(|_| io::Error::other("OpenFHE bridge spawner mutex was poisoned"))?
        .send((command, reply_tx))
        .map_err(|_| io::Error::other("OpenFHE bridge spawner thread is gone"))?;
    reply_rx
        .recv()
        .map_err(|_| io::Error::other("OpenFHE bridge spawner thread dropped the request"))?
}

fn write_bridge_request_with_deadline(
    worker_process: &Arc<WorkerProcess>,
    request_bytes: Zeroizing<Vec<u8>>,
    timeout: Duration,
) -> Result<(), BridgeWriteError> {
    let (result_tx, result_rx) = mpsc::sync_channel(1);
    let writer_process = Arc::clone(worker_process);
    let spawned = thread::Builder::new()
        .name("openfhe-bridge-write".to_string())
        .spawn(move || {
            let result = match writer_process.stdin.lock() {
                Ok(mut stdin) => stdin
                    .write_all(request_bytes.as_slice())
                    .and_then(|_| stdin.flush()),
                Err(_) => Err(io::Error::other("OpenFHE bridge stdin mutex was poisoned")),
            };
            let _ = result_tx.send(result);
        });
    if let Err(err) = spawned {
        return Err(BridgeWriteError::Io(err));
    }
    match result_rx.recv_timeout(timeout) {
        Ok(result) => result.map_err(BridgeWriteError::Io),
        Err(mpsc::RecvTimeoutError::Timeout) => Err(BridgeWriteError::Timeout),
        Err(mpsc::RecvTimeoutError::Disconnected) => Err(BridgeWriteError::Io(io::Error::other(
            "OpenFHE bridge writer thread exited without a result",
        ))),
    }
}

fn serialize_bridge_request<T: Serialize>(
    request: &T,
    request_name: &str,
) -> Result<Zeroizing<Vec<u8>>, CkksError> {
    serde_json::to_vec(request)
        .map(Zeroizing::new)
        .map_err(|err| CkksError::Backend(format!("failed to serialize {request_name}: {err}")))
}

trait CommandOpenFheContextRequest: Serialize + Clone {
    fn remove_public_material(&mut self);
}

fn serialize_bridge_request_without_public_material<T: CommandOpenFheContextRequest>(
    request: &T,
    request_name: &str,
) -> Result<Zeroizing<Vec<u8>>, CkksError> {
    let mut request = request.clone();
    request.remove_public_material();
    serde_json::to_vec(&request)
        .map(Zeroizing::new)
        .map_err(|err| {
            CkksError::Backend(format!(
                "failed to serialize cached-context {request_name}: {err}"
            ))
        })
}

#[cfg(target_os = "linux")]
#[repr(C)]
struct LandlockRulesetAttr {
    handled_access_fs: u64,
}

#[cfg(target_os = "linux")]
const LANDLOCK_CREATE_RULESET_VERSION: u32 = 1;
#[cfg(target_os = "linux")]
const LANDLOCK_ACCESS_FS_WRITE_FILE: u64 = 1 << 1;
#[cfg(target_os = "linux")]
const LANDLOCK_ACCESS_FS_REMOVE_DIR: u64 = 1 << 4;
#[cfg(target_os = "linux")]
const LANDLOCK_ACCESS_FS_REMOVE_FILE: u64 = 1 << 5;
#[cfg(target_os = "linux")]
const LANDLOCK_ACCESS_FS_MAKE_CHAR: u64 = 1 << 6;
#[cfg(target_os = "linux")]
const LANDLOCK_ACCESS_FS_MAKE_DIR: u64 = 1 << 7;
#[cfg(target_os = "linux")]
const LANDLOCK_ACCESS_FS_MAKE_REG: u64 = 1 << 8;
#[cfg(target_os = "linux")]
const LANDLOCK_ACCESS_FS_MAKE_SOCK: u64 = 1 << 9;
#[cfg(target_os = "linux")]
const LANDLOCK_ACCESS_FS_MAKE_FIFO: u64 = 1 << 10;
#[cfg(target_os = "linux")]
const LANDLOCK_ACCESS_FS_MAKE_BLOCK: u64 = 1 << 11;
#[cfg(target_os = "linux")]
const LANDLOCK_ACCESS_FS_MAKE_SYM: u64 = 1 << 12;
#[cfg(target_os = "linux")]
const LANDLOCK_ACCESS_FS_REFER: u64 = 1 << 13;
#[cfg(target_os = "linux")]
const LANDLOCK_ACCESS_FS_TRUNCATE: u64 = 1 << 14;

#[cfg(target_os = "linux")]
fn linux_landlock_abi_version() -> io::Result<i64> {
    let version = unsafe {
        nix::libc::syscall(
            nix::libc::SYS_landlock_create_ruleset,
            std::ptr::null::<LandlockRulesetAttr>(),
            0usize,
            LANDLOCK_CREATE_RULESET_VERSION,
        )
    };
    if version < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(version)
}

#[cfg(target_os = "linux")]
fn landlock_write_deny_access_for_abi(abi_version: i64) -> u64 {
    let mut access = LANDLOCK_ACCESS_FS_WRITE_FILE
        | LANDLOCK_ACCESS_FS_REMOVE_DIR
        | LANDLOCK_ACCESS_FS_REMOVE_FILE
        | LANDLOCK_ACCESS_FS_MAKE_CHAR
        | LANDLOCK_ACCESS_FS_MAKE_DIR
        | LANDLOCK_ACCESS_FS_MAKE_REG
        | LANDLOCK_ACCESS_FS_MAKE_SOCK
        | LANDLOCK_ACCESS_FS_MAKE_FIFO
        | LANDLOCK_ACCESS_FS_MAKE_BLOCK
        | LANDLOCK_ACCESS_FS_MAKE_SYM;
    if abi_version >= 2 {
        access |= LANDLOCK_ACCESS_FS_REFER;
    }
    if abi_version >= 3 {
        access |= LANDLOCK_ACCESS_FS_TRUNCATE;
    }
    access
}

#[cfg(target_os = "linux")]
fn apply_linux_landlock_write_deny() -> io::Result<()> {
    let abi_version = linux_landlock_abi_version()?;
    if abi_version < 1 {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "Linux Landlock ABI is unavailable",
        ));
    }

    let attr = LandlockRulesetAttr {
        handled_access_fs: landlock_write_deny_access_for_abi(abi_version),
    };
    let ruleset_fd = unsafe {
        nix::libc::syscall(
            nix::libc::SYS_landlock_create_ruleset,
            &attr as *const LandlockRulesetAttr,
            std::mem::size_of::<LandlockRulesetAttr>(),
            0u32,
        )
    };
    if ruleset_fd < 0 {
        return Err(io::Error::last_os_error());
    }

    let restrict_result =
        unsafe { nix::libc::syscall(nix::libc::SYS_landlock_restrict_self, ruleset_fd, 0u32) };
    let restrict_error = if restrict_result != 0 {
        Some(io::Error::last_os_error())
    } else {
        None
    };
    let close_result = unsafe { nix::libc::close(ruleset_fd as nix::libc::c_int) };
    if let Some(err) = restrict_error {
        return Err(err);
    }
    if close_result != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn apply_linux_network_namespace_egress_deny() -> io::Result<()> {
    let result = unsafe { nix::libc::unshare(nix::libc::CLONE_NEWNET) };
    if result != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn bridge_sandbox_uses_landlock(sandbox: BridgeSandbox) -> bool {
    matches!(
        sandbox,
        BridgeSandbox::LinuxLandlockWriteDeny
            | BridgeSandbox::LinuxLandlockWriteDenyNetworkNamespace
    )
}

#[cfg(target_os = "linux")]
fn bridge_sandbox_uses_network_namespace(sandbox: BridgeSandbox) -> bool {
    matches!(
        sandbox,
        BridgeSandbox::LinuxLandlockWriteDenyNetworkNamespace
    )
}

#[cfg(target_os = "linux")]
fn configure_bridge_command_sandbox(
    command: &mut Command,
    checked_program: bool,
    sandbox: BridgeSandbox,
) {
    // This is not a full sandbox, but it prevents the bridge process from
    // gaining privileges through setuid binaries or file capabilities after
    // Qdrant has already validated the executable path and ownership. It also
    // disables core dumps for the plaintext-bearing bridge process, restricts
    // default permissions for any bridge-created files, and blocks regular
    // file writes for checked production bridge binaries. Network-namespace
    // sandbox kinds additionally detach the bridge from the host network
    // namespace before exec so a bridge with no network dependency has no
    // route to external egress. The
    // parent-death signal prevents a bridge from staying alive as an orphan if
    // Qdrant exits while the bridge is handling plaintext embeddings.
    unsafe {
        command.pre_exec(move || {
            if bridge_sandbox_uses_network_namespace(sandbox) {
                apply_linux_network_namespace_egress_deny()?;
            }
            let result = nix::libc::prctl(nix::libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
            if result != 0 {
                return Err(io::Error::last_os_error());
            }
            let result = nix::libc::prctl(nix::libc::PR_SET_PDEATHSIG, nix::libc::SIGKILL, 0, 0, 0);
            if result != 0 {
                return Err(io::Error::last_os_error());
            }
            let zero_limit = nix::libc::rlimit {
                rlim_cur: 0,
                rlim_max: 0,
            };
            let result = nix::libc::setrlimit(nix::libc::RLIMIT_CORE, &zero_limit);
            if result != 0 {
                return Err(io::Error::last_os_error());
            }
            if checked_program {
                let result = nix::libc::setrlimit(nix::libc::RLIMIT_FSIZE, &zero_limit);
                if result != 0 {
                    return Err(io::Error::last_os_error());
                }
            }
            if bridge_sandbox_uses_landlock(sandbox) {
                apply_linux_landlock_write_deny()?;
            }
            nix::libc::umask(0o077);
            Ok(())
        });
    }
}

#[cfg(not(target_os = "linux"))]
fn configure_bridge_command_sandbox(
    _command: &mut Command,
    _checked_program: bool,
    _sandbox: BridgeSandbox,
) {
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "snake_case")]
struct CommandOpenFheRequest<'a> {
    version: u8,
    operation: &'static str,
    scheme: &'static str,
    collection: &'a str,
    point_id: &'a str,
    vector_name: &'a str,
    context_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    parameters: Option<&'a CkksParameters>,
    #[serde(skip_serializing_if = "Option::is_none")]
    crypto_context: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    public_key: Option<String>,
    values: &'a [f64],
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "snake_case")]
struct CommandOpenFheBatchRequest<'a> {
    version: u8,
    operation: &'static str,
    scheme: &'static str,
    collection: &'a str,
    vector_name: &'a str,
    context_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    parameters: Option<&'a CkksParameters>,
    #[serde(skip_serializing_if = "Option::is_none")]
    crypto_context: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    public_key: Option<String>,
    items: Vec<CommandOpenFheBatchItem<'a>>,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "snake_case")]
struct CommandOpenFheBatchItem<'a> {
    point_id: &'a str,
    values: &'a [f64],
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "snake_case")]
struct CommandOpenFheQueryRequest<'a> {
    version: u8,
    operation: &'static str,
    scheme: &'static str,
    collection: &'a str,
    vector_name: &'a str,
    context_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    parameters: Option<&'a CkksParameters>,
    #[serde(skip_serializing_if = "Option::is_none")]
    crypto_context: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    public_key: Option<String>,
    values: &'a [f64],
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "snake_case")]
struct CommandOpenFheScoreRequest<'a> {
    version: u8,
    operation: &'static str,
    scheme: &'static str,
    collection: &'a str,
    point_id: &'a str,
    vector_name: &'a str,
    distance: &'a str,
    context_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    parameters: Option<&'a CkksParameters>,
    #[serde(skip_serializing_if = "Option::is_none")]
    crypto_context: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    public_key: Option<String>,
    query_values: &'a [f64],
    ciphertext: String,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "snake_case")]
struct CommandOpenFheScoreBatchRequest<'a> {
    version: u8,
    operation: &'static str,
    scheme: &'static str,
    collection: &'a str,
    vector_name: &'a str,
    distance: &'a str,
    context_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    parameters: Option<&'a CkksParameters>,
    #[serde(skip_serializing_if = "Option::is_none")]
    crypto_context: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    public_key: Option<String>,
    query_values: &'a [f64],
    items: Vec<CommandOpenFheScoreBatchItem<'a>>,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "snake_case")]
struct CommandOpenFheScoreBatchItem<'a> {
    point_id: &'a str,
    ciphertext: String,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "snake_case")]
struct CommandOpenFheEncryptedScoreRequest<'a> {
    version: u8,
    operation: &'static str,
    scheme: &'static str,
    collection: &'a str,
    point_id: &'a str,
    vector_name: &'a str,
    distance: &'a str,
    context_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    parameters: Option<&'a CkksParameters>,
    #[serde(skip_serializing_if = "Option::is_none")]
    crypto_context: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    public_key: Option<String>,
    encrypted_query: String,
    ciphertext: String,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "snake_case")]
struct CommandOpenFheEncryptedScoreBatchRequest<'a> {
    version: u8,
    operation: &'static str,
    scheme: &'static str,
    collection: &'a str,
    vector_name: &'a str,
    distance: &'a str,
    context_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    parameters: Option<&'a CkksParameters>,
    #[serde(skip_serializing_if = "Option::is_none")]
    crypto_context: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    public_key: Option<String>,
    encrypted_query: String,
    items: Vec<CommandOpenFheScoreBatchItem<'a>>,
}

macro_rules! impl_command_openfhe_context_request {
    ($request:ty) => {
        impl<'a> CommandOpenFheContextRequest for $request {
            fn remove_public_material(&mut self) {
                self.parameters = None;
                self.crypto_context = None;
                self.public_key = None;
            }
        }
    };
}

impl_command_openfhe_context_request!(CommandOpenFheRequest<'a>);
impl_command_openfhe_context_request!(CommandOpenFheBatchRequest<'a>);
impl_command_openfhe_context_request!(CommandOpenFheQueryRequest<'a>);
impl_command_openfhe_context_request!(CommandOpenFheScoreRequest<'a>);
impl_command_openfhe_context_request!(CommandOpenFheScoreBatchRequest<'a>);
impl_command_openfhe_context_request!(CommandOpenFheEncryptedScoreRequest<'a>);
impl_command_openfhe_context_request!(CommandOpenFheEncryptedScoreBatchRequest<'a>);

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
struct CommandOpenFheResponse {
    version: u8,
    #[serde(default)]
    security_profile: Option<String>,
    #[serde(default)]
    security_level_bits: Option<u16>,
    #[serde(default)]
    noise_budget_bits: Option<f64>,
    ciphertext: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
struct CommandOpenFheBatchResponse {
    version: u8,
    #[serde(default)]
    security_profile: Option<String>,
    #[serde(default)]
    security_level_bits: Option<u16>,
    #[serde(default)]
    noise_budget_bits: Option<f64>,
    ciphertexts: Vec<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
struct CommandOpenFheScoreResponse {
    version: u8,
    #[serde(default)]
    security_profile: Option<String>,
    #[serde(default)]
    security_level_bits: Option<u16>,
    #[serde(default)]
    noise_budget_bits: Option<f64>,
    score: f64,
}

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
struct CommandOpenFheScoreBatchResponse {
    version: u8,
    #[serde(default)]
    security_profile: Option<String>,
    #[serde(default)]
    security_level_bits: Option<u16>,
    #[serde(default)]
    noise_budget_bits: Option<f64>,
    scores: Vec<f64>,
}

fn decode_single_bridge_response(
    response_bytes: &[u8],
    expected_security_profile: &str,
) -> Result<Vec<u8>, CkksError> {
    let response: CommandOpenFheResponse =
        serde_json::from_slice(response_bytes).map_err(|err| {
            CkksError::Backend(format!("failed to parse OpenFHE bridge response: {err}"))
        })?;
    if response.version != 1 {
        return Err(CkksError::Backend(format!(
            "unsupported OpenFHE bridge response version {}",
            response.version,
        )));
    }
    validate_bridge_security_profile(
        response.security_profile.as_deref(),
        expected_security_profile,
    )?;
    validate_bridge_security_metadata(response.security_level_bits, response.noise_budget_bits)?;

    decode_bridge_ciphertext(&response.ciphertext, "OpenFHE bridge returned")
}

fn decode_score_bridge_response(
    response_bytes: &[u8],
    expected_security_profile: &str,
) -> Result<f64, CkksError> {
    let response: CommandOpenFheScoreResponse =
        serde_json::from_slice(response_bytes).map_err(|err| {
            CkksError::Backend(format!(
                "failed to parse OpenFHE bridge score response: {err}"
            ))
        })?;
    if response.version != 1 {
        return Err(CkksError::Backend(format!(
            "unsupported OpenFHE bridge score response version {}",
            response.version,
        )));
    }
    validate_bridge_security_profile(
        response.security_profile.as_deref(),
        expected_security_profile,
    )?;
    validate_bridge_security_metadata(response.security_level_bits, response.noise_budget_bits)?;
    if !response.score.is_finite() {
        return Err(CkksError::Backend(
            "OpenFHE bridge returned non-finite score".to_string(),
        ));
    }

    Ok(response.score)
}

fn decode_score_batch_bridge_response(
    response_bytes: &[u8],
    expected: usize,
    expected_security_profile: &str,
) -> Result<Vec<f64>, CkksError> {
    let response: CommandOpenFheScoreBatchResponse = serde_json::from_slice(response_bytes)
        .map_err(|err| {
            CkksError::Backend(format!(
                "failed to parse OpenFHE bridge score batch response: {err}"
            ))
        })?;
    if response.version != 1 {
        return Err(CkksError::Backend(format!(
            "unsupported OpenFHE bridge score batch response version {}",
            response.version,
        )));
    }
    validate_bridge_security_profile(
        response.security_profile.as_deref(),
        expected_security_profile,
    )?;
    validate_bridge_security_metadata(response.security_level_bits, response.noise_budget_bits)?;
    if response.scores.len() != expected {
        return Err(CkksError::Backend(format!(
            "OpenFHE bridge returned {} batch scores for {expected} encrypted vectors",
            response.scores.len(),
        )));
    }
    if response.scores.iter().any(|score| !score.is_finite()) {
        return Err(CkksError::Backend(
            "OpenFHE bridge returned non-finite batch score".to_string(),
        ));
    }

    Ok(response.scores)
}

fn decode_batch_bridge_response(
    response_bytes: &[u8],
    expected: usize,
    expected_security_profile: &str,
) -> Result<Vec<Vec<u8>>, CkksError> {
    let response: CommandOpenFheBatchResponse =
        serde_json::from_slice(response_bytes).map_err(|err| {
            CkksError::Backend(format!(
                "failed to parse OpenFHE bridge batch response: {err}"
            ))
        })?;
    if response.version != 1 {
        return Err(CkksError::Backend(format!(
            "unsupported OpenFHE bridge batch response version {}",
            response.version,
        )));
    }
    validate_bridge_security_profile(
        response.security_profile.as_deref(),
        expected_security_profile,
    )?;
    validate_bridge_security_metadata(response.security_level_bits, response.noise_budget_bits)?;
    if response.ciphertexts.len() != expected {
        return Err(CkksError::Backend(format!(
            "OpenFHE bridge returned {} batch ciphertexts for {expected} input vectors",
            response.ciphertexts.len(),
        )));
    }

    response
        .ciphertexts
        .iter()
        .map(|ciphertext| decode_bridge_ciphertext(ciphertext, "OpenFHE bridge returned batch"))
        .collect()
}

fn decode_bridge_ciphertext(ciphertext_b64: &str, context: &str) -> Result<Vec<u8>, CkksError> {
    if ciphertext_b64.len() > MAX_BRIDGE_CIPHERTEXT_B64_LEN {
        return Err(CkksError::Backend(format!(
            "{context} ciphertext exceeds maximum size"
        )));
    }
    let ciphertext = BASE64URL_NOPAD
        .decode(ciphertext_b64.as_bytes())
        .map_err(|_| CkksError::Backend(format!("{context} invalid ciphertext")))?;
    if ciphertext.is_empty() {
        return Err(CkksError::Backend(format!("{context} empty ciphertext")));
    }
    if ciphertext.len() > MAX_BRIDGE_CIPHERTEXT_BYTES {
        return Err(CkksError::Backend(format!(
            "{context} ciphertext exceeds maximum size"
        )));
    }
    Ok(ciphertext)
}

fn expected_security_profile(parameters: &CkksParameters) -> Result<&'static str, CkksError> {
    parameters.security_profile().ok_or_else(|| {
        CkksError::InvalidParameters(
            "OpenFHE bridge request parameters do not match an allowlisted security profile"
                .to_string(),
        )
    })
}

fn validate_bridge_security_profile(
    reported: Option<&str>,
    expected: &str,
) -> Result<(), CkksError> {
    let reported = reported.ok_or_else(|| {
        CkksError::Backend(format!(
            "OpenFHE bridge response is missing security profile {expected}",
        ))
    })?;

    if reported != expected {
        return Err(CkksError::Backend(format!(
            "OpenFHE bridge security profile {reported} does not match expected {expected}",
        )));
    }

    Ok(())
}

fn validate_bridge_security_metadata(
    security_level_bits: Option<u16>,
    noise_budget_bits: Option<f64>,
) -> Result<(), CkksError> {
    if let Some(security_level_bits) = security_level_bits
        && security_level_bits < MIN_OPENFHE_SECURITY_LEVEL_BITS
    {
        return Err(CkksError::Backend(format!(
            "OpenFHE bridge security level {security_level_bits} bits is below required {MIN_OPENFHE_SECURITY_LEVEL_BITS} bits",
        )));
    }

    if let Some(noise_budget_bits) = noise_budget_bits
        && (!noise_budget_bits.is_finite() || noise_budget_bits < 0.0)
    {
        return Err(CkksError::Backend(format!(
            "OpenFHE bridge returned invalid noise budget {noise_budget_bits}",
        )));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_zeroizing_bridge_request(_: &Zeroizing<Vec<u8>>) {}

    #[test]
    fn bridge_request_serialization_uses_zeroizing_buffers() {
        let parameters = CkksParameters::default();
        let request = serialize_bridge_request(
            &CommandOpenFheQueryRequest {
                version: 1,
                operation: "encrypt_query",
                scheme: CKKS_SCHEME,
                collection: "docs",
                vector_name: "text",
                context_id: "ctx-1".to_string(),
                parameters: Some(&parameters),
                crypto_context: Some("crypto-context".to_string()),
                public_key: Some("public-key".to_string()),
                values: &[1.0, 2.0],
            },
            "test query request",
        )
        .unwrap();

        assert_zeroizing_bridge_request(&request);
        assert!(
            std::str::from_utf8(request.as_slice())
                .unwrap()
                .contains("\"values\"")
        );
    }

    #[test]
    fn bridge_response_decode_rejects_oversized_ciphertext_before_decode() {
        let expected_profile = CkksParameters::default().security_profile().unwrap();
        let oversized_ciphertext = "A".repeat(MAX_BRIDGE_CIPHERTEXT_B64_LEN + 1);

        let single_response = serde_json::json!({
            "version": 1,
            "ciphertext": oversized_ciphertext,
            "security_profile": expected_profile,
            "security_level_bits": MIN_OPENFHE_SECURITY_LEVEL_BITS,
        })
        .to_string();
        let err = decode_single_bridge_response(single_response.as_bytes(), expected_profile)
            .expect_err("oversized single ciphertext must fail before decode");
        assert!(format!("{err}").contains("ciphertext exceeds maximum size"));

        let batch_response = serde_json::json!({
            "version": 1,
            "ciphertexts": ["A".repeat(MAX_BRIDGE_CIPHERTEXT_B64_LEN + 1)],
            "security_profile": expected_profile,
            "security_level_bits": MIN_OPENFHE_SECURITY_LEVEL_BITS,
        })
        .to_string();
        let err = decode_batch_bridge_response(batch_response.as_bytes(), 1, expected_profile)
            .expect_err("oversized batch ciphertext must fail before decode");
        assert!(format!("{err}").contains("ciphertext exceeds maximum size"));
    }

    #[test]
    fn bridge_response_decode_rejects_empty_ciphertext() {
        let expected_profile = CkksParameters::default().security_profile().unwrap();
        let response = serde_json::json!({
            "version": 1,
            "ciphertext": "",
            "security_profile": expected_profile,
            "security_level_bits": MIN_OPENFHE_SECURITY_LEVEL_BITS,
        })
        .to_string();

        let err = decode_single_bridge_response(response.as_bytes(), expected_profile)
            .expect_err("empty bridge ciphertext must fail closed");
        assert!(format!("{err}").contains("empty ciphertext"));
    }

    #[test]
    fn command_backend_debug_redacts_program_policy_values() {
        let sentinel = "openfhe-backend-debug-sentinel";
        let mut backend = CommandOpenFheBackend::new_unchecked(format!("/tmp/{sentinel}/bridge"))
            .with_args([format!("--token={sentinel}")])
            .with_sensitive_env_names([format!("OPENFHE_{sentinel}")]);
        backend.expected_sha256_b64 = Some(format!("sha256-{sentinel}"));
        let rendered = format!("{backend:?}");

        assert!(!rendered.contains(sentinel), "{rendered}");
        assert!(rendered.contains("program: \"[redacted]\""), "{rendered}");
        assert!(rendered.contains("args_count: 1"), "{rendered}");
        assert!(rendered.contains("expected_sha256_b64: Some"), "{rendered}");
        assert!(
            rendered.contains("sensitive_env_names_count: 1"),
            "{rendered}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn unchecked_bridge_strips_qdrant_and_sensitive_env_names() {
        use std::os::unix::fs::PermissionsExt;

        static ENV_LOCK: Mutex<()> = Mutex::new(());
        let _env_guard = ENV_LOCK.lock().unwrap();

        let dir = tempfile::Builder::new()
            .prefix("qdrant-sec-openfhe-env-")
            .tempdir_in(std::env::current_dir().unwrap())
            .unwrap();
        let script = dir.path().join("openfhe-bridge");
        let expected_profile = CkksParameters::default().security_profile().unwrap();
        let script_body = format!(
            r#"#!/bin/sh
if [ "${{QDRANT+x}}" = x ] || \
   [ "${{QDRANT_UNCHECKED_OPENFHE_SECRET_FOR_TEST+x}}" = x ] || \
   [ "${{TENANT_OPENFHE_ENV_SECRET_FOR_TEST+x}}" = x ]; then
  printf '%s\n' 'secret env leaked to unchecked bridge' >&2
  exit 41
fi
if [ "${{OPENFHE_BRIDGE_PUBLIC_ENV_FOR_TEST}}" != "ambient-ok" ]; then
  printf '%s\n' 'public env did not reach unchecked bridge' >&2
  exit 42
fi
while IFS= read -r _line; do
  printf '%s\n' '{{"version":1,"ciphertext":"AQ","security_profile":"{expected_profile}","security_level_bits":128}}'
done
"#
        );
        std::fs::write(&script, script_body).unwrap();
        let mut dir_permissions = std::fs::metadata(dir.path()).unwrap().permissions();
        dir_permissions.set_mode(0o700);
        std::fs::set_permissions(dir.path(), dir_permissions).unwrap();
        let mut script_permissions = std::fs::metadata(&script).unwrap().permissions();
        script_permissions.set_mode(0o700);
        std::fs::set_permissions(&script, script_permissions).unwrap();

        unsafe {
            std::env::set_var("QDRANT", "qdrant-root-secret");
            std::env::set_var(
                "QDRANT_UNCHECKED_OPENFHE_SECRET_FOR_TEST",
                "qdrant-prefixed-secret",
            );
            std::env::set_var(
                "TENANT_OPENFHE_ENV_SECRET_FOR_TEST",
                "tenant-material-secret",
            );
            std::env::set_var("OPENFHE_BRIDGE_PUBLIC_ENV_FOR_TEST", "ambient-ok");
        }

        let backend = CommandOpenFheBackend::new_unchecked(&script)
            .with_timeout(Duration::from_secs(2))
            .with_sensitive_env_names(["TENANT_OPENFHE_ENV_SECRET_FOR_TEST"]);
        let parameters = CkksParameters::default();
        let public_material =
            crate::vector::CkksPublicMaterial::new(b"env-test-context", b"env-test-public-key")
                .unwrap();
        let result = backend.encrypt(CkksEncryptionInput {
            parameters: &parameters,
            public_material: &public_material,
            collection: "docs",
            point_id: "point-1",
            vector_name: "embedding",
            values: &[1.0, 2.0],
        });

        unsafe {
            std::env::remove_var("QDRANT");
            std::env::remove_var("QDRANT_UNCHECKED_OPENFHE_SECRET_FOR_TEST");
            std::env::remove_var("TENANT_OPENFHE_ENV_SECRET_FOR_TEST");
            std::env::remove_var("OPENFHE_BRIDGE_PUBLIC_ENV_FOR_TEST");
        }

        let ciphertext = result.expect("unchecked bridge should receive only allowed env values");
        assert_eq!(ciphertext, vec![1]);
    }

    #[test]
    fn cached_context_requests_strip_public_material_for_all_openfhe_operations() {
        let parameters = CkksParameters::default();
        let score_item = CommandOpenFheScoreBatchItem {
            point_id: "42",
            ciphertext: "ciphertext".to_string(),
        };
        let batch_item = CommandOpenFheBatchItem {
            point_id: "42",
            values: &[1.0, 2.0],
        };

        let mut requests = Vec::new();
        requests.push(
            serialize_bridge_request_without_public_material(
                &CommandOpenFheRequest {
                    version: 1,
                    operation: "encrypt",
                    scheme: CKKS_SCHEME,
                    collection: "docs",
                    point_id: "42",
                    vector_name: "text",
                    context_id: "ctx-1".to_string(),
                    parameters: Some(&parameters),
                    crypto_context: Some("crypto-context".to_string()),
                    public_key: Some("public-key".to_string()),
                    values: &[1.0, 2.0],
                },
                "test encrypt request",
            )
            .unwrap(),
        );
        requests.push(
            serialize_bridge_request_without_public_material(
                &CommandOpenFheBatchRequest {
                    version: 1,
                    operation: "encrypt_batch",
                    scheme: CKKS_SCHEME,
                    collection: "docs",
                    vector_name: "text",
                    context_id: "ctx-1".to_string(),
                    parameters: Some(&parameters),
                    crypto_context: Some("crypto-context".to_string()),
                    public_key: Some("public-key".to_string()),
                    items: vec![batch_item],
                },
                "test batch request",
            )
            .unwrap(),
        );
        requests.push(
            serialize_bridge_request_without_public_material(
                &CommandOpenFheQueryRequest {
                    version: 1,
                    operation: "encrypt_query",
                    scheme: CKKS_SCHEME,
                    collection: "docs",
                    vector_name: "text",
                    context_id: "ctx-1".to_string(),
                    parameters: Some(&parameters),
                    crypto_context: Some("crypto-context".to_string()),
                    public_key: Some("public-key".to_string()),
                    values: &[1.0, 2.0],
                },
                "test query request",
            )
            .unwrap(),
        );
        requests.push(
            serialize_bridge_request_without_public_material(
                &CommandOpenFheScoreRequest {
                    version: 1,
                    operation: "score_plaintext_query",
                    scheme: CKKS_SCHEME,
                    collection: "docs",
                    point_id: "42",
                    vector_name: "text",
                    distance: "cosine",
                    context_id: "ctx-1".to_string(),
                    parameters: Some(&parameters),
                    crypto_context: Some("crypto-context".to_string()),
                    public_key: Some("public-key".to_string()),
                    query_values: &[1.0, 2.0],
                    ciphertext: "ciphertext".to_string(),
                },
                "test score request",
            )
            .unwrap(),
        );
        requests.push(
            serialize_bridge_request_without_public_material(
                &CommandOpenFheScoreBatchRequest {
                    version: 1,
                    operation: "score_plaintext_query_batch",
                    scheme: CKKS_SCHEME,
                    collection: "docs",
                    vector_name: "text",
                    distance: "cosine",
                    context_id: "ctx-1".to_string(),
                    parameters: Some(&parameters),
                    crypto_context: Some("crypto-context".to_string()),
                    public_key: Some("public-key".to_string()),
                    query_values: &[1.0, 2.0],
                    items: vec![score_item.clone()],
                },
                "test score batch request",
            )
            .unwrap(),
        );
        requests.push(
            serialize_bridge_request_without_public_material(
                &CommandOpenFheEncryptedScoreRequest {
                    version: 1,
                    operation: "score_encrypted_query",
                    scheme: CKKS_SCHEME,
                    collection: "docs",
                    point_id: "42",
                    vector_name: "text",
                    distance: "cosine",
                    context_id: "ctx-1".to_string(),
                    parameters: Some(&parameters),
                    crypto_context: Some("crypto-context".to_string()),
                    public_key: Some("public-key".to_string()),
                    encrypted_query: "query-ciphertext".to_string(),
                    ciphertext: "ciphertext".to_string(),
                },
                "test encrypted score request",
            )
            .unwrap(),
        );
        requests.push(
            serialize_bridge_request_without_public_material(
                &CommandOpenFheEncryptedScoreBatchRequest {
                    version: 1,
                    operation: "score_encrypted_query_batch",
                    scheme: CKKS_SCHEME,
                    collection: "docs",
                    vector_name: "text",
                    distance: "cosine",
                    context_id: "ctx-1".to_string(),
                    parameters: Some(&parameters),
                    crypto_context: Some("crypto-context".to_string()),
                    public_key: Some("public-key".to_string()),
                    encrypted_query: "query-ciphertext".to_string(),
                    items: vec![score_item],
                },
                "test encrypted score batch request",
            )
            .unwrap(),
        );

        for request in requests {
            let request: serde_json::Value = serde_json::from_slice(&request).unwrap();
            assert_eq!(request["context_id"], "ctx-1");
            assert!(request.get("parameters").is_none());
            assert!(request.get("crypto_context").is_none());
            assert!(request.get("public_key").is_none());
        }
    }

    #[cfg(unix)]
    #[test]
    fn worker_process_reserves_idle_worker_until_reservation_drops() {
        let backend = CommandOpenFheBackend::new_unchecked("cat")
            .with_pool_size(NonZeroUsize::new(2).unwrap());

        let first = backend.worker_process().unwrap();
        let first_worker = Arc::clone(first.worker());
        let second = backend.worker_process().unwrap();
        let second_worker = Arc::clone(second.worker());

        assert!(!Arc::ptr_eq(&first_worker, &second_worker));

        drop(first);
        let third = backend.worker_process().unwrap();

        assert!(Arc::ptr_eq(third.worker(), &first_worker));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn bridge_worker_survives_the_exit_of_the_thread_that_spawned_it() {
        let backend = CommandOpenFheBackend::new_unchecked("cat")
            .with_pool_size(NonZeroUsize::new(1).unwrap());
        let spawner = backend.clone();
        let worker = std::thread::spawn(move || {
            let reservation = spawner.worker_process().unwrap();
            Arc::clone(reservation.worker())
        })
        .join()
        .unwrap();
        // PR_SET_PDEATHSIG fires when the spawning *thread* exits; give the kernel a moment.
        std::thread::sleep(Duration::from_millis(200));
        assert!(
            worker.try_wait().unwrap().is_none(),
            "bridge worker died with the thread that spawned it"
        );
        let reservation = backend.worker_process().unwrap();
        assert!(Arc::ptr_eq(reservation.worker(), &worker));
    }

    #[cfg(unix)]
    #[test]
    fn cloned_backend_worker_process_fails_fast_when_shared_pool_is_busy() {
        let backend = CommandOpenFheBackend::new_unchecked("cat")
            .with_pool_size(NonZeroUsize::new(1).unwrap());
        let cloned = backend.clone();

        let _first = backend.worker_process().unwrap();
        match cloned.worker_process() {
            Ok(_) => {
                panic!("a busy full pool must fail fast instead of serializing on a busy worker")
            }
            Err(CkksError::Backend(message)) => {
                assert!(message.contains("worker pool is exhausted"), "{message}");
            }
            Err(err) => panic!("unexpected busy full pool error: {err:?}"),
        }
    }

    #[cfg(unix)]
    #[test]
    fn builder_policy_change_uses_isolated_worker_pool() {
        let backend = CommandOpenFheBackend::new_unchecked("cat")
            .with_pool_size(NonZeroUsize::new(1).unwrap());
        let first = backend.worker_process().unwrap();
        let first_worker = Arc::clone(first.worker());

        let changed = backend.clone().with_timeout(Duration::from_millis(250));
        let changed_worker = changed.worker_process().unwrap();

        assert!(
            !Arc::ptr_eq(changed_worker.worker(), &first_worker),
            "policy-changing builders must not reuse workers started with the previous policy",
        );
    }

    #[cfg(unix)]
    #[test]
    fn bridge_request_retries_once_after_worker_exits_before_response() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::Builder::new()
            .prefix("qdrant-sec-openfhe-retry-")
            .tempdir_in(std::env::current_dir().unwrap())
            .unwrap();
        let marker = dir.path().join("first-worker-exited");
        let script = dir.path().join("openfhe-bridge");
        let expected_profile = CkksParameters::default().security_profile().unwrap();
        let script_body = format!(
            r#"#!/bin/sh
if [ ! -f "{marker}" ]; then
  : > "{marker}"
  exit 0
fi
while IFS= read -r _line; do
  printf '%s\n' '{{"version":1,"ciphertext":"AQ","security_profile":"{expected_profile}","security_level_bits":128}}'
done
"#,
            marker = marker.display(),
        );
        std::fs::write(&script, script_body).unwrap();
        let mut dir_permissions = std::fs::metadata(dir.path()).unwrap().permissions();
        dir_permissions.set_mode(0o700);
        std::fs::set_permissions(dir.path(), dir_permissions).unwrap();
        let mut script_permissions = std::fs::metadata(&script).unwrap().permissions();
        script_permissions.set_mode(0o700);
        std::fs::set_permissions(&script, script_permissions).unwrap();

        let backend = CommandOpenFheBackend::new_unchecked(&script)
            .with_timeout(Duration::from_secs(2))
            .with_pool_size(NonZeroUsize::new(1).unwrap());
        let parameters = CkksParameters::default();
        let public_material =
            crate::vector::CkksPublicMaterial::new(b"retry-test-context", b"retry-test-public-key")
                .unwrap();

        let ciphertext = backend
            .encrypt(CkksEncryptionInput {
                parameters: &parameters,
                public_material: &public_material,
                collection: "docs",
                point_id: "point-1",
                vector_name: "embedding",
                values: &[1.0, 2.0],
            })
            .expect("second bridge worker should satisfy the retried request");

        assert_eq!(ciphertext, vec![1]);
    }

    #[cfg(unix)]
    #[test]
    fn bridge_batch_request_retries_once_after_worker_exits_before_response() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::Builder::new()
            .prefix("qdrant-sec-openfhe-batch-retry-")
            .tempdir_in(std::env::current_dir().unwrap())
            .unwrap();
        let marker = dir.path().join("first-worker-exited");
        let script = dir.path().join("openfhe-bridge");
        let expected_profile = CkksParameters::default().security_profile().unwrap();
        let script_body = format!(
            r#"#!/bin/sh
if [ ! -f "{marker}" ]; then
  : > "{marker}"
  exit 0
fi
while IFS= read -r _line; do
  printf '%s\n' '{{"version":1,"ciphertexts":["AQ","Ag"],"security_profile":"{expected_profile}","security_level_bits":128}}'
done
"#,
            marker = marker.display(),
        );
        std::fs::write(&script, script_body).unwrap();
        let mut dir_permissions = std::fs::metadata(dir.path()).unwrap().permissions();
        dir_permissions.set_mode(0o700);
        std::fs::set_permissions(dir.path(), dir_permissions).unwrap();
        let mut script_permissions = std::fs::metadata(&script).unwrap().permissions();
        script_permissions.set_mode(0o700);
        std::fs::set_permissions(&script, script_permissions).unwrap();

        let backend = CommandOpenFheBackend::new_unchecked(&script)
            .with_timeout(Duration::from_secs(2))
            .with_pool_size(NonZeroUsize::new(1).unwrap());
        let parameters = CkksParameters::default();
        let public_material = crate::vector::CkksPublicMaterial::new(
            b"batch-retry-test-context",
            b"batch-retry-test-public-key",
        )
        .unwrap();
        let items = [
            crate::vector::CkksVectorBatchItem {
                point_id: "point-1",
                values: &[1.0, 2.0],
            },
            crate::vector::CkksVectorBatchItem {
                point_id: "point-2",
                values: &[3.0, 4.0],
            },
        ];

        let ciphertexts = backend
            .encrypt_batch(CkksBatchEncryptionInput {
                parameters: &parameters,
                public_material: &public_material,
                collection: "docs",
                vector_name: "embedding",
                items: &items,
            })
            .expect("second bridge worker should satisfy the retried batch request");

        assert_eq!(ciphertexts, vec![vec![1], vec![2]]);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn checked_bridge_spawn_program_uses_validated_proc_fd_path() {
        let program = std::env::current_exe().unwrap();
        let expected_sha256_b64 =
            BASE64URL_NOPAD.encode(&Sha256::digest(std::fs::read(&program).unwrap()));

        let spawn_program =
            checked_bridge_spawn_program(&program, Some(&expected_sha256_b64)).unwrap();

        assert!(spawn_program.path().starts_with("/proc/self/fd"));
        assert!(spawn_program._fd.is_some());
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn checked_bridge_spawn_is_linux_only() {
        let program = std::env::current_exe().unwrap();
        let expected_sha256_b64 =
            BASE64URL_NOPAD.encode(&Sha256::digest(std::fs::read(&program).unwrap()));

        let err = CommandOpenFheBackend::new_checked_with_sha256_b64(&program, expected_sha256_b64)
            .expect_err("non-Linux checked bridge spawn must fail closed");

        assert!(
            format!("{err}").contains("requires Linux fd-backed /proc/self/fd execution"),
            "{err}"
        );
    }

    #[test]
    fn checked_bridge_sha256_pin_rejects_oversized_encoded_pin() {
        let program = std::env::current_exe().unwrap();
        let err = CommandOpenFheBackend::new_checked_with_sha256_b64(&program, "A".repeat(1024))
            .expect_err("oversized sha256 pin must fail before bridge hash validation");
        assert!(format!("{err}").contains("must decode to 32 bytes"));
    }

    #[test]
    fn checked_bridge_errors_do_not_reflect_program_path() {
        let relative_program = PathBuf::from("qdrant-sec-openfhe-path-sentinel");
        let err = CommandOpenFheBackend::new_checked(&relative_program)
            .expect_err("relative checked bridge program path must be rejected");
        let rendered = format!("{err}");
        assert!(
            !rendered.contains("qdrant-sec-openfhe-path-sentinel"),
            "{rendered}"
        );

        let program = std::env::current_exe().unwrap();
        let err = CommandOpenFheBackend::new_checked_with_sha256_b64(
            &program,
            BASE64URL_NOPAD.encode(&[0u8; 32]),
        )
        .expect_err("sha256 mismatch must be rejected");
        let rendered = format!("{err}");
        assert!(
            !rendered.contains(&program.display().to_string()),
            "{rendered}"
        );
    }

    #[test]
    fn checked_bridge_sha256_pin_rejects_oversized_program_before_hash() {
        #[cfg(unix)]
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::Builder::new()
            .prefix("qdrant-sec-openfhe-oversized-")
            .tempdir_in(std::env::current_dir().unwrap())
            .unwrap();
        #[cfg(unix)]
        {
            let mut dir_permissions = std::fs::metadata(dir.path()).unwrap().permissions();
            dir_permissions.set_mode(0o700);
            std::fs::set_permissions(dir.path(), dir_permissions).unwrap();
        }

        let program = dir.path().join("openfhe-bridge");
        let file = std::fs::File::create(&program).unwrap();
        file.set_len(MAX_BRIDGE_PROGRAM_SHA256_BYTES + 1).unwrap();
        drop(file);
        #[cfg(unix)]
        {
            let mut permissions = std::fs::metadata(&program).unwrap().permissions();
            permissions.set_mode(0o700);
            std::fs::set_permissions(&program, permissions).unwrap();
        }

        let err = CommandOpenFheBackend::new_checked_with_sha256_b64(
            &program,
            BASE64URL_NOPAD.encode(&[0u8; 32]),
        )
        .expect_err("oversized bridge program must fail before full-file hash allocation");
        assert!(format!("{err}").contains("exceeds"));
    }
}

#[cfg(test)]
#[path = "openfhe_concurrency_tests.rs"]
mod concurrency_tests;
