use std::io::{self, BufReader, Read, Write};
use std::num::NonZeroUsize;
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use data_encoding::BASE64URL_NOPAD;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::vector::{
    CKKS_SCHEME, CkksBatchEncryptionInput, CkksEncryptionInput, CkksError, CkksParameters,
    CkksVectorBackend,
};

const DEFAULT_BRIDGE_TIMEOUT: Duration = Duration::from_secs(30);
const DEFAULT_MAX_OUTPUT_BYTES: usize = 1024 * 1024;

#[derive(Clone)]
pub struct CommandOpenFheBackend {
    program: PathBuf,
    args: Vec<String>,
    timeout: Duration,
    max_output_bytes: usize,
    pool_size: NonZeroUsize,
    checked_program: bool,
    expected_sha256_b64: Option<String>,
    workers: Arc<Mutex<Vec<Arc<WorkerProcess>>>>,
    next_worker: Arc<AtomicUsize>,
}

impl std::fmt::Debug for CommandOpenFheBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CommandOpenFheBackend")
            .field("program", &self.program)
            .field("args", &self.args)
            .field("timeout", &self.timeout)
            .field("max_output_bytes", &self.max_output_bytes)
            .field("pool_size", &self.pool_size)
            .field("checked_program", &self.checked_program)
            .field(
                "expected_sha256_b64",
                &self.expected_sha256_b64.as_ref().map(|_| "<configured>"),
            )
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
    }
}

impl Eq for CommandOpenFheBackend {}

struct WorkerProcess {
    child: Mutex<Child>,
    stdin: Mutex<ChildStdin>,
    stdout_rx: Mutex<mpsc::Receiver<BridgeStdoutEvent>>,
    stderr_truncated: Arc<AtomicBool>,
    terminated: AtomicBool,
    request_lock: Mutex<()>,
    stdout_thread: Mutex<Option<JoinHandle<()>>>,
    stderr_thread: Mutex<Option<JoinHandle<io::Result<()>>>>,
}

enum BridgeStdoutEvent {
    Response { bytes: Vec<u8>, truncated: bool },
    Eof,
    Error(io::Error),
    StderrExceeded,
}

impl WorkerProcess {
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
            if let Some(stdout_thread) = self
                .stdout_thread
                .lock()
                .map_err(|_| {
                    CkksError::Backend(
                        "OpenFHE bridge stdout thread mutex was poisoned".to_string(),
                    )
                })?
                .take()
            {
                stdout_thread
                    .join()
                    .map_err(|_| CkksError::Backend("bridge stdout reader panicked".to_string()))?;
            }
            if let Some(stderr_thread) = self
                .stderr_thread
                .lock()
                .map_err(|_| {
                    CkksError::Backend(
                        "OpenFHE bridge stderr thread mutex was poisoned".to_string(),
                    )
                })?
                .take()
            {
                stderr_thread
                    .join()
                    .map_err(|_| CkksError::Backend("bridge stderr reader panicked".to_string()))?
                    .map_err(|err| {
                        CkksError::Backend(format!("failed to drain OpenFHE bridge stderr: {err}"))
                    })?;
            }
        } else {
            if let Ok(mut stdout_thread) = self.stdout_thread.lock() {
                let _ = stdout_thread.take();
            }
            if let Ok(mut stderr_thread) = self.stderr_thread.lock() {
                let _ = stderr_thread.take();
            }
        }

        Ok(())
    }
}

impl CommandOpenFheBackend {
    fn new_unchecked(program: impl Into<PathBuf>) -> Self {
        Self {
            program: program.into(),
            args: Vec::new(),
            timeout: DEFAULT_BRIDGE_TIMEOUT,
            max_output_bytes: DEFAULT_MAX_OUTPUT_BYTES,
            pool_size: NonZeroUsize::new(1).expect("pool size must be non-zero"),
            checked_program: false,
            expected_sha256_b64: None,
            workers: Arc::new(Mutex::new(Vec::new())),
            next_worker: Arc::new(AtomicUsize::new(0)),
        }
    }

    /// Builds a backend without validating the bridge program path.
    ///
    /// This is only intended for tests that deliberately execute a helper
    /// through a shell such as `bash script.sh`. Production/runtime code should
    /// use `new_checked` or `new_checked_with_sha256_b64`.
    #[doc(hidden)]
    pub fn new_unchecked_for_tests(program: impl Into<PathBuf>) -> Self {
        Self::new_unchecked(program)
    }

    pub fn new_checked(program: impl Into<PathBuf>) -> Result<Self, CkksError> {
        let program = program.into();
        validate_checked_bridge_program(&program)?;

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
        self.workers = Arc::new(Mutex::new(Vec::new()));
        self.next_worker = Arc::new(AtomicUsize::new(0));
        self
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self.workers = Arc::new(Mutex::new(Vec::new()));
        self.next_worker = Arc::new(AtomicUsize::new(0));
        self
    }

    pub fn with_max_output_bytes(mut self, max_output_bytes: usize) -> Self {
        self.max_output_bytes = max_output_bytes;
        self.workers = Arc::new(Mutex::new(Vec::new()));
        self.next_worker = Arc::new(AtomicUsize::new(0));
        self
    }

    pub fn with_pool_size(mut self, pool_size: NonZeroUsize) -> Self {
        self.pool_size = pool_size;
        self.workers = Arc::new(Mutex::new(Vec::new()));
        self.next_worker = Arc::new(AtomicUsize::new(0));
        self
    }
}

fn validate_checked_bridge_program(path: &Path) -> Result<(), CkksError> {
    if !path.is_absolute() {
        return Err(CkksError::Backend(format!(
            "OpenFHE bridge program must be an absolute path: {}",
            path.display(),
        )));
    }

    let link_metadata = std::fs::symlink_metadata(path).map_err(|err| {
        CkksError::Backend(format!(
            "failed to inspect OpenFHE bridge program {}: {err}",
            path.display(),
        ))
    })?;
    if link_metadata.file_type().is_symlink() || !link_metadata.is_file() {
        return Err(CkksError::Backend(format!(
            "OpenFHE bridge program must be a regular non-symlink file: {}",
            path.display(),
        )));
    }

    let metadata = std::fs::metadata(path).map_err(|err| {
        CkksError::Backend(format!(
            "failed to inspect OpenFHE bridge program {}: {err}",
            path.display(),
        ))
    })?;
    if !metadata.is_file() {
        return Err(CkksError::Backend(format!(
            "OpenFHE bridge program must be a regular file: {}",
            path.display(),
        )));
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};

        unsafe extern "C" {
            fn geteuid() -> u32;
        }

        let mode = metadata.permissions().mode();
        if mode & 0o111 == 0 || mode & 0o022 != 0 {
            return Err(CkksError::Backend(format!(
                "OpenFHE bridge program must be executable and not group/world-writable: {}",
                path.display(),
            )));
        }

        let effective_uid = unsafe { geteuid() };
        let owner = metadata.uid();
        if owner != 0 && owner != effective_uid {
            return Err(CkksError::Backend(format!(
                "OpenFHE bridge program must be owned by root or the qdrant process user: {}",
                path.display(),
            )));
        }

        let mut parent = path.parent();
        while let Some(directory) = parent {
            let directory_metadata = std::fs::symlink_metadata(directory).map_err(|err| {
                CkksError::Backend(format!(
                    "failed to inspect OpenFHE bridge parent directory {}: {err}",
                    directory.display(),
                ))
            })?;
            if directory_metadata.file_type().is_symlink() || !directory_metadata.is_dir() {
                return Err(CkksError::Backend(format!(
                    "OpenFHE bridge parent path must be a regular directory: {}",
                    directory.display(),
                )));
            }
            if directory_metadata.permissions().mode() & 0o022 != 0 {
                return Err(CkksError::Backend(format!(
                    "OpenFHE bridge parent directory must not be group/world-writable: {}",
                    directory.display(),
                )));
            }
            let owner = directory_metadata.uid();
            if owner != 0 && owner != effective_uid {
                return Err(CkksError::Backend(format!(
                    "OpenFHE bridge parent directory must be owned by root or the qdrant process user: {}",
                    directory.display(),
                )));
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
    let expected = BASE64URL_NOPAD
        .decode(expected_sha256_b64.as_bytes())
        .map_err(|_| {
            CkksError::Backend(format!(
                "OpenFHE bridge sha256 pin must be base64url-no-padding: {}",
                path.display(),
            ))
        })?;
    if expected.len() != 32 {
        return Err(CkksError::Backend(format!(
            "OpenFHE bridge sha256 pin must decode to 32 bytes: {}",
            path.display(),
        )));
    }

    let bytes = std::fs::read(path).map_err(|err| {
        CkksError::Backend(format!(
            "failed to read OpenFHE bridge program {} for sha256 pinning: {err}",
            path.display(),
        ))
    })?;
    let actual = Sha256::digest(&bytes);
    if actual[..] != expected[..] {
        return Err(CkksError::Backend(format!(
            "OpenFHE bridge sha256 pin does not match: {}",
            path.display(),
        )));
    }

    Ok(())
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
        let request = CommandOpenFheRequest {
            version: 1,
            scheme: CKKS_SCHEME,
            collection: input.collection,
            point_id: input.point_id,
            vector_name: input.vector_name,
            parameters: input.parameters,
            crypto_context: BASE64URL_NOPAD.encode(input.public_material.crypto_context()),
            public_key: BASE64URL_NOPAD.encode(input.public_material.public_key()),
            values: input.values,
        };
        let request_bytes = serde_json::to_vec(&request).map_err(|err| {
            CkksError::Backend(format!("failed to serialize OpenFHE bridge request: {err}"))
        })?;

        self.send_bridge_request(&request_bytes, decode_single_bridge_response)
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
        let request = CommandOpenFheBatchRequest {
            version: 1,
            scheme: CKKS_SCHEME,
            collection: input.collection,
            vector_name: input.vector_name,
            parameters: input.parameters,
            crypto_context: BASE64URL_NOPAD.encode(input.public_material.crypto_context()),
            public_key: BASE64URL_NOPAD.encode(input.public_material.public_key()),
            items,
        };
        let request_bytes = serde_json::to_vec(&request).map_err(|err| {
            CkksError::Backend(format!(
                "failed to serialize OpenFHE bridge batch request: {err}"
            ))
        })?;

        self.send_bridge_request(&request_bytes, |response_bytes| {
            decode_batch_bridge_response(response_bytes, input.items.len())
        })
    }
}

impl CommandOpenFheBackend {
    fn send_bridge_request<T>(
        &self,
        request_bytes: &[u8],
        decode_response: impl Fn(&[u8]) -> Result<T, CkksError>,
    ) -> Result<T, CkksError> {
        let mut request_bytes = request_bytes.to_vec();
        request_bytes.push(b'\n');

        for attempt in 0..=1 {
            let worker_process = self.worker_process()?;
            let _request_guard = worker_process.request_lock.lock().map_err(|_| {
                CkksError::Backend("OpenFHE bridge request mutex was poisoned".to_string())
            })?;
            if worker_process.stderr_truncated.load(Ordering::Relaxed) {
                self.discard_worker(&worker_process, false)?;
                return Err(CkksError::Backend(format!(
                    "OpenFHE bridge stderr exceeded {} bytes",
                    self.max_output_bytes,
                )));
            }

            let write_result = {
                let mut stdin = worker_process.stdin.lock().map_err(|_| {
                    CkksError::Backend("OpenFHE bridge stdin mutex was poisoned".to_string())
                })?;
                stdin.write_all(&request_bytes).and_then(|_| stdin.flush())
            };
            if let Err(err) = write_result {
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

            let timeout = self.timeout;
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
                Ok(response) => Ok(response),
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

    fn worker_process(&self) -> Result<Arc<WorkerProcess>, CkksError> {
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
            if worker_process.request_lock.try_lock().is_ok() {
                return Ok(Arc::clone(worker_process));
            }
        }

        if workers.len() == self.pool_size.get()
            && let Some(worker_process) =
                workers.get(self.next_worker.fetch_add(1, Ordering::Relaxed) % self.pool_size.get())
        {
            return Ok(Arc::clone(worker_process));
        }

        if self.checked_program {
            validate_checked_bridge_program(&self.program)?;
            if let Some(expected_sha256_b64) = self.expected_sha256_b64.as_deref() {
                validate_bridge_program_sha256_b64(&self.program, expected_sha256_b64)?;
            }
        }

        let mut child = Command::new(&self.program)
            .args(&self.args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
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
            terminated: AtomicBool::new(false),
            request_lock: Mutex::new(()),
            stdout_thread: Mutex::new(Some(stdout_thread)),
            stderr_thread: Mutex::new(Some(stderr_thread)),
        });
        workers.push(Arc::clone(&worker_process));
        Ok(worker_process)
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

#[derive(Serialize)]
#[serde(rename_all = "snake_case")]
struct CommandOpenFheRequest<'a> {
    version: u8,
    scheme: &'static str,
    collection: &'a str,
    point_id: &'a str,
    vector_name: &'a str,
    parameters: &'a CkksParameters,
    crypto_context: String,
    public_key: String,
    values: &'a [f64],
}

#[derive(Serialize)]
#[serde(rename_all = "snake_case")]
struct CommandOpenFheBatchRequest<'a> {
    version: u8,
    scheme: &'static str,
    collection: &'a str,
    vector_name: &'a str,
    parameters: &'a CkksParameters,
    crypto_context: String,
    public_key: String,
    items: Vec<CommandOpenFheBatchItem<'a>>,
}

#[derive(Serialize)]
#[serde(rename_all = "snake_case")]
struct CommandOpenFheBatchItem<'a> {
    point_id: &'a str,
    values: &'a [f64],
}

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
struct CommandOpenFheResponse {
    version: u8,
    ciphertext: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
struct CommandOpenFheBatchResponse {
    version: u8,
    ciphertexts: Vec<String>,
}

fn decode_single_bridge_response(response_bytes: &[u8]) -> Result<Vec<u8>, CkksError> {
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

    BASE64URL_NOPAD
        .decode(response.ciphertext.as_bytes())
        .map_err(|_| CkksError::Backend("OpenFHE bridge returned invalid ciphertext".to_string()))
}

fn decode_batch_bridge_response(
    response_bytes: &[u8],
    expected: usize,
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
    if response.ciphertexts.len() != expected {
        return Err(CkksError::Backend(format!(
            "OpenFHE bridge returned {} batch ciphertexts for {expected} input vectors",
            response.ciphertexts.len(),
        )));
    }

    response
        .ciphertexts
        .iter()
        .map(|ciphertext| {
            BASE64URL_NOPAD.decode(ciphertext.as_bytes()).map_err(|_| {
                CkksError::Backend("OpenFHE bridge returned invalid batch ciphertext".to_string())
            })
        })
        .collect()
}
