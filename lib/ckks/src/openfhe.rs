use std::io::{self, BufReader, Read, Write};
use std::path::PathBuf;
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::sync::mpsc;
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, Ordering},
};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use data_encoding::BASE64URL_NOPAD;
use serde::{Deserialize, Serialize};

use crate::vector::{
    CKKS_SCHEME, CkksEncryptionInput, CkksError, CkksParameters, CkksVectorBackend,
};

const DEFAULT_BRIDGE_TIMEOUT: Duration = Duration::from_secs(30);
const DEFAULT_MAX_OUTPUT_BYTES: usize = 1024 * 1024;

#[derive(Clone)]
pub struct CommandOpenFheBackend {
    program: PathBuf,
    args: Vec<String>,
    timeout: Duration,
    max_output_bytes: usize,
    worker: Arc<Mutex<Option<WorkerProcess>>>,
}

impl std::fmt::Debug for CommandOpenFheBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CommandOpenFheBackend")
            .field("program", &self.program)
            .field("args", &self.args)
            .field("timeout", &self.timeout)
            .field("max_output_bytes", &self.max_output_bytes)
            .finish()
    }
}

impl PartialEq for CommandOpenFheBackend {
    fn eq(&self, other: &Self) -> bool {
        self.program == other.program
            && self.args == other.args
            && self.timeout == other.timeout
            && self.max_output_bytes == other.max_output_bytes
    }
}

impl Eq for CommandOpenFheBackend {}

struct WorkerProcess {
    child: Child,
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
    stderr_truncated: Arc<AtomicBool>,
    stderr_thread: Option<JoinHandle<io::Result<()>>>,
}

impl WorkerProcess {
    fn shutdown(&mut self) -> Result<(), CkksError> {
        let _ = self.child.kill();
        let _ = self.child.wait();
        if let Some(stderr_thread) = self.stderr_thread.take() {
            stderr_thread
                .join()
                .map_err(|_| CkksError::Backend("bridge stderr reader panicked".to_string()))?
                .map_err(|err| {
                    CkksError::Backend(format!("failed to drain OpenFHE bridge stderr: {err}"))
                })?;
        }
        Ok(())
    }
}

impl CommandOpenFheBackend {
    pub fn new(program: impl Into<PathBuf>) -> Self {
        Self {
            program: program.into(),
            args: Vec::new(),
            timeout: DEFAULT_BRIDGE_TIMEOUT,
            max_output_bytes: DEFAULT_MAX_OUTPUT_BYTES,
            worker: Arc::new(Mutex::new(None)),
        }
    }

    pub fn with_args<I, S>(mut self, args: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.args.extend(args.into_iter().map(Into::into));
        self.worker = Arc::new(Mutex::new(None));
        self
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self.worker = Arc::new(Mutex::new(None));
        self
    }

    pub fn with_max_output_bytes(mut self, max_output_bytes: usize) -> Self {
        self.max_output_bytes = max_output_bytes;
        self.worker = Arc::new(Mutex::new(None));
        self
    }
}

impl Drop for CommandOpenFheBackend {
    fn drop(&mut self) {
        if Arc::strong_count(&self.worker) != 1 {
            return;
        }
        if let Ok(mut worker) = self.worker.lock()
            && let Some(mut worker) = worker.take()
        {
            let _ = worker.shutdown();
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
        let mut request_bytes = serde_json::to_vec(&request).map_err(|err| {
            CkksError::Backend(format!("failed to serialize OpenFHE bridge request: {err}"))
        })?;
        request_bytes.push(b'\n');

        for attempt in 0..=1 {
            let mut worker = self.worker.lock().map_err(|_| {
                CkksError::Backend("OpenFHE bridge worker mutex was poisoned".to_string())
            })?;
            if let Some(worker_process) = worker.as_mut() {
                if worker_process
                    .child
                    .try_wait()
                    .map_err(|err| {
                        CkksError::Backend(format!("failed to poll OpenFHE bridge status: {err}"))
                    })?
                    .is_some()
                {
                    worker_process.shutdown()?;
                    *worker = None;
                }
            }

            if worker.is_none() {
                let mut child = Command::new(&self.program)
                    .args(&self.args)
                    .stdin(Stdio::piped())
                    .stdout(Stdio::piped())
                    .stderr(Stdio::piped())
                    .spawn()
                    .map_err(|err| {
                        CkksError::Backend(format!("failed to start OpenFHE bridge: {err}"))
                    })?;
                let stdin = child
                    .stdin
                    .take()
                    .ok_or_else(|| CkksError::Backend("failed to open bridge stdin".to_string()))?;
                let stdout = child.stdout.take().ok_or_else(|| {
                    CkksError::Backend("failed to open bridge stdout".to_string())
                })?;
                let stderr = child.stderr.take().ok_or_else(|| {
                    CkksError::Backend("failed to open bridge stderr".to_string())
                })?;
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
                        }
                    }
                });
                *worker = Some(WorkerProcess {
                    child,
                    stdin,
                    stdout: BufReader::new(stdout),
                    stderr_truncated,
                    stderr_thread: Some(stderr_thread),
                });
            }

            let worker_process = worker.as_mut().unwrap();
            if worker_process.stderr_truncated.load(Ordering::Relaxed) {
                worker_process.shutdown()?;
                *worker = None;
                return Err(CkksError::Backend(format!(
                    "OpenFHE bridge stderr exceeded {} bytes",
                    self.max_output_bytes,
                )));
            }

            if let Err(err) = worker_process
                .stdin
                .write_all(&request_bytes)
                .and_then(|_| worker_process.stdin.flush())
            {
                let retry = attempt == 0
                    && matches!(
                        err.kind(),
                        io::ErrorKind::BrokenPipe | io::ErrorKind::UnexpectedEof
                    );
                worker_process.shutdown()?;
                *worker = None;
                if retry {
                    continue;
                }
                return Err(CkksError::Backend(format!(
                    "failed to write OpenFHE bridge request: {err}",
                )));
            }

            let child = &mut worker_process.child;
            let stdout = &mut worker_process.stdout;
            let (tx, rx) = mpsc::channel();
            let max_output_bytes = self.max_output_bytes;
            let timeout = self.timeout;
            let mut timed_out = false;
            let response = thread::scope(|scope| {
                scope.spawn(|| {
                    let mut bytes = Vec::new();
                    let mut truncated = false;
                    let mut byte = [0u8; 1];
                    loop {
                        match stdout.read(&mut byte) {
                            Ok(0) => break,
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
                                let _ = tx.send(Err(err));
                                return;
                            }
                        }
                    }
                    let _ = tx.send(Ok((bytes, truncated)));
                });

                match rx.recv_timeout(timeout) {
                    Ok(Ok((mut bytes, truncated))) => {
                        if bytes.last() == Some(&b'\n') {
                            bytes.pop();
                            if bytes.last() == Some(&b'\r') {
                                bytes.pop();
                            }
                        }
                        Ok((bytes, truncated))
                    }
                    Ok(Err(err)) => Err(CkksError::Backend(format!(
                        "failed to read OpenFHE bridge response: {err}",
                    ))),
                    Err(mpsc::RecvTimeoutError::Timeout) => {
                        timed_out = true;
                        let _ = child.kill();
                        let _ = child.wait();
                        Err(CkksError::Backend(format!(
                            "OpenFHE bridge timed out after {} ms",
                            timeout.as_millis(),
                        )))
                    }
                    Err(mpsc::RecvTimeoutError::Disconnected) => Err(CkksError::Backend(
                        "bridge stdout reader disconnected".to_string(),
                    )),
                }
            });

            if timed_out {
                worker_process.shutdown()?;
                *worker = None;
                return Err(CkksError::Backend(format!(
                    "OpenFHE bridge timed out after {} ms",
                    timeout.as_millis(),
                )));
            }

            let (response_bytes, truncated) = match response {
                Ok(response) => response,
                Err(err) => {
                    let retry = attempt == 0
                        && matches!(
                            err,
                            CkksError::Backend(ref message)
                                if message.contains("failed to read OpenFHE bridge response")
                                    || message.contains("bridge stdout reader disconnected")
                        );
                    worker_process.shutdown()?;
                    *worker = None;
                    if retry {
                        continue;
                    }
                    return Err(err);
                }
            };
            if truncated {
                let mut worker_process = worker.take().unwrap();
                worker_process.shutdown()?;
                return Err(CkksError::Backend(format!(
                    "OpenFHE bridge stdout exceeded {} bytes",
                    self.max_output_bytes,
                )));
            }
            if response_bytes.is_empty() {
                let retry = attempt == 0;
                let mut worker_process = worker.take().unwrap();
                worker_process.shutdown()?;
                if retry {
                    continue;
                }
                return Err(CkksError::Backend(
                    "OpenFHE bridge returned an empty response".to_string(),
                ));
            }
            let bridge_status = {
                let worker_process = worker.as_mut().unwrap();
                if worker_process.stderr_truncated.load(Ordering::Relaxed) {
                    Err(CkksError::Backend(format!(
                        "OpenFHE bridge stderr exceeded {} bytes",
                        self.max_output_bytes,
                    )))
                } else {
                    worker_process.child.try_wait().map_err(|err| {
                        CkksError::Backend(format!("failed to poll OpenFHE bridge status: {err}"))
                    })
                }
            };
            let bridge_status = match bridge_status {
                Ok(bridge_status) => bridge_status,
                Err(err) => {
                    if let Some(mut worker_process) = worker.take() {
                        worker_process.shutdown()?;
                    }
                    return Err(err);
                }
            };
            match bridge_status {
                Some(status) => {
                    let mut worker_process = worker.take().unwrap();
                    worker_process.shutdown()?;
                    if !status.success() {
                        return Err(CkksError::Backend(format!(
                            "OpenFHE bridge exited with status {}",
                            status,
                        )));
                    }
                }
                None => {}
            }

            let response: CommandOpenFheResponse = match serde_json::from_slice(&response_bytes) {
                Ok(response) => response,
                Err(err) => {
                    if let Some(mut worker_process) = worker.take() {
                        worker_process.shutdown()?;
                    }
                    return Err(CkksError::Backend(format!(
                        "failed to parse OpenFHE bridge response: {err}",
                    )));
                }
            };
            if response.version != 1 {
                if let Some(mut worker_process) = worker.take() {
                    worker_process.shutdown()?;
                }
                return Err(CkksError::Backend(format!(
                    "unsupported OpenFHE bridge response version {}",
                    response.version,
                )));
            }

            return match BASE64URL_NOPAD.decode(response.ciphertext.as_bytes()) {
                Ok(ciphertext) => Ok(ciphertext),
                Err(_) => {
                    if let Some(mut worker_process) = worker.take() {
                        worker_process.shutdown()?;
                    }
                    Err(CkksError::Backend(
                        "OpenFHE bridge returned invalid ciphertext".to_string(),
                    ))
                }
            };
        }

        Err(CkksError::Backend(
            "OpenFHE bridge retry budget was exhausted".to_string(),
        ))
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

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
struct CommandOpenFheResponse {
    version: u8,
    ciphertext: String,
}
