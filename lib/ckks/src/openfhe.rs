use std::io::{self, Read, Write};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use data_encoding::BASE64URL_NOPAD;
use serde::{Deserialize, Serialize};

use crate::vector::{
    CKKS_SCHEME, CkksEncryptionInput, CkksError, CkksParameters, CkksVectorBackend,
};

const DEFAULT_BRIDGE_TIMEOUT: Duration = Duration::from_secs(30);
const DEFAULT_MAX_OUTPUT_BYTES: usize = 1024 * 1024;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CommandOpenFheBackend {
    program: PathBuf,
    args: Vec<String>,
    timeout: Duration,
    max_output_bytes: usize,
}

impl CommandOpenFheBackend {
    pub fn new(program: impl Into<PathBuf>) -> Self {
        Self {
            program: program.into(),
            args: Vec::new(),
            timeout: DEFAULT_BRIDGE_TIMEOUT,
            max_output_bytes: DEFAULT_MAX_OUTPUT_BYTES,
        }
    }

    pub fn with_args<I, S>(mut self, args: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.args.extend(args.into_iter().map(Into::into));
        self
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    pub fn with_max_output_bytes(mut self, max_output_bytes: usize) -> Self {
        self.max_output_bytes = max_output_bytes;
        self
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

        let mut child = Command::new(&self.program)
            .args(&self.args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|err| CkksError::Backend(format!("failed to start OpenFHE bridge: {err}")))?;

        {
            let stdin = child
                .stdin
                .as_mut()
                .ok_or_else(|| CkksError::Backend("failed to open bridge stdin".to_string()))?;
            serde_json::to_writer(&mut *stdin, &request).map_err(|err| {
                CkksError::Backend(format!("failed to write OpenFHE bridge request: {err}"))
            })?;
            stdin.write_all(b"\n").map_err(|err| {
                CkksError::Backend(format!("failed to terminate OpenFHE bridge request: {err}"))
            })?;
        }
        drop(child.stdin.take());

        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| CkksError::Backend("failed to open bridge stdout".to_string()))?;
        let stderr = child
            .stderr
            .take()
            .ok_or_else(|| CkksError::Backend("failed to open bridge stderr".to_string()))?;
        let stdout_reader = read_capped(stdout, self.max_output_bytes);
        let stderr_reader = read_capped(stderr, self.max_output_bytes);

        let status = wait_with_timeout(&mut child, self.timeout)?;
        let stdout = stdout_reader
            .join()
            .map_err(|_| CkksError::Backend("bridge stdout reader panicked".to_string()))?
            .map_err(|err| {
                CkksError::Backend(format!("failed to read OpenFHE bridge response: {err}"))
            })?;
        let stderr = stderr_reader
            .join()
            .map_err(|_| CkksError::Backend("bridge stderr reader panicked".to_string()))?
            .map_err(|err| {
                CkksError::Backend(format!("failed to drain OpenFHE bridge stderr: {err}"))
            })?;
        if stdout.truncated {
            return Err(CkksError::Backend(format!(
                "OpenFHE bridge stdout exceeded {} bytes",
                self.max_output_bytes,
            )));
        }
        if stderr.truncated {
            return Err(CkksError::Backend(format!(
                "OpenFHE bridge stderr exceeded {} bytes",
                self.max_output_bytes,
            )));
        }
        if !status.success() {
            return Err(CkksError::Backend(format!(
                "OpenFHE bridge exited with status {}",
                status,
            )));
        }

        let response: CommandOpenFheResponse =
            serde_json::from_slice(&stdout.bytes).map_err(|err| {
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
            .map_err(|_| {
                CkksError::Backend("OpenFHE bridge returned invalid ciphertext".to_string())
            })
    }
}

#[derive(Debug)]
struct CappedOutput {
    bytes: Vec<u8>,
    truncated: bool,
}

fn read_capped<R>(reader: R, max_bytes: usize) -> thread::JoinHandle<io::Result<CappedOutput>>
where
    R: Read + Send + 'static,
{
    thread::spawn(move || {
        let limit = max_bytes.saturating_add(1);
        let mut bytes = Vec::new();
        reader.take(limit as u64).read_to_end(&mut bytes)?;
        let truncated = bytes.len() > max_bytes;
        if truncated {
            bytes.truncate(max_bytes);
        }
        Ok(CappedOutput { bytes, truncated })
    })
}

fn wait_with_timeout(
    child: &mut std::process::Child,
    timeout: Duration,
) -> Result<std::process::ExitStatus, CkksError> {
    let deadline = Instant::now() + timeout;
    loop {
        if let Some(status) = child.try_wait().map_err(|err| {
            CkksError::Backend(format!("failed to poll OpenFHE bridge status: {err}"))
        })? {
            return Ok(status);
        }

        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            return Err(CkksError::Backend(format!(
                "OpenFHE bridge timed out after {} ms",
                timeout.as_millis(),
            )));
        }

        thread::sleep(Duration::from_millis(10));
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
