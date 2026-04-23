use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};

use data_encoding::BASE64URL_NOPAD;
use serde::{Deserialize, Serialize};

use crate::vector::{
    CKKS_SCHEME, CkksEncryptionInput, CkksError, CkksParameters, CkksVectorBackend,
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CommandOpenFheBackend {
    program: PathBuf,
    args: Vec<String>,
}

impl CommandOpenFheBackend {
    pub fn new(program: impl Into<PathBuf>) -> Self {
        Self {
            program: program.into(),
            args: Vec::new(),
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

        let output = child.wait_with_output().map_err(|err| {
            CkksError::Backend(format!("failed to read OpenFHE bridge response: {err}"))
        })?;
        if !output.status.success() {
            return Err(CkksError::Backend(format!(
                "OpenFHE bridge exited with status {}",
                output.status,
            )));
        }

        let response: CommandOpenFheResponse =
            serde_json::from_slice(&output.stdout).map_err(|err| {
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
