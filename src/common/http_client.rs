use std::path::Path;
use std::{io, result};

use common::defaults::APP_USER_AGENT;
use fs_err as fs;
use reqwest::header::{HeaderMap, HeaderValue, InvalidHeaderValue};
use storage::content_manager::errors::StorageError;
use zeroize::Zeroizing;

use super::auth::HTTP_HEADER_API_KEY;
use crate::settings::{Settings, TlsConfig};

#[derive(Clone)]
pub struct HttpClient {
    tls_config: Option<TlsConfig>,
    verify_https_client_certificate: bool,
}

impl HttpClient {
    pub fn from_settings(settings: &Settings) -> Result<Self> {
        let tls_config = if settings.service.enable_tls {
            let Some(tls_config) = settings.tls.clone() else {
                return Err(Error::TlsConfigUndefined);
            };

            Some(tls_config)
        } else {
            None
        };

        let verify_https_client_certificate = settings.service.verify_https_client_certificate;

        let http_client = Self {
            tls_config,
            verify_https_client_certificate,
        };

        Ok(http_client)
    }

    /// Create a new HTTP(S) client
    ///
    /// An API key can be optionally provided to be used in this HTTP client. It'll send the API
    /// key as `Api-key` header in every request.
    ///
    /// # Warning
    ///
    /// Setting an API key may leak when the client is used to send a request to a malicious
    /// server. This is potentially dangerous if a user has control over what URL is accessed.
    ///
    /// For this reason the API key is not set by default as provided in the configuration. It must
    /// be explicitly provided when creating the HTTP client.
    pub fn client(&self, api_key: Option<&str>) -> Result<reqwest::Client> {
        https_client(
            api_key,
            self.tls_config.as_ref(),
            self.verify_https_client_certificate,
        )
    }
}

fn https_client(
    api_key: Option<&str>,
    tls_config: Option<&TlsConfig>,
    verify_https_client_certificate: bool,
) -> Result<reqwest::Client> {
    let mut builder = reqwest::Client::builder()
        .user_agent(APP_USER_AGENT.as_str())
        .redirect(reqwest::redirect::Policy::none());

    // Configure TLS root certificate and validation
    if let Some(tls_config) = tls_config {
        if let Some(ca_cert) = &tls_config.ca_cert {
            match https_client_ca_cert(ca_cert) {
                Ok(ca_cert) => builder = builder.add_root_certificate(ca_cert),
                Err(err) => {
                    // I think it might be Ok to not fail here, if root certificate is not found
                    // There are 2 possible scenarios:
                    //
                    // 1. Server TLS is either not used or it uses some other CA certificate (like global one)
                    // 2. Server TLS is using self-signed certificate, and we should have it.
                    //
                    // In first case, we don't need to load the CA certificate, everything will work in either case.
                    // In second case, we should have the CA certificate, request will fail because of invalid certificate.
                    //
                    // So both scenarios work exactly the same way if we fail early or not.
                    // Warning message is needed for easier debugging in case of second scenario.
                    log::warn!(
                        "Failed to load CA certificate, skipping HTTPS client CA certificate configuration: {err}",
                    );
                }
            }
        } else if !verify_https_client_certificate {
            // If ca_cert is not provided, and we are not verifying client certificate,
            // there is no way to verify https connection.
            //
            // So we have to disable certificate verification in order to be able to connect to the server.
            builder = builder
                .danger_accept_invalid_certs(true)
                .danger_accept_invalid_hostnames(true);
        }

        if verify_https_client_certificate {
            builder = builder.identity(https_client_identity(
                tls_config.cert.as_ref(),
                tls_config.key.as_ref(),
            )?);
        }
    }

    // Attach API key as sensitive header
    if let Some(api_key) = api_key {
        let mut headers = HeaderMap::new();
        let mut api_key_value = HeaderValue::from_str(api_key).map_err(Error::MalformedApiKey)?;
        api_key_value.set_sensitive(true);
        headers.insert(HTTP_HEADER_API_KEY, api_key_value);
        builder = builder.default_headers(headers);
    }

    let client = builder.build()?;

    Ok(client)
}

fn https_client_ca_cert(ca_cert: impl AsRef<Path>) -> Result<reqwest::tls::Certificate> {
    let ca_cert_pem = fs::read(ca_cert.as_ref())
        .map_err(|err| Error::failed_to_read(err, "CA certificate", ca_cert.as_ref()))?;

    let ca_cert = reqwest::Certificate::from_pem(&ca_cert_pem)?;

    Ok(ca_cert)
}

fn https_client_identity(cert: &Path, key: &Path) -> Result<reqwest::tls::Identity> {
    let mut identity_pem = Zeroizing::new(
        fs::read(cert).map_err(|err| Error::failed_to_read(err, "certificate", cert))?,
    );

    let mut key_file = fs::File::open(key).map_err(|err| Error::failed_to_read(err, "key", key))?;

    // Concatenate certificate and key into a single PEM bytes
    io::copy(&mut key_file, &mut *identity_pem)
        .map_err(|err| Error::failed_to_read(err, "key", key))?;

    let identity = reqwest::Identity::from_pem(&identity_pem)?;

    Ok(identity)
}

pub type Result<T, E = Error> = result::Result<T, E>;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("TLS config is not defined in the Qdrant config file")]
    TlsConfigUndefined,

    #[error("{1}: {0}")]
    Io(#[source] io::Error, String),

    #[error("failed to setup HTTPS client: {0}")]
    Reqwest(#[from] reqwest::Error),

    #[error("malformed API key")]
    MalformedApiKey(#[source] InvalidHeaderValue),
}

impl Error {
    pub fn io(source: io::Error, context: impl Into<String>) -> Self {
        Self::Io(source, context.into())
    }

    pub fn failed_to_read(source: io::Error, file: &str, path: &Path) -> Self {
        Self::io(
            source,
            format!("failed to read HTTPS client {file} file {}", path.display()),
        )
    }
}

impl From<Error> for StorageError {
    fn from(err: Error) -> Self {
        StorageError::service_error(format!("failed to initialize HTTP(S) client: {err}"))
    }
}

#[cfg(test)]
mod tests {
    use fs_err as fs;
    use reqwest::StatusCode;

    use super::{https_client, https_client_identity};

    #[tokio::test]
    async fn api_key_client_does_not_follow_redirects() {
        let mut server = mockito::Server::new_async().await;
        let redirect = server
            .mock("GET", "/redirect")
            .with_status(StatusCode::FOUND.as_u16() as usize)
            .with_header("location", "/target")
            .create();
        let target = server.mock("GET", "/target").with_status(200).create();

        let client = https_client(Some("secret-api-key"), None, true).unwrap();
        let response = client
            .get(format!("{}/redirect", server.url()))
            .send()
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::FOUND);
        redirect.expect(1).assert_async().await;
        target.expect(0).assert_async().await;
    }

    #[test]
    fn https_client_identity_error_does_not_echo_private_key_contents() {
        let directory = tempfile::tempdir().unwrap();
        let cert_path = directory.path().join("cert.pem");
        let key_path = directory.path().join("key.pem");
        let private_key_sentinel = "qdrant-sec-tls-private-key-sentinel";

        fs::write(&cert_path, b"not a certificate").unwrap();
        fs::write(
            &key_path,
            format!(
                "-----BEGIN PRIVATE KEY-----\n{private_key_sentinel}\n-----END PRIVATE KEY-----\n"
            ),
        )
        .unwrap();

        let err = https_client_identity(&cert_path, &key_path)
            .expect_err("invalid identity material must fail");
        let rendered = err.to_string();

        assert!(!rendered.contains(private_key_sentinel), "{rendered}");
    }
}

impl From<Error> for io::Error {
    fn from(err: Error) -> Self {
        io::Error::other(err)
    }
}
