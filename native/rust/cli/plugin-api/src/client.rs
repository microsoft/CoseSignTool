// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Client-side helpers for authenticated plugin IPC.

use std::io::{Read, Write};
use std::time::{Duration, Instant};

#[cfg(unix)]
use std::os::unix::net::UnixStream;

use crate::auth::AUTH_KEY_LENGTH;
use crate::protocol::{self, methods, Request, Response, ResponseResult};
use crate::traits::{
    PluginConfig, PluginInfo, TrustPolicyInfo, VerificationOptions, VerificationResult,
};

const CONNECT_RETRY_DELAY: Duration = Duration::from_millis(50);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// Combined read/write transport for pipe-based plugin IPC.
pub trait PipeStream: Read + Write + Send {}

impl<T> PipeStream for T where T: Read + Write + Send {}

/// Errors that can occur while using a connected plugin client.
#[derive(Debug)]
pub enum ClientError {
    /// Connecting to the plugin timed out.
    ConnectionTimeout(String),
    /// I/O or protocol framing failed.
    Io(std::io::Error),
    /// The plugin returned an application-level error.
    Plugin {
        /// Method that failed.
        method: String,
        /// Plugin-provided error code.
        code: String,
        /// Plugin-provided message.
        message: String,
    },
    /// The plugin returned a response shape that did not match the method.
    UnexpectedResponse {
        /// Method being processed.
        method: String,
        /// Human-readable detail.
        details: String,
    },
}

impl std::fmt::Display for ClientError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ConnectionTimeout(pipe_name) => {
                write!(f, "timed out connecting to plugin pipe '{}'", pipe_name)
            }
            Self::Io(error) => write!(f, "plugin client I/O failed: {}", error),
            Self::Plugin {
                method,
                code,
                message,
            } => write!(
                f,
                "plugin returned an error for '{}': [{}] {}",
                method, code, message
            ),
            Self::UnexpectedResponse { method, details } => write!(
                f,
                "plugin returned an unexpected response for '{}': {}",
                method, details
            ),
        }
    }
}

impl std::error::Error for ClientError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            _ => None,
        }
    }
}

impl From<std::io::Error> for ClientError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value)
    }
}

/// A connected, authenticated plugin client.
pub struct PluginClient {
    stream: Box<dyn PipeStream>,
}

impl PluginClient {
    /// Connect to the given named pipe or Unix socket and authenticate.
    pub fn connect(pipe_name: &str, auth_key: &[u8; AUTH_KEY_LENGTH]) -> Result<Self, ClientError> {
        let stream = connect_stream(pipe_name)?;
        Self::connect_with_stream(stream, auth_key)
    }

    /// Authenticate an already-connected stream.
    pub fn connect_with_stream(
        mut stream: Box<dyn PipeStream>,
        auth_key: &[u8; AUTH_KEY_LENGTH],
    ) -> Result<Self, ClientError> {
        protocol::write_request(&mut stream, &Request::authenticate(auth_key.to_vec()))?;

        let response = protocol::read_response(&mut stream)?;
        if let Some(error) = response.error {
            return Err(ClientError::Plugin {
                method: methods::AUTHENTICATE.to_string(),
                code: error.code,
                message: error.message,
            });
        }

        match response.result {
            ResponseResult::Acknowledged => Ok(Self { stream }),
            result => Err(Self::unexpected_response(
                methods::AUTHENTICATE,
                "expected acknowledgement",
                result,
            )),
        }
    }

    /// Send a capabilities request.
    pub fn capabilities(&mut self) -> Result<PluginInfo, ClientError> {
        let response = self.call(&Request::capabilities())?;
        match response.result {
            ResponseResult::PluginInfo(info) => Ok(info),
            result => Err(Self::unexpected_response(
                methods::CAPABILITIES,
                "expected plugin info",
                result,
            )),
        }
    }

    /// Create a signing service.
    pub fn create_service(&mut self, config: PluginConfig) -> Result<String, ClientError> {
        let response = self.call(&Request::create_service(config))?;
        match response.result {
            ResponseResult::CreateService { service_id } => Ok(service_id),
            result => Err(Self::unexpected_response(
                methods::CREATE_SERVICE,
                "expected service identifier",
                result,
            )),
        }
    }

    /// Get the certificate chain for an existing service.
    pub fn get_cert_chain(&mut self, service_id: &str) -> Result<Vec<Vec<u8>>, ClientError> {
        let response = self.call(&Request::get_cert_chain(service_id))?;
        match response.result {
            ResponseResult::CertificateChain(chain) => Ok(chain.certificates),
            result => Err(Self::unexpected_response(
                methods::GET_CERT_CHAIN,
                "expected certificate chain",
                result,
            )),
        }
    }

    /// Get the signing algorithm for an existing service.
    pub fn get_algorithm(&mut self, service_id: &str) -> Result<i64, ClientError> {
        let response = self.call(&Request::get_algorithm(service_id))?;
        match response.result {
            ResponseResult::Algorithm(result) => Ok(result.algorithm),
            result => Err(Self::unexpected_response(
                methods::GET_ALGORITHM,
                "expected algorithm response",
                result,
            )),
        }
    }

    /// Sign data using an existing service.
    pub fn sign(
        &mut self,
        service_id: &str,
        data: &[u8],
        algorithm: i64,
    ) -> Result<Vec<u8>, ClientError> {
        let response = self.call(&Request::sign(service_id, data.to_vec(), algorithm))?;
        match response.result {
            ResponseResult::Sign(result) => Ok(result.signature),
            result => Err(Self::unexpected_response(
                methods::SIGN,
                "expected signature response",
                result,
            )),
        }
    }

    /// Sign a payload end-to-end using an existing service.
    pub fn sign_payload(
        &mut self,
        service_id: &str,
        payload: &[u8],
        content_type: &str,
        format: &str,
        options: PluginConfig,
    ) -> Result<Vec<u8>, ClientError> {
        let response = self.call(&Request::sign_payload(
            service_id,
            payload.to_vec(),
            content_type,
            format,
            options,
        ))?;
        match response.result {
            ResponseResult::SignPayload(result) => Ok(result.cose_bytes),
            result => Err(Self::unexpected_response(
                methods::SIGN_PAYLOAD,
                "expected sign_payload response",
                result,
            )),
        }
    }

    /// Get trust policy information, if the plugin supports verification.
    pub fn trust_policy_info(&mut self) -> Result<Option<TrustPolicyInfo>, ClientError> {
        let response = self.call(&Request::trust_policy_info())?;
        match response.result {
            ResponseResult::None => Ok(None),
            ResponseResult::TrustPolicyInfo(info) => Ok(Some(info)),
            result => Err(Self::unexpected_response(
                methods::GET_TRUST_POLICY_INFO,
                "expected trust policy info or null",
                result,
            )),
        }
    }

    /// Verify a COSE_Sign1 message, if the plugin supports verification.
    pub fn verify(
        &mut self,
        cose_bytes: &[u8],
        payload: Option<&[u8]>,
        options: VerificationOptions,
    ) -> Result<Option<VerificationResult>, ClientError> {
        let response = self.call(&Request::verify(
            cose_bytes.to_vec(),
            payload.map(|bytes| bytes.to_vec()),
            options,
        ))?;
        match response.result {
            ResponseResult::None => Ok(None),
            ResponseResult::Verification(result) => Ok(Some(result)),
            result => Err(Self::unexpected_response(
                methods::VERIFY,
                "expected verification result or null",
                result,
            )),
        }
    }

    /// Send shutdown and consume the client.
    pub fn shutdown(mut self) -> Result<(), ClientError> {
        self.send_shutdown()
    }

    /// Send shutdown without consuming the client.
    pub fn send_shutdown(&mut self) -> Result<(), ClientError> {
        let response = self.call(&Request::shutdown())?;
        match response.result {
            ResponseResult::Acknowledged => Ok(()),
            result => Err(Self::unexpected_response(
                methods::SHUTDOWN,
                "expected acknowledgement",
                result,
            )),
        }
    }

    fn call(&mut self, request: &Request) -> Result<Response, ClientError> {
        let method = request.method.clone();
        protocol::write_request(&mut self.stream, request)?;

        let response = protocol::read_response(&mut self.stream)?;
        if let Some(error) = response.error {
            return Err(ClientError::Plugin {
                method,
                code: error.code,
                message: error.message,
            });
        }

        Ok(response)
    }

    fn unexpected_response(method: &str, expected: &str, result: ResponseResult) -> ClientError {
        ClientError::UnexpectedResponse {
            method: method.to_string(),
            details: format!("{}; received {:?}", expected, result),
        }
    }
}

fn connect_stream(pipe_name: &str) -> Result<Box<dyn PipeStream>, ClientError> {
    let start = Instant::now();

    loop {
        match try_connect_stream(pipe_name) {
            Ok(stream) => return Ok(stream),
            Err(error) => {
                if start.elapsed() >= CONNECT_TIMEOUT {
                    return Err(ClientError::Io(std::io::Error::new(
                        error.kind(),
                        format!(
                            "timed out connecting to plugin pipe '{}': {}",
                            pipe_name, error
                        ),
                    )));
                }
            }
        }

        std::thread::sleep(CONNECT_RETRY_DELAY);
    }
}

#[cfg(windows)]
fn try_connect_stream(pipe_name: &str) -> std::io::Result<Box<dyn PipeStream>> {
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(pipe_name)?;
    Ok(Box::new(file))
}

#[cfg(unix)]
fn try_connect_stream(pipe_name: &str) -> std::io::Result<Box<dyn PipeStream>> {
    let stream = UnixStream::connect(pipe_name)?;
    Ok(Box::new(stream))
}
