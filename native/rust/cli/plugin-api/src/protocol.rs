// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! JSON-framed IPC protocol over named pipes.
//!
//! Each message is a JSON object on a single line (newline-delimited JSON).
//! This keeps the protocol simple, debuggable, and language-agnostic.
//!
//! # Message Flow
//!
//! ```text
//! Host                              Plugin
//!   │                                 │
//!   │  {"method":"capabilities"}      │
//!   │ ──────────────────────────────► │
//!   │  {"result":{...plugin_info...}} │
//!   │ ◄────────────────────────────── │
//!   │                                 │
//!   │  {"method":"create_service",    │
//!   │   "params":{...config...}}      │
//!   │ ──────────────────────────────► │
//!   │  {"result":{"service_id":"s1"}} │
//!   │ ◄────────────────────────────── │
//!   │                                 │
//!   │  {"method":"get_cert_chain",    │
//!   │   "params":{"service_id":"s1"}} │
//!   │ ──────────────────────────────► │
//!   │  {"result":{...certs...}}       │
//!   │ ◄────────────────────────────── │
//!   │                                 │
//!   │  {"method":"sign",              │
//!   │   "params":{...sign_req...}}    │
//!   │ ──────────────────────────────► │
//!   │  {"result":{...signature...}}   │
//!   │ ◄────────────────────────────── │
//!   │                                 │
//!   │  {"method":"shutdown"}          │
//!   │ ──────────────────────────────► │
//!   │                          [exit] │
//! ```

use crate::traits::*;
use serde::{Deserialize, Serialize};

/// A request from the host to a plugin.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Request {
    /// RPC method name.
    pub method: String,
    /// Optional parameters (JSON value).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub params: Option<serde_json::Value>,
}

/// A response from a plugin to the host.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Response {
    /// Result on success.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result: Option<serde_json::Value>,
    /// Error on failure.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<ProtocolError>,
}

/// An error response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtocolError {
    /// Error code.
    pub code: String,
    /// Human-readable message.
    pub message: String,
}

impl Response {
    /// Create a success response.
    pub fn ok(result: serde_json::Value) -> Self {
        Self {
            result: Some(result),
            error: None,
        }
    }

    /// Create an error response.
    pub fn err(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            result: None,
            error: Some(ProtocolError {
                code: code.into(),
                message: message.into(),
            }),
        }
    }
}

// ============================================================================
// Well-known method names
// ============================================================================

/// Method names for the plugin protocol.
pub mod methods {
    /// Query plugin capabilities. Returns `PluginInfo`.
    pub const CAPABILITIES: &str = "capabilities";
    /// Create a signing service from configuration. Returns `{"service_id": "..."}`.
    pub const CREATE_SERVICE: &str = "create_service";
    /// Get the certificate chain for a service. Returns `CertificateChainResponse`.
    pub const GET_CERT_CHAIN: &str = "get_cert_chain";
    /// Get the signing algorithm for a service. Returns `{"algorithm": <i64>}`.
    pub const GET_ALGORITHM: &str = "get_algorithm";
    /// Sign data. Returns `SignResponse`.
    pub const SIGN: &str = "sign";
    /// Graceful shutdown.
    pub const SHUTDOWN: &str = "shutdown";
}

// ============================================================================
// Helpers for reading/writing protocol messages
// ============================================================================

use std::io::{BufRead, Write};

/// Write a request as a newline-delimited JSON line.
pub fn write_request(writer: &mut dyn Write, request: &Request) -> std::io::Result<()> {
    let json = serde_json::to_string(request)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    writeln!(writer, "{json}")?;
    writer.flush()
}

/// Write a response as a newline-delimited JSON line.
pub fn write_response(writer: &mut dyn Write, response: &Response) -> std::io::Result<()> {
    let json = serde_json::to_string(response)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    writeln!(writer, "{json}")?;
    writer.flush()
}

/// Read a request from a newline-delimited JSON stream.
pub fn read_request(reader: &mut dyn BufRead) -> std::io::Result<Option<Request>> {
    let mut line = String::new();
    let bytes_read = reader.read_line(&mut line)?;
    if bytes_read == 0 {
        return Ok(None); // EOF
    }
    let request: Request = serde_json::from_str(line.trim())
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    Ok(Some(request))
}

/// Read a response from a newline-delimited JSON stream.
pub fn read_response(reader: &mut dyn BufRead) -> std::io::Result<Response> {
    let mut line = String::new();
    reader.read_line(&mut line)?;
    let response: Response = serde_json::from_str(line.trim())
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    Ok(response)
}
