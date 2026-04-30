// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! CBOR-framed IPC protocol over named pipes.
//!
//! Each message is written as a 4-byte big-endian length prefix followed by a
//! definite-length CBOR map with string keys. Requests always use the shape
//! `{ "method": tstr, "params": map/nil }`, and responses always use the
//! shape `{ "result": any/nil, "error": map/nil }`.
//!
//! Byte-oriented payloads such as DER certificates and signatures are encoded as
//! CBOR byte strings (major type 2), avoiding JSON base64 expansion.

use std::collections::HashMap;
use std::io::{Read, Write};

use cbor_primitives::{CborDecoder, CborEncoder, CborProvider, CborType};
use cbor_primitives_everparse::EverParseCborProvider;

use crate::traits::*;

pub use crate::auth::{AUTH_KEY_ENV_VAR, AUTH_KEY_LENGTH};

const REQUEST_FIELD_COUNT: usize = 2;
const RESPONSE_FIELD_COUNT: usize = 2;

/// A request from the host to a plugin.
#[derive(Debug, Clone)]
pub struct Request {
    /// RPC method name.
    pub method: String,
    /// Method-specific parameters.
    pub params: RequestParams,
}

impl Request {
    /// Creates a request with explicit method and params.
    pub fn new(method: impl Into<String>, params: RequestParams) -> Self {
        Self {
            method: method.into(),
            params,
        }
    }

    /// Creates a `capabilities` request.
    pub fn capabilities() -> Self {
        Self::new(methods::CAPABILITIES, RequestParams::None)
    }

    /// Creates a `create_service` request.
    pub fn create_service(config: PluginConfig) -> Self {
        Self::new(
            methods::CREATE_SERVICE,
            RequestParams::CreateService(config),
        )
    }

    /// Creates a `get_cert_chain` request.
    pub fn get_cert_chain(service_id: impl Into<String>) -> Self {
        Self::new(
            methods::GET_CERT_CHAIN,
            RequestParams::ServiceId {
                service_id: service_id.into(),
            },
        )
    }

    /// Creates a `get_algorithm` request.
    pub fn get_algorithm(service_id: impl Into<String>) -> Self {
        Self::new(
            methods::GET_ALGORITHM,
            RequestParams::ServiceId {
                service_id: service_id.into(),
            },
        )
    }

    /// Creates a `sign` request.
    pub fn sign(service_id: impl Into<String>, data: Vec<u8>, algorithm: i64) -> Self {
        Self::new(
            methods::SIGN,
            RequestParams::Sign(SignRequest {
                service_id: service_id.into(),
                data,
                algorithm,
            }),
        )
    }

    /// Creates a `verify` request.
    pub fn verify(
        cose_bytes: Vec<u8>,
        payload: Option<Vec<u8>>,
        options: VerificationOptions,
    ) -> Self {
        Self::new(
            methods::VERIFY,
            RequestParams::Verify {
                cose_bytes,
                detached_payload: payload,
                options,
            },
        )
    }

    /// Creates a `get_trust_policy_info` request.
    pub fn trust_policy_info() -> Self {
        Self::new(methods::GET_TRUST_POLICY_INFO, RequestParams::None)
    }

    /// Creates a `shutdown` request.
    pub fn shutdown() -> Self {
        Self::new(methods::SHUTDOWN, RequestParams::None)
    }

    /// Creates an `authenticate` request with the given auth key.
    pub fn authenticate(auth_key: Vec<u8>) -> Self {
        Self::new(
            methods::AUTHENTICATE,
            RequestParams::Authenticate { auth_key },
        )
    }
}

/// Typed request parameters for the well-known plugin methods.
#[derive(Debug, Clone)]
pub enum RequestParams {
    /// No parameters (`null`).
    None,
    /// Parameters for `authenticate` — 32-byte auth key as CBOR bstr.
    Authenticate {
        /// The auth key bytes (must be AUTH_KEY_LENGTH bytes).
        auth_key: Vec<u8>,
    },
    /// Parameters for `create_service`.
    CreateService(PluginConfig),
    /// Parameters containing only a service identifier.
    ServiceId {
        /// The logical service identifier.
        service_id: String,
    },
    /// Parameters for `sign`.
    Sign(SignRequest),
    /// Parameters for `verify`.
    Verify {
        /// Raw COSE_Sign1 bytes.
        cose_bytes: Vec<u8>,
        /// Optional detached payload bytes.
        detached_payload: Option<Vec<u8>>,
        /// Verification options.
        options: VerificationOptions,
    },
    /// Raw pre-encoded CBOR for forward-compatible extensions.
    RawCbor(Vec<u8>),
}

/// A response from a plugin to the host.
#[derive(Debug, Clone)]
pub struct Response {
    /// Result on success, or `None` when the response encoded CBOR `null`.
    pub result: ResponseResult,
    /// Error details on failure.
    pub error: Option<ProtocolError>,
}

impl Response {
    /// Creates a successful response.
    pub fn ok(result: ResponseResult) -> Self {
        Self {
            result,
            error: None,
        }
    }

    /// Creates an error response.
    pub fn err(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            result: ResponseResult::None,
            error: Some(ProtocolError {
                code: code.into(),
                message: message.into(),
            }),
        }
    }
}

/// Typed response payloads for the well-known plugin methods.
#[derive(Debug, Clone)]
pub enum ResponseResult {
    /// No result (`null`).
    None,
    /// Acknowledgment (used for `authenticate` and `shutdown`).
    Acknowledged,
    /// Result payload for `capabilities`.
    PluginInfo(PluginInfo),
    /// Result payload for `create_service`.
    CreateService {
        /// The created service identifier.
        service_id: String,
    },
    /// Result payload for `get_cert_chain`.
    CertificateChain(CertificateChainResponse),
    /// Result payload for `get_algorithm`.
    Algorithm(AlgorithmResponse),
    /// Result payload for `sign`.
    Sign(SignResponse),
    /// Result payload for `get_trust_policy_info`.
    TrustPolicyInfo(TrustPolicyInfo),
    /// Result payload for `verify`.
    Verification(VerificationResult),
    /// Raw pre-encoded CBOR for forward-compatible extensions.
    RawCbor(Vec<u8>),
}

/// An error response payload.
#[derive(Debug, Clone)]
pub struct ProtocolError {
    /// Error code.
    pub code: String,
    /// Human-readable message.
    pub message: String,
}

/// Errors that can occur while encoding or decoding protocol frames.
#[derive(Debug)]
pub enum ProtocolCodecError {
    /// The message shape did not match the expected wire format.
    InvalidMessage(String),
    /// CBOR encoding or decoding failed.
    Cbor(String),
    /// Framing I/O failed.
    Io(std::io::Error),
}

impl std::fmt::Display for ProtocolCodecError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidMessage(message) => write!(f, "invalid plugin IPC message: {}", message),
            Self::Cbor(message) => write!(f, "CBOR codec error: {}", message),
            Self::Io(error) => write!(f, "I/O error: {}", error),
        }
    }
}

impl std::error::Error for ProtocolCodecError {}

impl From<std::io::Error> for ProtocolCodecError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value)
    }
}

/// Result alias for protocol encoding/decoding operations.
pub type ProtocolResult<T> = Result<T, ProtocolCodecError>;

/// Method names for the plugin protocol.
pub mod methods {
    /// Authenticate the connection. Must be the first message sent by the host.
    /// Params: `{ "auth_key": bstr }` — 32-byte random key passed via environment variable.
    /// The plugin verifies this key using constant-time comparison before accepting
    /// any further requests. This prevents unauthorized processes from connecting
    /// to the named pipe.
    pub const AUTHENTICATE: &str = "authenticate";
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
    /// Describe verification trust policies. Returns `TrustPolicyInfo` or `null`.
    pub const GET_TRUST_POLICY_INFO: &str = "get_trust_policy_info";
    /// Verify a COSE_Sign1 message. Returns `VerificationResult` or `null`.
    pub const VERIFY: &str = "verify";
    /// Graceful shutdown.
    pub const SHUTDOWN: &str = "shutdown";
}

/// Encodes a request body into CBOR.
pub fn encode_request<E>(encoder: &mut E, request: &Request) -> ProtocolResult<()>
where
    E: CborEncoder,
    E::Error: std::fmt::Display,
{
    validate_request(request)?;
    encoder
        .encode_map(REQUEST_FIELD_COUNT)
        .map_err(cbor_error)?;
    encoder.encode_tstr("method").map_err(cbor_error)?;
    encoder
        .encode_tstr(request.method.as_str())
        .map_err(cbor_error)?;
    encoder.encode_tstr("params").map_err(cbor_error)?;
    encode_request_params(encoder, &request.params)
}

/// Decodes a request body from CBOR.
pub fn decode_request<'a, D>(decoder: &mut D) -> ProtocolResult<Request>
where
    D: CborDecoder<'a>,
    D::Error: std::fmt::Display,
{
    let entry_count = decode_required_map_len(decoder, "request")?;
    let mut method: Option<String> = None;
    let mut params_bytes: Option<Vec<u8>> = None;
    let mut params_seen = false;

    for _ in 0..entry_count {
        let key = decode_tstr_owned(decoder)?;
        match key.as_str() {
            "method" => {
                method = Some(decode_tstr_owned(decoder)?);
            }
            "params" => {
                params_seen = true;
                if decoder.is_null().map_err(cbor_error)? {
                    decoder.decode_null().map_err(cbor_error)?;
                } else {
                    params_bytes = Some(decode_raw_owned(decoder)?);
                }
            }
            _ => {
                decoder.skip().map_err(cbor_error)?;
            }
        }
    }

    if !params_seen {
        return Err(ProtocolCodecError::InvalidMessage(
            "request is missing the 'params' field".into(),
        ));
    }

    let method = method.ok_or_else(|| {
        ProtocolCodecError::InvalidMessage("request is missing the 'method' field".into())
    })?;
    let params = decode_request_params(method.as_str(), params_bytes.as_deref())?;

    Ok(Request { method, params })
}

/// Encodes a response body into CBOR.
pub fn encode_response<E>(encoder: &mut E, response: &Response) -> ProtocolResult<()>
where
    E: CborEncoder,
    E::Error: std::fmt::Display,
{
    encoder
        .encode_map(RESPONSE_FIELD_COUNT)
        .map_err(cbor_error)?;
    encoder.encode_tstr("result").map_err(cbor_error)?;
    encode_response_result(encoder, &response.result)?;
    encoder.encode_tstr("error").map_err(cbor_error)?;
    match &response.error {
        Some(error) => encode_protocol_error(encoder, error),
        None => encoder.encode_null().map_err(cbor_error),
    }
}

/// Decodes a response body from CBOR.
pub fn decode_response<'a, D>(decoder: &mut D) -> ProtocolResult<Response>
where
    D: CborDecoder<'a>,
    D::Error: std::fmt::Display,
{
    let entry_count = decode_required_map_len(decoder, "response")?;
    let mut result = ResponseResult::None;
    let mut error: Option<ProtocolError> = None;
    let mut result_seen = false;
    let mut error_seen = false;

    for _ in 0..entry_count {
        let key = decode_tstr_owned(decoder)?;
        match key.as_str() {
            "result" => {
                result_seen = true;
                if decoder.is_null().map_err(cbor_error)? {
                    decoder.decode_null().map_err(cbor_error)?;
                    result = ResponseResult::None;
                } else {
                    let raw = decode_raw_owned(decoder)?;
                    result = decode_response_result(raw.as_slice())?;
                }
            }
            "error" => {
                error_seen = true;
                if decoder.is_null().map_err(cbor_error)? {
                    decoder.decode_null().map_err(cbor_error)?;
                    error = None;
                } else {
                    error = Some(decode_protocol_error(decoder)?);
                }
            }
            _ => {
                decoder.skip().map_err(cbor_error)?;
            }
        }
    }

    if !result_seen {
        return Err(ProtocolCodecError::InvalidMessage(
            "response is missing the 'result' field".into(),
        ));
    }

    if !error_seen {
        return Err(ProtocolCodecError::InvalidMessage(
            "response is missing the 'error' field".into(),
        ));
    }

    Ok(Response { result, error })
}

/// Writes a length-prefixed CBOR frame.
pub fn write_frame(writer: &mut impl Write, cbor_bytes: &[u8]) -> std::io::Result<()> {
    if cbor_bytes.len() > u32::MAX as usize {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "plugin IPC frame exceeds the 4-byte length prefix limit",
        ));
    }

    let length_prefix = (cbor_bytes.len() as u32).to_be_bytes();
    writer.write_all(&length_prefix)?;
    writer.write_all(cbor_bytes)?;
    writer.flush()
}

/// Reads a length-prefixed CBOR frame.
pub fn read_frame(reader: &mut impl Read) -> std::io::Result<Vec<u8>> {
    match read_frame_optional(reader)? {
        Some(frame) => Ok(frame),
        None => Err(std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            "named pipe closed before a full frame prefix was read",
        )),
    }
}

/// Writes a framed CBOR request.
pub fn write_request(writer: &mut impl Write, request: &Request) -> std::io::Result<()> {
    let provider = EverParseCborProvider;
    let mut encoder = provider.encoder();
    encode_request(&mut encoder, request).map_err(protocol_to_io_error)?;
    let frame = encoder.into_bytes();
    write_frame(writer, frame.as_slice())
}

/// Reads a framed CBOR request.
pub fn read_request(reader: &mut impl Read) -> std::io::Result<Option<Request>> {
    let frame = match read_frame_optional(reader)? {
        Some(frame) => frame,
        None => return Ok(None),
    };

    let provider = EverParseCborProvider;
    let mut decoder = provider.decoder(frame.as_slice());
    let request = decode_request(&mut decoder).map_err(protocol_to_io_error)?;
    ensure_no_trailing(&decoder, "request").map_err(protocol_to_io_error)?;
    Ok(Some(request))
}

/// Writes a framed CBOR response.
pub fn write_response(writer: &mut impl Write, response: &Response) -> std::io::Result<()> {
    let provider = EverParseCborProvider;
    let mut encoder = provider.encoder();
    encode_response(&mut encoder, response).map_err(protocol_to_io_error)?;
    let frame = encoder.into_bytes();
    write_frame(writer, frame.as_slice())
}

/// Reads a framed CBOR response.
pub fn read_response(reader: &mut impl Read) -> std::io::Result<Response> {
    let frame = read_frame(reader)?;
    let provider = EverParseCborProvider;
    let mut decoder = provider.decoder(frame.as_slice());
    let response = decode_response(&mut decoder).map_err(protocol_to_io_error)?;
    ensure_no_trailing(&decoder, "response").map_err(protocol_to_io_error)?;
    Ok(response)
}

fn validate_request(request: &Request) -> ProtocolResult<()> {
    match request.method.as_str() {
        methods::CAPABILITIES | methods::GET_TRUST_POLICY_INFO | methods::SHUTDOWN => {
            if !matches!(request.params, RequestParams::None) {
                return Err(ProtocolCodecError::InvalidMessage(format!(
                    "'{}' must not include params",
                    request.method
                )));
            }
        }
        methods::AUTHENTICATE => {
            if !matches!(request.params, RequestParams::Authenticate { .. }) {
                return Err(ProtocolCodecError::InvalidMessage(
                    "'authenticate' requires auth_key bstr param".into(),
                ));
            }
        }
        methods::CREATE_SERVICE => {
            if !matches!(request.params, RequestParams::CreateService(_)) {
                return Err(ProtocolCodecError::InvalidMessage(
                    "'create_service' requires PluginConfig params".into(),
                ));
            }
        }
        methods::GET_CERT_CHAIN | methods::GET_ALGORITHM => {
            if !matches!(request.params, RequestParams::ServiceId { .. }) {
                return Err(ProtocolCodecError::InvalidMessage(format!(
                    "'{}' requires a service_id param map",
                    request.method
                )));
            }
        }
        methods::SIGN => {
            if !matches!(request.params, RequestParams::Sign(_)) {
                return Err(ProtocolCodecError::InvalidMessage(
                    "'sign' requires SignRequest params".into(),
                ));
            }
        }
        methods::VERIFY => {
            if !matches!(request.params, RequestParams::Verify { .. }) {
                return Err(ProtocolCodecError::InvalidMessage(
                    "'verify' requires verification params".into(),
                ));
            }
        }
        _ => {}
    }

    Ok(())
}

fn encode_request_params<E>(encoder: &mut E, params: &RequestParams) -> ProtocolResult<()>
where
    E: CborEncoder,
    E::Error: std::fmt::Display,
{
    match params {
        RequestParams::None => encoder.encode_null().map_err(cbor_error),
        RequestParams::Authenticate { auth_key } => {
            encoder.encode_map(1).map_err(cbor_error)?;
            encoder.encode_tstr("auth_key").map_err(cbor_error)?;
            encoder.encode_bstr(auth_key.as_slice()).map_err(cbor_error)
        }
        RequestParams::CreateService(config) => encode_plugin_config(encoder, config),
        RequestParams::ServiceId { service_id } => {
            encoder.encode_map(1).map_err(cbor_error)?;
            encoder.encode_tstr("service_id").map_err(cbor_error)?;
            encoder.encode_tstr(service_id.as_str()).map_err(cbor_error)
        }
        RequestParams::Sign(request) => {
            encoder.encode_map(3).map_err(cbor_error)?;
            encoder.encode_tstr("service_id").map_err(cbor_error)?;
            encoder
                .encode_tstr(request.service_id.as_str())
                .map_err(cbor_error)?;
            encoder.encode_tstr("data").map_err(cbor_error)?;
            encoder
                .encode_bstr(request.data.as_slice())
                .map_err(cbor_error)?;
            encoder.encode_tstr("algorithm").map_err(cbor_error)?;
            encoder.encode_i64(request.algorithm).map_err(cbor_error)
        }
        RequestParams::Verify {
            cose_bytes,
            detached_payload,
            options,
        } => {
            encoder.encode_map(3).map_err(cbor_error)?;
            encoder.encode_tstr("cose_bytes").map_err(cbor_error)?;
            encoder
                .encode_bstr(cose_bytes.as_slice())
                .map_err(cbor_error)?;
            encoder.encode_tstr("payload").map_err(cbor_error)?;
            match detached_payload {
                Some(payload) => encoder
                    .encode_bstr(payload.as_slice())
                    .map_err(cbor_error)?,
                None => encoder.encode_null().map_err(cbor_error)?,
            }
            encoder.encode_tstr("options").map_err(cbor_error)?;
            encode_verification_options(encoder, options)
        }
        RequestParams::RawCbor(raw) => encoder.encode_raw(raw.as_slice()).map_err(cbor_error),
    }
}

fn encode_response_result<E>(encoder: &mut E, result: &ResponseResult) -> ProtocolResult<()>
where
    E: CborEncoder,
    E::Error: std::fmt::Display,
{
    match result {
        ResponseResult::None => encoder.encode_null().map_err(cbor_error),
        ResponseResult::Acknowledged => encoder.encode_bool(true).map_err(cbor_error),
        ResponseResult::PluginInfo(info) => encode_plugin_info(encoder, info),
        ResponseResult::CreateService { service_id } => {
            encoder.encode_map(1).map_err(cbor_error)?;
            encoder.encode_tstr("service_id").map_err(cbor_error)?;
            encoder.encode_tstr(service_id.as_str()).map_err(cbor_error)
        }
        ResponseResult::CertificateChain(chain) => {
            encoder.encode_map(1).map_err(cbor_error)?;
            encoder.encode_tstr("certificates").map_err(cbor_error)?;
            encoder
                .encode_array(chain.certificates.len())
                .map_err(cbor_error)?;
            for certificate in &chain.certificates {
                encoder
                    .encode_bstr(certificate.as_slice())
                    .map_err(cbor_error)?;
            }
            Ok(())
        }
        ResponseResult::Algorithm(result) => {
            encoder.encode_map(1).map_err(cbor_error)?;
            encoder.encode_tstr("algorithm").map_err(cbor_error)?;
            encoder.encode_i64(result.algorithm).map_err(cbor_error)
        }
        ResponseResult::Sign(result) => {
            encoder.encode_map(1).map_err(cbor_error)?;
            encoder.encode_tstr("signature").map_err(cbor_error)?;
            encoder
                .encode_bstr(result.signature.as_slice())
                .map_err(cbor_error)
        }
        ResponseResult::TrustPolicyInfo(result) => encode_trust_policy_info(encoder, result),
        ResponseResult::Verification(result) => encode_verification_result(encoder, result),
        ResponseResult::RawCbor(raw) => encoder.encode_raw(raw.as_slice()).map_err(cbor_error),
    }
}

fn encode_plugin_info<E>(encoder: &mut E, info: &PluginInfo) -> ProtocolResult<()>
where
    E: CborEncoder,
    E::Error: std::fmt::Display,
{
    encoder.encode_map(5).map_err(cbor_error)?;
    encoder.encode_tstr("id").map_err(cbor_error)?;
    encoder.encode_tstr(info.id.as_str()).map_err(cbor_error)?;
    encoder.encode_tstr("name").map_err(cbor_error)?;
    encoder
        .encode_tstr(info.name.as_str())
        .map_err(cbor_error)?;
    encoder.encode_tstr("version").map_err(cbor_error)?;
    encoder
        .encode_tstr(info.version.as_str())
        .map_err(cbor_error)?;
    encoder.encode_tstr("description").map_err(cbor_error)?;
    encoder
        .encode_tstr(info.description.as_str())
        .map_err(cbor_error)?;
    encoder.encode_tstr("capabilities").map_err(cbor_error)?;
    encoder
        .encode_array(info.capabilities.len())
        .map_err(cbor_error)?;
    for capability in &info.capabilities {
        encoder
            .encode_tstr(capability.as_str())
            .map_err(cbor_error)?;
    }
    Ok(())
}

fn encode_plugin_config<E>(encoder: &mut E, config: &PluginConfig) -> ProtocolResult<()>
where
    E: CborEncoder,
    E::Error: std::fmt::Display,
{
    encoder.encode_map(1).map_err(cbor_error)?;
    encoder.encode_tstr("options").map_err(cbor_error)?;
    encode_string_map(encoder, &config.options)
}

fn encode_verification_options<E>(
    encoder: &mut E,
    options: &VerificationOptions,
) -> ProtocolResult<()>
where
    E: CborEncoder,
    E::Error: std::fmt::Display,
{
    encoder.encode_map(3).map_err(cbor_error)?;
    encoder
        .encode_tstr("trust_embedded_chain")
        .map_err(cbor_error)?;
    encoder
        .encode_bool(options.trust_embedded_chain)
        .map_err(cbor_error)?;
    encoder
        .encode_tstr("allowed_thumbprints")
        .map_err(cbor_error)?;
    encode_string_array(encoder, options.allowed_thumbprints.as_slice())?;
    encoder.encode_tstr("signature_only").map_err(cbor_error)?;
    encoder
        .encode_bool(options.signature_only)
        .map_err(cbor_error)
}

fn encode_trust_policy_info<E>(encoder: &mut E, info: &TrustPolicyInfo) -> ProtocolResult<()>
where
    E: CborEncoder,
    E::Error: std::fmt::Display,
{
    encoder.encode_map(3).map_err(cbor_error)?;
    encoder.encode_tstr("name").map_err(cbor_error)?;
    encoder
        .encode_tstr(info.name.as_str())
        .map_err(cbor_error)?;
    encoder.encode_tstr("description").map_err(cbor_error)?;
    encoder
        .encode_tstr(info.description.as_str())
        .map_err(cbor_error)?;
    encoder.encode_tstr("supported_modes").map_err(cbor_error)?;
    encode_string_array(encoder, info.supported_modes.as_slice())
}

fn encode_verification_result<E>(encoder: &mut E, result: &VerificationResult) -> ProtocolResult<()>
where
    E: CborEncoder,
    E::Error: std::fmt::Display,
{
    encoder.encode_map(3).map_err(cbor_error)?;
    encoder.encode_tstr("is_valid").map_err(cbor_error)?;
    encoder.encode_bool(result.is_valid).map_err(cbor_error)?;
    encoder.encode_tstr("stages").map_err(cbor_error)?;
    encoder
        .encode_array(result.stages.len())
        .map_err(cbor_error)?;
    for stage in &result.stages {
        encode_verification_stage_result(encoder, stage)?;
    }
    encoder.encode_tstr("metadata").map_err(cbor_error)?;
    encode_string_map(encoder, &result.metadata)
}

fn encode_verification_stage_result<E>(
    encoder: &mut E,
    result: &VerificationStageResult,
) -> ProtocolResult<()>
where
    E: CborEncoder,
    E::Error: std::fmt::Display,
{
    encoder.encode_map(4).map_err(cbor_error)?;
    encoder.encode_tstr("stage").map_err(cbor_error)?;
    encoder
        .encode_tstr(result.stage.as_str())
        .map_err(cbor_error)?;
    encoder.encode_tstr("kind").map_err(cbor_error)?;
    encoder
        .encode_tstr(verification_stage_kind_as_str(&result.kind))
        .map_err(cbor_error)?;
    encoder.encode_tstr("failures").map_err(cbor_error)?;
    encoder
        .encode_array(result.failures.len())
        .map_err(cbor_error)?;
    for failure in &result.failures {
        encode_verification_failure(encoder, failure)?;
    }
    encoder.encode_tstr("metadata").map_err(cbor_error)?;
    encode_string_map(encoder, &result.metadata)
}

fn encode_verification_failure<E>(
    encoder: &mut E,
    failure: &VerificationFailure,
) -> ProtocolResult<()>
where
    E: CborEncoder,
    E::Error: std::fmt::Display,
{
    encoder.encode_map(2).map_err(cbor_error)?;
    encoder.encode_tstr("message").map_err(cbor_error)?;
    encoder
        .encode_tstr(failure.message.as_str())
        .map_err(cbor_error)?;
    encoder.encode_tstr("error_code").map_err(cbor_error)?;
    match &failure.error_code {
        Some(error_code) => encoder.encode_tstr(error_code.as_str()).map_err(cbor_error),
        None => encoder.encode_null().map_err(cbor_error),
    }
}

fn encode_string_map<E>(encoder: &mut E, values: &HashMap<String, String>) -> ProtocolResult<()>
where
    E: CborEncoder,
    E::Error: std::fmt::Display,
{
    let mut entries: Vec<(&String, &String)> = values.iter().collect();
    entries.sort_by(|left, right| left.0.cmp(right.0));

    encoder.encode_map(entries.len()).map_err(cbor_error)?;
    for (key, value) in entries {
        encoder.encode_tstr(key.as_str()).map_err(cbor_error)?;
        encoder.encode_tstr(value.as_str()).map_err(cbor_error)?;
    }
    Ok(())
}

fn encode_string_array<E>(encoder: &mut E, values: &[String]) -> ProtocolResult<()>
where
    E: CborEncoder,
    E::Error: std::fmt::Display,
{
    encoder.encode_array(values.len()).map_err(cbor_error)?;
    for value in values {
        encoder.encode_tstr(value.as_str()).map_err(cbor_error)?;
    }
    Ok(())
}

fn encode_protocol_error<E>(encoder: &mut E, error: &ProtocolError) -> ProtocolResult<()>
where
    E: CborEncoder,
    E::Error: std::fmt::Display,
{
    encoder.encode_map(2).map_err(cbor_error)?;
    encoder.encode_tstr("code").map_err(cbor_error)?;
    encoder
        .encode_tstr(error.code.as_str())
        .map_err(cbor_error)?;
    encoder.encode_tstr("message").map_err(cbor_error)?;
    encoder
        .encode_tstr(error.message.as_str())
        .map_err(cbor_error)?;
    Ok(())
}

fn decode_request_params(method: &str, raw_params: Option<&[u8]>) -> ProtocolResult<RequestParams> {
    match method {
        methods::CAPABILITIES | methods::GET_TRUST_POLICY_INFO | methods::SHUTDOWN => {
            if raw_params.is_some() {
                return Err(ProtocolCodecError::InvalidMessage(format!(
                    "'{}' must not include params",
                    method
                )));
            }
            Ok(RequestParams::None)
        }
        methods::AUTHENTICATE => {
            let raw = require_params(method, raw_params)?;
            let auth_key = decode_auth_key_from_bytes(raw)?;
            Ok(RequestParams::Authenticate { auth_key })
        }
        methods::CREATE_SERVICE => {
            let raw = require_params(method, raw_params)?;
            Ok(RequestParams::CreateService(
                decode_plugin_config_from_bytes(raw)?,
            ))
        }
        methods::GET_CERT_CHAIN | methods::GET_ALGORITHM => {
            let raw = require_params(method, raw_params)?;
            let service_id = decode_service_id_map_from_bytes(raw, method)?;
            Ok(RequestParams::ServiceId { service_id })
        }
        methods::SIGN => {
            let raw = require_params(method, raw_params)?;
            Ok(RequestParams::Sign(decode_sign_request_from_bytes(raw)?))
        }
        methods::VERIFY => {
            let raw = require_params(method, raw_params)?;
            decode_verify_request_from_bytes(raw)
        }
        _ => match raw_params {
            Some(raw) => Ok(RequestParams::RawCbor(raw.to_vec())),
            None => Ok(RequestParams::None),
        },
    }
}

fn decode_response_result(raw_result: &[u8]) -> ProtocolResult<ResponseResult> {
    if try_decode_acknowledged_from_bytes(raw_result)? {
        return Ok(ResponseResult::Acknowledged);
    }

    if let Some(info) = try_decode_plugin_info_from_bytes(raw_result)? {
        return Ok(ResponseResult::PluginInfo(info));
    }

    if let Some(service_id) = try_decode_create_service_result_from_bytes(raw_result)? {
        return Ok(ResponseResult::CreateService { service_id });
    }

    if let Some(chain) = try_decode_certificate_chain_response_from_bytes(raw_result)? {
        return Ok(ResponseResult::CertificateChain(chain));
    }

    if let Some(algorithm) = try_decode_algorithm_response_from_bytes(raw_result)? {
        return Ok(ResponseResult::Algorithm(algorithm));
    }

    if let Some(signature) = try_decode_sign_response_from_bytes(raw_result)? {
        return Ok(ResponseResult::Sign(signature));
    }

    if let Some(info) = try_decode_trust_policy_info_from_bytes(raw_result)? {
        return Ok(ResponseResult::TrustPolicyInfo(info));
    }

    if let Some(result) = try_decode_verification_result_from_bytes(raw_result)? {
        return Ok(ResponseResult::Verification(result));
    }

    Ok(ResponseResult::RawCbor(raw_result.to_vec()))
}

fn decode_plugin_config_from_bytes(data: &[u8]) -> ProtocolResult<PluginConfig> {
    let provider = EverParseCborProvider;
    let mut decoder = provider.decoder(data);
    let entry_count = decode_required_map_len(&mut decoder, "create_service params")?;
    let mut options: Option<HashMap<String, String>> = None;

    for _ in 0..entry_count {
        let key = decode_tstr_owned(&mut decoder)?;
        match key.as_str() {
            "options" => {
                options = Some(decode_options_map(&mut decoder)?);
            }
            _ => {
                decoder.skip().map_err(cbor_error)?;
            }
        }
    }

    ensure_no_trailing(&decoder, "create_service params")?;

    Ok(PluginConfig {
        options: options.ok_or_else(|| {
            ProtocolCodecError::InvalidMessage(
                "create_service params are missing the 'options' map".into(),
            )
        })?,
    })
}

fn decode_sign_request_from_bytes(data: &[u8]) -> ProtocolResult<SignRequest> {
    let provider = EverParseCborProvider;
    let mut decoder = provider.decoder(data);
    let entry_count = decode_required_map_len(&mut decoder, "sign params")?;
    let mut service_id: Option<String> = None;
    let mut payload: Option<Vec<u8>> = None;
    let mut algorithm: Option<i64> = None;

    for _ in 0..entry_count {
        let key = decode_tstr_owned(&mut decoder)?;
        match key.as_str() {
            "service_id" => {
                service_id = Some(decode_tstr_owned(&mut decoder)?);
            }
            "data" => {
                payload = Some(decode_bstr_owned(&mut decoder)?);
            }
            "algorithm" => {
                algorithm = Some(decoder.decode_i64().map_err(cbor_error)?);
            }
            _ => {
                decoder.skip().map_err(cbor_error)?;
            }
        }
    }

    ensure_no_trailing(&decoder, "sign params")?;

    Ok(SignRequest {
        service_id: service_id.ok_or_else(|| {
            ProtocolCodecError::InvalidMessage("sign params are missing 'service_id'".into())
        })?,
        data: payload.ok_or_else(|| {
            ProtocolCodecError::InvalidMessage("sign params are missing 'data'".into())
        })?,
        algorithm: algorithm.ok_or_else(|| {
            ProtocolCodecError::InvalidMessage("sign params are missing 'algorithm'".into())
        })?,
    })
}

fn decode_verify_request_from_bytes(data: &[u8]) -> ProtocolResult<RequestParams> {
    let provider = EverParseCborProvider;
    let mut decoder = provider.decoder(data);
    let entry_count = decode_required_map_len(&mut decoder, "verify params")?;
    let mut cose_bytes: Option<Vec<u8>> = None;
    let mut detached_payload: Option<Vec<u8>> = None;
    let mut payload_seen = false;
    let mut options: Option<VerificationOptions> = None;

    for _ in 0..entry_count {
        let key = decode_tstr_owned(&mut decoder)?;
        match key.as_str() {
            "cose_bytes" => {
                cose_bytes = Some(decode_bstr_owned(&mut decoder)?);
            }
            "payload" => {
                payload_seen = true;
                if decoder.is_null().map_err(cbor_error)? {
                    decoder.decode_null().map_err(cbor_error)?;
                    detached_payload = None;
                } else {
                    detached_payload = Some(decode_bstr_owned(&mut decoder)?);
                }
            }
            "options" => {
                options = Some(decode_verification_options(&mut decoder)?);
            }
            _ => {
                decoder.skip().map_err(cbor_error)?;
            }
        }
    }

    ensure_no_trailing(&decoder, "verify params")?;

    if !payload_seen {
        return Err(ProtocolCodecError::InvalidMessage(
            "verify params are missing 'payload'".into(),
        ));
    }

    Ok(RequestParams::Verify {
        cose_bytes: cose_bytes.ok_or_else(|| {
            ProtocolCodecError::InvalidMessage("verify params are missing 'cose_bytes'".into())
        })?,
        detached_payload,
        options: options.ok_or_else(|| {
            ProtocolCodecError::InvalidMessage("verify params are missing 'options'".into())
        })?,
    })
}

fn decode_service_id_map_from_bytes(data: &[u8], context: &str) -> ProtocolResult<String> {
    let provider = EverParseCborProvider;
    let mut decoder = provider.decoder(data);
    let entry_count = decode_required_map_len(&mut decoder, context)?;
    let mut service_id: Option<String> = None;

    for _ in 0..entry_count {
        let key = decode_tstr_owned(&mut decoder)?;
        match key.as_str() {
            "service_id" => {
                service_id = Some(decode_tstr_owned(&mut decoder)?);
            }
            _ => {
                decoder.skip().map_err(cbor_error)?;
            }
        }
    }

    ensure_no_trailing(&decoder, context)?;

    service_id.ok_or_else(|| {
        ProtocolCodecError::InvalidMessage(format!("{} is missing 'service_id'", context))
    })
}

fn decode_auth_key_from_bytes(data: &[u8]) -> ProtocolResult<Vec<u8>> {
    let provider = EverParseCborProvider;
    let mut decoder = provider.decoder(data);
    let entry_count = decode_required_map_len(&mut decoder, "authenticate")?;
    let mut auth_key: Option<Vec<u8>> = None;

    for _ in 0..entry_count {
        let key = decode_tstr_owned(&mut decoder)?;
        match key.as_str() {
            "auth_key" => {
                auth_key = Some(decoder.decode_bstr_owned().map_err(cbor_error)?);
            }
            _ => {
                decoder.skip().map_err(cbor_error)?;
            }
        }
    }

    ensure_no_trailing(&decoder, "authenticate")?;

    auth_key.ok_or_else(|| {
        ProtocolCodecError::InvalidMessage("authenticate is missing 'auth_key'".into())
    })
}

fn try_decode_acknowledged_from_bytes(data: &[u8]) -> ProtocolResult<bool> {
    let provider = EverParseCborProvider;
    let mut decoder = provider.decoder(data);
    if decoder.peek_type().map_err(cbor_error)? != CborType::Bool {
        return Ok(false);
    }

    let acknowledged = decoder.decode_bool().map_err(cbor_error)?;
    ensure_no_trailing(&decoder, "acknowledgement result")?;
    Ok(acknowledged)
}

fn try_decode_plugin_info_from_bytes(data: &[u8]) -> ProtocolResult<Option<PluginInfo>> {
    let provider = EverParseCborProvider;
    let mut decoder = provider.decoder(data);
    if decoder.peek_type().map_err(cbor_error)? != CborType::Map {
        return Ok(None);
    }

    let entry_count = decode_required_map_len(&mut decoder, "capabilities result")?;
    let mut id: Option<String> = None;
    let mut name: Option<String> = None;
    let mut version: Option<String> = None;
    let mut description: Option<String> = None;
    let mut capabilities: Option<Vec<PluginCapability>> = None;
    let mut matched_unique_field = false;

    for _ in 0..entry_count {
        let key = decode_tstr_owned(&mut decoder)?;
        match key.as_str() {
            "id" => {
                matched_unique_field = true;
                id = Some(decode_tstr_owned(&mut decoder)?);
            }
            "name" => {
                name = Some(decode_tstr_owned(&mut decoder)?);
            }
            "version" => {
                matched_unique_field = true;
                version = Some(decode_tstr_owned(&mut decoder)?);
            }
            "description" => {
                description = Some(decode_tstr_owned(&mut decoder)?);
            }
            "capabilities" => {
                matched_unique_field = true;
                capabilities = Some(decode_capabilities_array(&mut decoder)?);
            }
            _ => {
                decoder.skip().map_err(cbor_error)?;
            }
        }
    }

    ensure_no_trailing(&decoder, "capabilities result")?;

    if !matched_unique_field {
        return Ok(None);
    }

    Ok(Some(PluginInfo {
        id: id.ok_or_else(|| {
            ProtocolCodecError::InvalidMessage("capabilities result is missing 'id'".into())
        })?,
        name: name.ok_or_else(|| {
            ProtocolCodecError::InvalidMessage("capabilities result is missing 'name'".into())
        })?,
        version: version.ok_or_else(|| {
            ProtocolCodecError::InvalidMessage("capabilities result is missing 'version'".into())
        })?,
        description: description.ok_or_else(|| {
            ProtocolCodecError::InvalidMessage(
                "capabilities result is missing 'description'".into(),
            )
        })?,
        capabilities: capabilities.ok_or_else(|| {
            ProtocolCodecError::InvalidMessage(
                "capabilities result is missing 'capabilities'".into(),
            )
        })?,
    }))
}

fn try_decode_create_service_result_from_bytes(data: &[u8]) -> ProtocolResult<Option<String>> {
    let provider = EverParseCborProvider;
    let mut decoder = provider.decoder(data);
    if decoder.peek_type().map_err(cbor_error)? != CborType::Map {
        return Ok(None);
    }

    let entry_count = decode_required_map_len(&mut decoder, "create_service result")?;
    let mut service_id: Option<String> = None;

    for _ in 0..entry_count {
        let key = decode_tstr_owned(&mut decoder)?;
        match key.as_str() {
            "service_id" => {
                service_id = Some(decode_tstr_owned(&mut decoder)?);
            }
            _ => {
                decoder.skip().map_err(cbor_error)?;
            }
        }
    }

    ensure_no_trailing(&decoder, "create_service result")?;
    Ok(service_id)
}

fn try_decode_certificate_chain_response_from_bytes(
    data: &[u8],
) -> ProtocolResult<Option<CertificateChainResponse>> {
    let provider = EverParseCborProvider;
    let mut decoder = provider.decoder(data);
    if decoder.peek_type().map_err(cbor_error)? != CborType::Map {
        return Ok(None);
    }

    let entry_count = decode_required_map_len(&mut decoder, "get_cert_chain result")?;
    let mut certificates: Option<Vec<Vec<u8>>> = None;

    for _ in 0..entry_count {
        let key = decode_tstr_owned(&mut decoder)?;
        match key.as_str() {
            "certificates" => {
                certificates = Some(decode_certificate_array(&mut decoder)?);
            }
            _ => {
                decoder.skip().map_err(cbor_error)?;
            }
        }
    }

    ensure_no_trailing(&decoder, "get_cert_chain result")?;

    match certificates {
        Some(certificates) => Ok(Some(CertificateChainResponse { certificates })),
        None => Ok(None),
    }
}

fn try_decode_algorithm_response_from_bytes(
    data: &[u8],
) -> ProtocolResult<Option<AlgorithmResponse>> {
    let provider = EverParseCborProvider;
    let mut decoder = provider.decoder(data);
    if decoder.peek_type().map_err(cbor_error)? != CborType::Map {
        return Ok(None);
    }

    let entry_count = decode_required_map_len(&mut decoder, "get_algorithm result")?;
    let mut algorithm: Option<i64> = None;

    for _ in 0..entry_count {
        let key = decode_tstr_owned(&mut decoder)?;
        match key.as_str() {
            "algorithm" => {
                algorithm = Some(decoder.decode_i64().map_err(cbor_error)?);
            }
            _ => {
                decoder.skip().map_err(cbor_error)?;
            }
        }
    }

    ensure_no_trailing(&decoder, "get_algorithm result")?;

    match algorithm {
        Some(algorithm) => Ok(Some(AlgorithmResponse { algorithm })),
        None => Ok(None),
    }
}

fn try_decode_sign_response_from_bytes(data: &[u8]) -> ProtocolResult<Option<SignResponse>> {
    let provider = EverParseCborProvider;
    let mut decoder = provider.decoder(data);
    if decoder.peek_type().map_err(cbor_error)? != CborType::Map {
        return Ok(None);
    }

    let entry_count = decode_required_map_len(&mut decoder, "sign result")?;
    let mut signature: Option<Vec<u8>> = None;

    for _ in 0..entry_count {
        let key = decode_tstr_owned(&mut decoder)?;
        match key.as_str() {
            "signature" => {
                signature = Some(decode_bstr_owned(&mut decoder)?);
            }
            _ => {
                decoder.skip().map_err(cbor_error)?;
            }
        }
    }

    ensure_no_trailing(&decoder, "sign result")?;

    match signature {
        Some(signature) => Ok(Some(SignResponse { signature })),
        None => Ok(None),
    }
}

fn try_decode_trust_policy_info_from_bytes(data: &[u8]) -> ProtocolResult<Option<TrustPolicyInfo>> {
    let provider = EverParseCborProvider;
    let mut decoder = provider.decoder(data);
    if decoder.peek_type().map_err(cbor_error)? != CborType::Map {
        return Ok(None);
    }

    let entry_count = decode_required_map_len(&mut decoder, "trust policy info result")?;
    let mut name: Option<String> = None;
    let mut description: Option<String> = None;
    let mut supported_modes: Option<Vec<String>> = None;

    for _ in 0..entry_count {
        let key = decode_tstr_owned(&mut decoder)?;
        match key.as_str() {
            "name" => {
                name = Some(decode_tstr_owned(&mut decoder)?);
            }
            "description" => {
                description = Some(decode_tstr_owned(&mut decoder)?);
            }
            "supported_modes" => {
                supported_modes = Some(decode_string_array(&mut decoder, "supported_modes")?);
            }
            _ => {
                decoder.skip().map_err(cbor_error)?;
            }
        }
    }

    ensure_no_trailing(&decoder, "trust policy info result")?;

    match supported_modes {
        Some(supported_modes) => Ok(Some(TrustPolicyInfo {
            name: name.ok_or_else(|| {
                ProtocolCodecError::InvalidMessage(
                    "trust policy info result is missing 'name'".into(),
                )
            })?,
            description: description.ok_or_else(|| {
                ProtocolCodecError::InvalidMessage(
                    "trust policy info result is missing 'description'".into(),
                )
            })?,
            supported_modes,
        })),
        None => Ok(None),
    }
}

fn try_decode_verification_result_from_bytes(
    data: &[u8],
) -> ProtocolResult<Option<VerificationResult>> {
    let provider = EverParseCborProvider;
    let mut decoder = provider.decoder(data);
    if decoder.peek_type().map_err(cbor_error)? != CborType::Map {
        return Ok(None);
    }

    let entry_count = decode_required_map_len(&mut decoder, "verify result")?;
    let mut is_valid: Option<bool> = None;
    let mut stages: Option<Vec<VerificationStageResult>> = None;
    let mut metadata: Option<HashMap<String, String>> = None;

    for _ in 0..entry_count {
        let key = decode_tstr_owned(&mut decoder)?;
        match key.as_str() {
            "is_valid" => {
                is_valid = Some(decoder.decode_bool().map_err(cbor_error)?);
            }
            "stages" => {
                stages = Some(decode_verification_stage_array(&mut decoder)?);
            }
            "metadata" => {
                metadata = Some(decode_string_map(&mut decoder, "verification metadata")?);
            }
            _ => {
                decoder.skip().map_err(cbor_error)?;
            }
        }
    }

    ensure_no_trailing(&decoder, "verify result")?;

    if is_valid.is_none() && stages.is_none() {
        return Ok(None);
    }

    Ok(Some(VerificationResult {
        is_valid: is_valid.ok_or_else(|| {
            ProtocolCodecError::InvalidMessage("verify result is missing 'is_valid'".into())
        })?,
        stages: stages.ok_or_else(|| {
            ProtocolCodecError::InvalidMessage("verify result is missing 'stages'".into())
        })?,
        metadata: metadata.ok_or_else(|| {
            ProtocolCodecError::InvalidMessage("verify result is missing 'metadata'".into())
        })?,
    }))
}

fn decode_verification_stage_array<'a, D>(
    decoder: &mut D,
) -> ProtocolResult<Vec<VerificationStageResult>>
where
    D: CborDecoder<'a>,
    D::Error: std::fmt::Display,
{
    let entry_count = decode_required_array_len(decoder, "verification stages")?;
    let mut stages = Vec::with_capacity(entry_count);

    for _ in 0..entry_count {
        stages.push(decode_verification_stage_result(decoder)?);
    }

    Ok(stages)
}

fn decode_verification_stage_result<'a, D>(
    decoder: &mut D,
) -> ProtocolResult<VerificationStageResult>
where
    D: CborDecoder<'a>,
    D::Error: std::fmt::Display,
{
    let entry_count = decode_required_map_len(decoder, "verification stage")?;
    let mut stage: Option<String> = None;
    let mut kind: Option<VerificationStageKind> = None;
    let mut failures: Option<Vec<VerificationFailure>> = None;
    let mut metadata: Option<HashMap<String, String>> = None;

    for _ in 0..entry_count {
        let key = decode_tstr_owned(decoder)?;
        match key.as_str() {
            "stage" => {
                stage = Some(decode_tstr_owned(decoder)?);
            }
            "kind" => {
                kind = Some(decode_verification_stage_kind(decoder)?);
            }
            "failures" => {
                failures = Some(decode_verification_failure_array(decoder)?);
            }
            "metadata" => {
                metadata = Some(decode_string_map(decoder, "verification stage metadata")?);
            }
            _ => {
                decoder.skip().map_err(cbor_error)?;
            }
        }
    }

    Ok(VerificationStageResult {
        stage: stage.ok_or_else(|| {
            ProtocolCodecError::InvalidMessage("verification stage is missing 'stage'".into())
        })?,
        kind: kind.ok_or_else(|| {
            ProtocolCodecError::InvalidMessage("verification stage is missing 'kind'".into())
        })?,
        failures: failures.ok_or_else(|| {
            ProtocolCodecError::InvalidMessage("verification stage is missing 'failures'".into())
        })?,
        metadata: metadata.ok_or_else(|| {
            ProtocolCodecError::InvalidMessage("verification stage is missing 'metadata'".into())
        })?,
    })
}

fn decode_verification_failure_array<'a, D>(
    decoder: &mut D,
) -> ProtocolResult<Vec<VerificationFailure>>
where
    D: CborDecoder<'a>,
    D::Error: std::fmt::Display,
{
    let entry_count = decode_required_array_len(decoder, "verification failures")?;
    let mut failures = Vec::with_capacity(entry_count);

    for _ in 0..entry_count {
        failures.push(decode_verification_failure(decoder)?);
    }

    Ok(failures)
}

fn decode_verification_failure<'a, D>(decoder: &mut D) -> ProtocolResult<VerificationFailure>
where
    D: CborDecoder<'a>,
    D::Error: std::fmt::Display,
{
    let entry_count = decode_required_map_len(decoder, "verification failure")?;
    let mut message: Option<String> = None;
    let mut error_code: Option<Option<String>> = None;

    for _ in 0..entry_count {
        let key = decode_tstr_owned(decoder)?;
        match key.as_str() {
            "message" => {
                message = Some(decode_tstr_owned(decoder)?);
            }
            "error_code" => {
                if decoder.is_null().map_err(cbor_error)? {
                    decoder.decode_null().map_err(cbor_error)?;
                    error_code = Some(None);
                } else {
                    error_code = Some(Some(decode_tstr_owned(decoder)?));
                }
            }
            _ => {
                decoder.skip().map_err(cbor_error)?;
            }
        }
    }

    Ok(VerificationFailure {
        message: message.ok_or_else(|| {
            ProtocolCodecError::InvalidMessage("verification failure is missing 'message'".into())
        })?,
        error_code: error_code.ok_or_else(|| {
            ProtocolCodecError::InvalidMessage(
                "verification failure is missing 'error_code'".into(),
            )
        })?,
    })
}

fn decode_protocol_error<'a, D>(decoder: &mut D) -> ProtocolResult<ProtocolError>
where
    D: CborDecoder<'a>,
    D::Error: std::fmt::Display,
{
    let entry_count = decode_required_map_len(decoder, "response error")?;
    let mut code: Option<String> = None;
    let mut message: Option<String> = None;

    for _ in 0..entry_count {
        let key = decode_tstr_owned(decoder)?;
        match key.as_str() {
            "code" => {
                code = Some(decode_tstr_owned(decoder)?);
            }
            "message" => {
                message = Some(decode_tstr_owned(decoder)?);
            }
            _ => {
                decoder.skip().map_err(cbor_error)?;
            }
        }
    }

    Ok(ProtocolError {
        code: code.ok_or_else(|| {
            ProtocolCodecError::InvalidMessage("response error is missing 'code'".into())
        })?,
        message: message.ok_or_else(|| {
            ProtocolCodecError::InvalidMessage("response error is missing 'message'".into())
        })?,
    })
}

fn decode_options_map<'a, D>(decoder: &mut D) -> ProtocolResult<HashMap<String, String>>
where
    D: CborDecoder<'a>,
    D::Error: std::fmt::Display,
{
    decode_string_map(decoder, "options map")
}

fn decode_verification_options<'a, D>(decoder: &mut D) -> ProtocolResult<VerificationOptions>
where
    D: CborDecoder<'a>,
    D::Error: std::fmt::Display,
{
    let entry_count = decode_required_map_len(decoder, "verification options")?;
    let mut trust_embedded_chain = false;
    let mut allowed_thumbprints = Vec::new();
    let mut signature_only = false;

    for _ in 0..entry_count {
        let key = decode_tstr_owned(decoder)?;
        match key.as_str() {
            "trust_embedded_chain" => {
                trust_embedded_chain = decoder.decode_bool().map_err(cbor_error)?;
            }
            "allowed_thumbprints" => {
                allowed_thumbprints = decode_string_array(decoder, "allowed_thumbprints")?;
            }
            "signature_only" => {
                signature_only = decoder.decode_bool().map_err(cbor_error)?;
            }
            _ => {
                decoder.skip().map_err(cbor_error)?;
            }
        }
    }

    Ok(VerificationOptions {
        trust_embedded_chain,
        allowed_thumbprints,
        signature_only,
    })
}

fn decode_string_map<'a, D>(
    decoder: &mut D,
    context: &str,
) -> ProtocolResult<HashMap<String, String>>
where
    D: CborDecoder<'a>,
    D::Error: std::fmt::Display,
{
    let entry_count = decode_required_map_len(decoder, context)?;
    let mut values = HashMap::with_capacity(entry_count);

    for _ in 0..entry_count {
        let key = decode_tstr_owned(decoder)?;
        let value = decode_tstr_owned(decoder)?;
        values.insert(key, value);
    }

    Ok(values)
}

fn decode_string_array<'a, D>(decoder: &mut D, context: &str) -> ProtocolResult<Vec<String>>
where
    D: CborDecoder<'a>,
    D::Error: std::fmt::Display,
{
    let entry_count = decode_required_array_len(decoder, context)?;
    let mut values = Vec::with_capacity(entry_count);

    for _ in 0..entry_count {
        values.push(decode_tstr_owned(decoder)?);
    }

    Ok(values)
}

fn decode_capabilities_array<'a, D>(decoder: &mut D) -> ProtocolResult<Vec<PluginCapability>>
where
    D: CborDecoder<'a>,
    D::Error: std::fmt::Display,
{
    let entry_count = decode_required_array_len(decoder, "capabilities array")?;
    let mut capabilities = Vec::with_capacity(entry_count);

    for _ in 0..entry_count {
        let capability = decode_tstr_owned(decoder)?;
        let capability = PluginCapability::from_str(capability.as_str()).ok_or_else(|| {
            ProtocolCodecError::InvalidMessage(format!(
                "unknown plugin capability '{}'",
                capability
            ))
        })?;
        capabilities.push(capability);
    }

    Ok(capabilities)
}

fn decode_certificate_array<'a, D>(decoder: &mut D) -> ProtocolResult<Vec<Vec<u8>>>
where
    D: CborDecoder<'a>,
    D::Error: std::fmt::Display,
{
    let entry_count = decode_required_array_len(decoder, "certificate array")?;
    let mut certificates = Vec::with_capacity(entry_count);

    for _ in 0..entry_count {
        certificates.push(decode_bstr_owned(decoder)?);
    }

    Ok(certificates)
}

fn verification_stage_kind_as_str(kind: &VerificationStageKind) -> &'static str {
    match kind {
        VerificationStageKind::Success => "success",
        VerificationStageKind::Failure => "failure",
        VerificationStageKind::NotApplicable => "not_applicable",
    }
}

fn decode_verification_stage_kind<'a, D>(decoder: &mut D) -> ProtocolResult<VerificationStageKind>
where
    D: CborDecoder<'a>,
    D::Error: std::fmt::Display,
{
    let kind = decode_tstr_owned(decoder)?;
    match kind.as_str() {
        "success" => Ok(VerificationStageKind::Success),
        "failure" => Ok(VerificationStageKind::Failure),
        "not_applicable" => Ok(VerificationStageKind::NotApplicable),
        _ => Err(ProtocolCodecError::InvalidMessage(format!(
            "unknown verification stage kind '{}'",
            kind
        ))),
    }
}

fn decode_required_map_len<'a, D>(decoder: &mut D, context: &str) -> ProtocolResult<usize>
where
    D: CborDecoder<'a>,
    D::Error: std::fmt::Display,
{
    match decoder.decode_map_len().map_err(cbor_error)? {
        Some(value) => Ok(value),
        None => Err(ProtocolCodecError::InvalidMessage(format!(
            "{} must be a definite-length CBOR map",
            context
        ))),
    }
}

fn decode_required_array_len<'a, D>(decoder: &mut D, context: &str) -> ProtocolResult<usize>
where
    D: CborDecoder<'a>,
    D::Error: std::fmt::Display,
{
    match decoder.decode_array_len().map_err(cbor_error)? {
        Some(value) => Ok(value),
        None => Err(ProtocolCodecError::InvalidMessage(format!(
            "{} must be a definite-length CBOR array",
            context
        ))),
    }
}

fn decode_tstr_owned<'a, D>(decoder: &mut D) -> ProtocolResult<String>
where
    D: CborDecoder<'a>,
    D::Error: std::fmt::Display,
{
    decoder
        .decode_tstr()
        .map(|value| value.to_string())
        .map_err(cbor_error)
}

fn decode_bstr_owned<'a, D>(decoder: &mut D) -> ProtocolResult<Vec<u8>>
where
    D: CborDecoder<'a>,
    D::Error: std::fmt::Display,
{
    decoder
        .decode_bstr()
        .map(|value| value.to_vec())
        .map_err(cbor_error)
}

fn decode_raw_owned<'a, D>(decoder: &mut D) -> ProtocolResult<Vec<u8>>
where
    D: CborDecoder<'a>,
    D::Error: std::fmt::Display,
{
    decoder
        .decode_raw()
        .map(|value| value.to_vec())
        .map_err(cbor_error)
}

fn ensure_no_trailing<'a, D>(decoder: &D, context: &str) -> ProtocolResult<()>
where
    D: CborDecoder<'a>,
{
    if decoder.remaining().is_empty() {
        return Ok(());
    }

    Err(ProtocolCodecError::InvalidMessage(format!(
        "{} contains trailing CBOR data",
        context
    )))
}

fn require_params<'a>(method: &str, params: Option<&'a [u8]>) -> ProtocolResult<&'a [u8]> {
    params.ok_or_else(|| {
        ProtocolCodecError::InvalidMessage(format!("'{}' is missing params", method))
    })
}

fn cbor_error<E>(error: E) -> ProtocolCodecError
where
    E: std::fmt::Display,
{
    ProtocolCodecError::Cbor(error.to_string())
}

fn protocol_to_io_error(error: ProtocolCodecError) -> std::io::Error {
    match error {
        ProtocolCodecError::Io(error) => error,
        other => std::io::Error::new(std::io::ErrorKind::InvalidData, other),
    }
}

fn read_frame_optional(reader: &mut impl Read) -> std::io::Result<Option<Vec<u8>>> {
    let mut length_prefix = [0u8; 4];
    let bytes_read = reader.read(&mut length_prefix[..1])?;
    if bytes_read == 0 {
        return Ok(None);
    }

    reader.read_exact(&mut length_prefix[1..])?;
    let frame_length = u32::from_be_bytes(length_prefix) as usize;
    let mut frame = vec![0u8; frame_length];
    reader.read_exact(frame.as_mut_slice())?;
    Ok(Some(frame))
}
