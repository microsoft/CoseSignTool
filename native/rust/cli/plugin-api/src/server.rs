// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Server-side helpers for plugin IPC.

use crate::auth::{constant_time_eq, read_and_clear_auth_key, AuthError, AUTH_KEY_LENGTH};
use crate::client::PipeStream;
use crate::protocol::{self, methods, Request, RequestParams, Response, ResponseResult};
use crate::traits::{
    AlgorithmResponse, CertificateChainResponse, PluginCapability, PluginProvider,
    SignPayloadResponse, SignResponse,
};
use std::io::{Read, Write};

#[cfg(unix)]
use std::os::unix::net::UnixListener;

/// Errors that can occur while running a plugin server.
#[derive(Debug)]
pub enum ServerError {
    /// Required CLI arguments were missing.
    MissingArgument(String),
    /// Auth key handling failed.
    Auth(AuthError),
    /// Pipe or protocol I/O failed.
    Io(std::io::Error),
    /// The client failed authentication.
    AuthenticationFailed(String),
}

impl std::fmt::Display for ServerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingArgument(argument) => write!(f, "missing required argument {}", argument),
            Self::Auth(error) => write!(f, "plugin server auth failed: {}", error),
            Self::Io(error) => write!(f, "plugin server I/O failed: {}", error),
            Self::AuthenticationFailed(message) => {
                write!(f, "client authentication failed: {}", message)
            }
        }
    }
}

impl std::error::Error for ServerError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Auth(error) => Some(error),
            Self::Io(error) => Some(error),
            _ => None,
        }
    }
}

impl From<AuthError> for ServerError {
    fn from(value: AuthError) -> Self {
        Self::Auth(value)
    }
}

impl From<std::io::Error> for ServerError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value)
    }
}

/// Run a plugin server on a named pipe or Unix socket.
pub fn run(plugin: impl PluginProvider) -> Result<(), ServerError> {
    let args: Vec<String> = std::env::args().collect();
    run_with_args(plugin, args.as_slice())
}

/// Run a plugin server using an explicit argument vector.
pub fn run_with_args(mut plugin: impl PluginProvider, args: &[String]) -> Result<(), ServerError> {
    let pipe_name = find_arg(args, "--pipe-name")
        .ok_or_else(|| ServerError::MissingArgument("--pipe-name <name>".to_string()))?;
    let auth_key = read_and_clear_auth_key()?;
    let mut stream = accept_one_connection(pipe_name.as_str())?;

    serve_connection(&mut plugin, stream.as_mut(), &auth_key)
}

/// Authenticate and serve requests on an existing plugin transport.
pub fn serve_connection<S>(
    plugin: &mut dyn PluginProvider,
    stream: &mut S,
    expected_key: &[u8; AUTH_KEY_LENGTH],
) -> Result<(), ServerError>
where
    S: Read + Write + ?Sized,
{
    authenticate(stream, expected_key)?;

    loop {
        let request = match protocol::read_request(stream)? {
            Some(request) => request,
            None => break,
        };
        let should_shutdown = request.method == methods::SHUTDOWN;
        let response = dispatch_request(plugin, &request);
        protocol::write_response(stream, &response)?;

        if should_shutdown {
            break;
        }
    }

    Ok(())
}

fn authenticate<S>(stream: &mut S, expected_key: &[u8; AUTH_KEY_LENGTH]) -> Result<(), ServerError>
where
    S: Read + Write + ?Sized,
{
    let first_request = protocol::read_request(stream)?.ok_or_else(|| {
        ServerError::AuthenticationFailed("pipe closed before authenticate request".to_string())
    })?;

    if first_request.method != methods::AUTHENTICATE {
        let _ = protocol::write_response(
            stream,
            &Response::err("AUTH_REQUIRED", "first message must be 'authenticate'"),
        );
        return Err(ServerError::AuthenticationFailed(format!(
            "client sent '{}' before authenticating",
            first_request.method
        )));
    }

    let client_key = match &first_request.params {
        RequestParams::Authenticate { auth_key } => auth_key,
        _ => {
            let _ = protocol::write_response(
                stream,
                &Response::err("AUTH_INVALID", "authenticate requires auth_key bstr"),
            );
            return Err(ServerError::AuthenticationFailed(
                "authenticate request did not include auth_key bytes".to_string(),
            ));
        }
    };

    if !constant_time_eq(expected_key, client_key.as_slice()) {
        let _ = protocol::write_response(stream, &Response::err("AUTH_FAILED", "invalid auth key"));
        return Err(ServerError::AuthenticationFailed(
            "authenticate request contained an invalid auth key".to_string(),
        ));
    }

    protocol::write_response(stream, &Response::ok(ResponseResult::Acknowledged))?;
    Ok(())
}

/// Dispatch a decoded request to the plugin provider.
pub fn dispatch_request(plugin: &mut dyn PluginProvider, request: &Request) -> Response {
    match request.method.as_str() {
        methods::AUTHENTICATE => Response::err(
            "AUTH_ALREADY_COMPLETED",
            "connection is already authenticated",
        ),
        methods::CAPABILITIES => Response::ok(ResponseResult::PluginInfo(plugin.info())),
        methods::CREATE_SERVICE => {
            let config = match &request.params {
                RequestParams::CreateService(config) => config.clone(),
                _ => return Response::err("INVALID_PARAMS", "create_service requires config"),
            };

            match plugin.create_service(config) {
                Ok(service_id) => Response::ok(ResponseResult::CreateService { service_id }),
                Err(error) => Response::err("CREATE_SERVICE_FAILED", error),
            }
        }
        methods::GET_CERT_CHAIN => {
            let service_id = match &request.params {
                RequestParams::ServiceId { service_id } => service_id.as_str(),
                _ => return Response::err("INVALID_PARAMS", "requires service_id"),
            };

            match plugin.get_cert_chain(service_id) {
                Ok(certificates) => {
                    Response::ok(ResponseResult::CertificateChain(CertificateChainResponse {
                        certificates,
                    }))
                }
                Err(error) => Response::err("CERT_CHAIN_FAILED", error),
            }
        }
        methods::GET_ALGORITHM => {
            let service_id = match &request.params {
                RequestParams::ServiceId { service_id } => service_id.as_str(),
                _ => return Response::err("INVALID_PARAMS", "requires service_id"),
            };

            match plugin.get_algorithm(service_id) {
                Ok(algorithm) => {
                    Response::ok(ResponseResult::Algorithm(AlgorithmResponse { algorithm }))
                }
                Err(error) => Response::err("ALGORITHM_FAILED", error),
            }
        }
        methods::SIGN => {
            let sign_request = match &request.params {
                RequestParams::Sign(sign_request) => sign_request,
                _ => return Response::err("INVALID_PARAMS", "sign requires SignRequest"),
            };

            match plugin.sign(
                sign_request.service_id.as_str(),
                sign_request.data.as_slice(),
                sign_request.algorithm,
            ) {
                Ok(signature) => Response::ok(ResponseResult::Sign(SignResponse { signature })),
                Err(error) => Response::err("SIGN_FAILED", error),
            }
        }
        methods::SIGN_PAYLOAD => {
            let sign_request = match &request.params {
                RequestParams::SignPayload(sign_request) => sign_request,
                _ => {
                    return Response::err(
                        "INVALID_PARAMS",
                        "sign_payload requires SignPayloadRequest",
                    )
                }
            };

            match plugin.sign_payload(
                sign_request.service_id.as_str(),
                sign_request.payload.as_slice(),
                sign_request.content_type.as_str(),
                sign_request.format.as_str(),
                &sign_request.options,
            ) {
                Ok(cose_bytes) => {
                    Response::ok(ResponseResult::SignPayload(SignPayloadResponse { cose_bytes }))
                }
                Err(error) => Response::err("SIGN_PAYLOAD_FAILED", error),
            }
        }
        methods::GET_TRUST_POLICY_INFO => {
            if !supports_capability(plugin, PluginCapability::Verification) {
                return Response::ok(ResponseResult::None);
            }

            if !matches!(request.params, RequestParams::None) {
                return Response::err("INVALID_PARAMS", "get_trust_policy_info requires no params");
            }

            match plugin.trust_policy_info() {
                Some(info) => Response::ok(ResponseResult::TrustPolicyInfo(info)),
                None => Response::ok(ResponseResult::None),
            }
        }
        methods::VERIFY => {
            if !supports_capability(plugin, PluginCapability::Verification) {
                return Response::ok(ResponseResult::None);
            }

            let (cose_bytes, detached_payload, options) = match &request.params {
                RequestParams::Verify {
                    cose_bytes,
                    detached_payload,
                    options,
                } => (
                    cose_bytes.as_slice(),
                    detached_payload.as_deref(),
                    options.clone(),
                ),
                _ => return Response::err("INVALID_PARAMS", "verify requires verification params"),
            };

            match plugin.verify(cose_bytes, detached_payload, options) {
                Ok(Some(result)) => Response::ok(ResponseResult::Verification(result)),
                Ok(None) => Response::ok(ResponseResult::None),
                Err(error) => Response::err("VERIFY_FAILED", error),
            }
        }
        methods::SHUTDOWN => Response::ok(ResponseResult::Acknowledged),
        _ => Response::err("UNKNOWN_METHOD", format!("Unknown: {}", request.method)),
    }
}

fn supports_capability(plugin: &dyn PluginProvider, capability: PluginCapability) -> bool {
    plugin
        .info()
        .capabilities
        .iter()
        .any(|item| item == &capability)
}

fn find_arg(args: &[String], name: &str) -> Option<String> {
    args.iter()
        .position(|argument| argument == name)
        .and_then(|index| args.get(index + 1))
        .cloned()
}

#[cfg(unix)]
fn accept_one_connection(pipe_name: &str) -> Result<Box<dyn PipeStream>, ServerError> {
    let cleanup = SocketPathCleanup {
        path: pipe_name.to_string(),
    };
    let _ = std::fs::remove_file(pipe_name);
    let listener = UnixListener::bind(pipe_name)?;
    let (stream, _) = listener.accept()?;
    drop(listener);
    drop(cleanup);
    Ok(Box::new(stream))
}

#[cfg(unix)]
struct SocketPathCleanup {
    path: String,
}

#[cfg(unix)]
impl Drop for SocketPathCleanup {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(self.path.as_str());
    }
}

#[cfg(windows)]
fn accept_one_connection(pipe_name: &str) -> Result<Box<dyn PipeStream>, ServerError> {
    use std::ffi::c_void;
    use std::fs::File;
    use std::os::windows::io::{FromRawHandle, RawHandle};

    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn CreateNamedPipeW(
            name: *const u16,
            open_mode: u32,
            pipe_mode: u32,
            max_instances: u32,
            out_buffer_size: u32,
            in_buffer_size: u32,
            default_timeout: u32,
            security_attributes: *mut c_void,
        ) -> *mut c_void;
        fn ConnectNamedPipe(handle: *mut c_void, overlapped: *mut c_void) -> i32;
        fn CloseHandle(handle: *mut c_void) -> i32;
        fn GetLastError() -> u32;
    }

    const ERROR_PIPE_CONNECTED: u32 = 535;
    const FILE_FLAG_FIRST_PIPE_INSTANCE: u32 = 0x0008_0000;
    const PIPE_ACCESS_DUPLEX: u32 = 0x0000_0003;
    const PIPE_TYPE_BYTE: u32 = 0x0000_0000;
    const PIPE_READMODE_BYTE: u32 = 0x0000_0000;
    const PIPE_WAIT: u32 = 0x0000_0000;
    const PIPE_BUFFER_SIZE: u32 = 64 * 1024;
    const INVALID_HANDLE_VALUE: isize = -1;

    let wide_name = encode_wide_null(pipe_name);

    // SAFETY: `wide_name` is null-terminated and remains alive for the call. The
    // remaining arguments match the CreateNamedPipeW contract for a single,
    // blocking duplex byte pipe instance.
    let handle = unsafe {
        CreateNamedPipeW(
            wide_name.as_ptr(),
            PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE,
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
            1,
            PIPE_BUFFER_SIZE,
            PIPE_BUFFER_SIZE,
            0,
            std::ptr::null_mut(),
        )
    };

    if handle == INVALID_HANDLE_VALUE as *mut c_void {
        return Err(ServerError::Io(std::io::Error::last_os_error()));
    }

    // SAFETY: `handle` is a valid pipe handle returned by CreateNamedPipeW and
    // the blocking connect path does not use OVERLAPPED.
    let connected = unsafe { ConnectNamedPipe(handle, std::ptr::null_mut()) };
    if connected == 0 {
        // SAFETY: GetLastError reads the thread-local Win32 error from the
        // immediately preceding Win32 call.
        let error = unsafe { GetLastError() };
        if error != ERROR_PIPE_CONNECTED {
            // SAFETY: `handle` is still owned by this function and must be closed
            // on failure to avoid leaking the pipe instance.
            unsafe {
                let _ = CloseHandle(handle);
            }
            return Err(ServerError::Io(std::io::Error::from_raw_os_error(
                error as i32,
            )));
        }
    }

    // SAFETY: ownership of the valid pipe handle is transferred to `File`, which
    // will close it when dropped.
    let file = unsafe { File::from_raw_handle(handle as RawHandle) };
    Ok(Box::new(file))
}

#[cfg(windows)]
fn encode_wide_null(value: &str) -> Vec<u16> {
    let mut wide: Vec<u16> = value.encode_utf16().collect();
    wide.push(0);
    wide
}
