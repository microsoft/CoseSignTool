// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! CoseSignTool Plugin Loader — trusted bridge between host and compiled-in providers.
//!
//! # Architecture
//!
//! ```text
//! CoseSignTool.exe (host)
//!     │  spawns with:
//!     │    COSESIGNTOOL_PLUGIN_AUTH_KEY=<32-byte hex>
//!     │    --pipe-name <name>
//!     │    --plugin <provider-name>
//!     ▼
//! cosesigntool-plugin-loader.exe (this binary — trusted, our code)
//!     │
//!     ├─ Creates named pipe, accepts exactly 1 connection
//!     ├─ Verifies auth frame (constant-time comparison of auth key)
//!     ├─ Selects the compiled-in provider by name (feature-gated)
//!     └─ Proxies CBOR requests ↔ provider trait method calls
//! ```
//!
//! # Plugin Model
//!
//! **First-party plugins** (ATS, AKV, MST) are compiled into this binary via
//! Cargo feature flags. No dynamic loading, no C ABI, no unsafe.
//!
//! **Third-party plugins** ship their own binary implementing the CBOR/named-pipe
//! protocol using the `cosesigntool_plugin_api` crate. The host discovers them
//! in the plugins/ directory and spawns them directly (not via this loader).
//!
//! # Security Model
//!
//! - Host generates 32-byte cryptographic random auth key
//! - Auth key passed via environment variable (never CLI arg — invisible to `ps`)
//! - Loader accepts exactly 1 client connection on the named pipe
//! - First frame must be `authenticate` with the correct auth key
//! - Constant-time comparison prevents timing attacks
//! - Auth key cleared from env immediately after read

use anyhow::{Context, Result};
use cosesigntool_plugin_api::protocol::{self, methods, Request, RequestParams, Response, ResponseResult};
use cosesigntool_plugin_api::traits::*;
use std::io::{Read, Write};

#[cfg(unix)]
use std::os::unix::net::UnixListener;

/// Plugin trait — compiled-in providers implement this.
/// No C ABI, no unsafe, no dynamic loading for first-party plugins.
pub trait PluginProvider: Send {
    /// Plugin metadata.
    fn info(&self) -> PluginInfo;
    /// Create a signing service, returning a service ID.
    fn create_service(&mut self, config: PluginConfig) -> Result<String, String>;
    /// Get the certificate chain (DER bytes, leaf first).
    fn get_cert_chain(&mut self, service_id: &str) -> Result<Vec<Vec<u8>>, String>;
    /// Get the signing algorithm (COSE algorithm ID).
    fn get_algorithm(&mut self, service_id: &str) -> Result<i64, String>;
    /// Sign data, returning signature bytes.
    fn sign(&mut self, service_id: &str, data: &[u8], algorithm: i64) -> Result<Vec<u8>, String>;
}

fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_writer(std::io::stderr)
        .init();

    if let Err(err) = run() {
        eprintln!("[plugin-loader] fatal: {err:#}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();

    let pipe_name = find_arg(&args, "--pipe-name")
        .context("--pipe-name is required")?;
    let plugin_name = find_arg(&args, "--plugin")
        .context("--plugin is required (e.g., ats, akv)")?;

    // Read auth key from environment (never from CLI args — security)
    let auth_key_hex = std::env::var(protocol::AUTH_KEY_ENV_VAR)
        .with_context(|| format!("{} environment variable is not set", protocol::AUTH_KEY_ENV_VAR))?;
    let auth_key = hex_decode(&auth_key_hex).context("Invalid auth key hex")?;

    if auth_key.len() != protocol::AUTH_KEY_LENGTH {
        anyhow::bail!(
            "Auth key must be {} bytes, got {}",
            protocol::AUTH_KEY_LENGTH,
            auth_key.len()
        );
    }

    // Clear the env var immediately — don't leak to process inspection
    std::env::remove_var(protocol::AUTH_KEY_ENV_VAR);

    tracing::info!(pipe = %pipe_name, plugin = %plugin_name, "Plugin loader starting");

    // Accept exactly one connection on the named pipe
    let mut stream = accept_one_connection(&pipe_name)?;

    // Authenticate the connection
    authenticate(&mut stream, &auth_key)?;

    // Select the compiled-in provider
    let mut plugin = create_provider(&plugin_name)?;
    tracing::info!(plugin_id = %plugin.info().id, "Provider ready");

    // Request loop
    loop {
        let request = match protocol::read_request(&mut stream)? {
            Some(req) => req,
            None => {
                tracing::info!("Pipe closed — shutting down");
                break;
            }
        };

        let response = handle_request(&mut *plugin, &request);
        protocol::write_response(&mut stream, &response)?;

        if request.method == methods::SHUTDOWN {
            tracing::info!("Shutdown requested");
            break;
        }
    }

    Ok(())
}

/// Authenticate the connecting client via auth key.
fn authenticate(stream: &mut (impl Read + Write), expected_key: &[u8]) -> Result<()> {
    let first_request = protocol::read_request(stream)?
        .ok_or_else(|| anyhow::anyhow!("Pipe closed before auth frame"))?;

    if first_request.method != methods::AUTHENTICATE {
        let _ = protocol::write_response(
            stream,
            &Response::err("AUTH_REQUIRED", "First message must be 'authenticate'"),
        );
        anyhow::bail!("Client sent '{}' before authenticating", first_request.method);
    }

    let client_key = match &first_request.params {
        RequestParams::Authenticate { auth_key } => auth_key,
        _ => {
            let _ = protocol::write_response(
                stream,
                &Response::err("AUTH_INVALID", "authenticate requires auth_key bstr"),
            );
            anyhow::bail!("Invalid authenticate params");
        }
    };

    if !constant_time_eq(expected_key, client_key) {
        let _ = protocol::write_response(
            stream,
            &Response::err("AUTH_FAILED", "Invalid auth key"),
        );
        anyhow::bail!("Authentication failed — invalid auth key");
    }

    protocol::write_response(stream, &Response::ok(ResponseResult::Acknowledged))?;
    tracing::info!("Client authenticated");
    Ok(())
}

/// Select a compiled-in provider by name.
fn create_provider(name: &str) -> Result<Box<dyn PluginProvider>> {
    match name {
        // First-party providers compiled in via feature flags.
        // No dynamic loading, no C ABI, no unsafe.
        //
        // To add a new provider:
        // 1. Add a feature flag in Cargo.toml
        // 2. Add a match arm here behind #[cfg(feature = "...")]
        // 3. Implement PluginProvider for your provider struct
        _ => anyhow::bail!(
            "Unknown plugin '{}'. Available: {}",
            name,
            available_plugins().join(", ")
        ),
    }
}

/// List available compiled-in plugins.
fn available_plugins() -> Vec<&'static str> {
    let mut plugins = Vec::new();
    // Each feature-gated provider adds itself here
    let _ = &plugins; // suppress unused warning when no features enabled
    plugins
}

/// Handle a single request by dispatching to the provider.
fn handle_request(plugin: &mut dyn PluginProvider, request: &Request) -> Response {
    match request.method.as_str() {
        methods::CAPABILITIES => Response::ok(ResponseResult::PluginInfo(plugin.info())),
        methods::CREATE_SERVICE => {
            let config = match &request.params {
                RequestParams::CreateService(c) => c.clone(),
                _ => return Response::err("INVALID_PARAMS", "create_service requires config"),
            };
            match plugin.create_service(config) {
                Ok(service_id) => Response::ok(ResponseResult::CreateService { service_id }),
                Err(e) => Response::err("CREATE_SERVICE_FAILED", e),
            }
        }
        methods::GET_CERT_CHAIN => {
            let service_id = match &request.params {
                RequestParams::ServiceId { service_id } => service_id.as_str(),
                _ => return Response::err("INVALID_PARAMS", "requires service_id"),
            };
            match plugin.get_cert_chain(service_id) {
                Ok(certs) => Response::ok(ResponseResult::CertificateChain(
                    CertificateChainResponse { certificates: certs },
                )),
                Err(e) => Response::err("CERT_CHAIN_FAILED", e),
            }
        }
        methods::GET_ALGORITHM => {
            let service_id = match &request.params {
                RequestParams::ServiceId { service_id } => service_id.as_str(),
                _ => return Response::err("INVALID_PARAMS", "requires service_id"),
            };
            match plugin.get_algorithm(service_id) {
                Ok(alg) => Response::ok(ResponseResult::Algorithm(AlgorithmResponse { algorithm: alg })),
                Err(e) => Response::err("ALGORITHM_FAILED", e),
            }
        }
        methods::SIGN => {
            let req = match &request.params {
                RequestParams::Sign(s) => s,
                _ => return Response::err("INVALID_PARAMS", "sign requires SignRequest"),
            };
            match plugin.sign(&req.service_id, &req.data, req.algorithm) {
                Ok(sig) => Response::ok(ResponseResult::Sign(SignResponse { signature: sig })),
                Err(e) => Response::err("SIGN_FAILED", e),
            }
        }
        methods::SHUTDOWN => Response::ok(ResponseResult::Acknowledged),
        _ => Response::err("UNKNOWN_METHOD", format!("Unknown: {}", request.method)),
    }
}

/// Combined Read + Write trait for named pipe streams.
trait PipeStream: Read + Write + Send {}
impl<T: Read + Write + Send> PipeStream for T {}

/// Accept exactly one connection on the named pipe.
fn accept_one_connection(pipe_name: &str) -> Result<Box<dyn PipeStream>> {
    #[cfg(unix)]
    {
        // Clean up stale socket file
        let _ = std::fs::remove_file(pipe_name);
        let listener = UnixListener::bind(pipe_name)
            .with_context(|| format!("Failed to bind Unix socket: {pipe_name}"))?;
        let (stream, _) = listener.accept().context("Failed to accept connection")?;
        // Drop listener — no more connections accepted
        drop(listener);
        let _ = std::fs::remove_file(pipe_name);
        Ok(Box::new(stream))
    }

    #[cfg(windows)]
    {
        let pipe = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(pipe_name)
            .with_context(|| format!("Failed to open named pipe: {pipe_name}"))?;
        Ok(Box::new(pipe))
    }
}

/// Constant-time byte array comparison to prevent timing attacks.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut acc: u8 = 0;
    for (x, y) in a.iter().zip(b.iter()) {
        acc |= x ^ y;
    }
    acc == 0
}

/// Decode hex string to bytes.
fn hex_decode(hex: &str) -> Result<Vec<u8>> {
    if hex.len() % 2 != 0 {
        anyhow::bail!("Odd-length hex string");
    }
    (0..hex.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&hex[i..i + 2], 16)
                .map_err(|e| anyhow::anyhow!("Invalid hex at {i}: {e}"))
        })
        .collect()
}

fn find_arg(args: &[String], name: &str) -> Option<String> {
    args.iter()
        .position(|a| a == name)
        .and_then(|i| args.get(i + 1))
        .cloned()
}

