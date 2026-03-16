// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! PFX (PKCS#12) format certificate loading.
//!
//! Uses a thin [`Pkcs12Parser`] trait to abstract the OpenSSL PKCS#12 parsing,
//! so that all business logic (password resolution, validation, result mapping)
//! can be unit tested with a mock parser.
//!
//! ## Architecture
//!
//! ```text
//! ┌──────────────────────────────────────────────┐
//! │  load_from_pfx() / load_from_pfx_bytes()     │  ← public API
//! │  load_with_parser()                          │  ← testable core
//! │    resolve_password()                        │  ← env var only, never CLI arg
//! │    parser.parse_pkcs12(bytes, password)       │  ← trait call
//! │    map ParsedPkcs12 → Certificate            │
//! ├──────────────────────────────────────────────┤
//! │  Pkcs12Parser trait                          │  ← seam (mockable)
//! ├──────────────────────────────────────────────┤
//! │  OpenSslPkcs12Parser                         │  ← thin OpenSSL wrapper
//! └──────────────────────────────────────────────┘
//! ```
//!
//! ## Password Security
//!
//! Passwords are **never** accepted as CLI arguments (visible in process
//! listings). Instead, use one of:
//!
//! - **Environment variable**: `COSESIGNTOOL_PFX_PASSWORD` (default) or custom name
//! - **Empty string**: for PFX files protected with a null/empty password
//! - **No password**: some PFX files have no password protection at all

use crate::certificate::Certificate;
use crate::error::CertLocalError;
use std::path::Path;

/// Default environment variable name for PFX passwords.
pub const PFX_PASSWORD_ENV_VAR: &str = "COSESIGNTOOL_PFX_PASSWORD";

// ============================================================================
// Parsed PFX result type
// ============================================================================

/// Result of parsing a PKCS#12 (PFX) file.
#[derive(Debug, Clone)]
pub struct ParsedPkcs12 {
    /// DER-encoded leaf certificate.
    pub cert_der: Vec<u8>,
    /// DER-encoded PKCS#8 private key (if present).
    pub private_key_der: Option<Vec<u8>>,
    /// DER-encoded CA/chain certificates (leaf-first order, excluding the leaf).
    pub chain_ders: Vec<Vec<u8>>,
}

// ============================================================================
// Thin parser trait — the only seam that touches OpenSSL
// ============================================================================

/// Abstracts PKCS#12 parsing so the business logic can be unit tested.
///
/// The real implementation uses OpenSSL's `Pkcs12::from_der` + `parse2`.
/// Tests inject a mock that returns canned data.
pub trait Pkcs12Parser: Send + Sync {
    /// Parse PKCS#12 bytes with the given password.
    ///
    /// # Arguments
    /// * `bytes` — raw PFX file bytes
    /// * `password` — password (empty string for null-protected PFX)
    fn parse_pkcs12(
        &self,
        bytes: &[u8],
        password: &str,
    ) -> Result<ParsedPkcs12, CertLocalError>;
}

// ============================================================================
// Password resolution — never from CLI args
// ============================================================================

/// How the PFX password is provided.
#[derive(Debug, Clone)]
pub enum PfxPasswordSource {
    /// Read from an environment variable (default: `COSESIGNTOOL_PFX_PASSWORD`).
    EnvironmentVariable(String),
    /// The PFX is protected with an empty/null password.
    Empty,
}

impl Default for PfxPasswordSource {
    fn default() -> Self {
        Self::EnvironmentVariable(PFX_PASSWORD_ENV_VAR.to_string())
    }
}

/// Resolve the actual password string from the source.
///
/// # Security
///
/// Passwords are **never** accepted as direct string arguments from CLI.
/// The only paths are:
/// - Environment variable (process-scoped, not visible in `ps` output)
/// - Empty string (for null-protected PFX files)
pub fn resolve_password(source: &PfxPasswordSource) -> Result<String, CertLocalError> {
    match source {
        PfxPasswordSource::EnvironmentVariable(var_name) => {
            std::env::var(var_name).map_err(|_| {
                CertLocalError::LoadFailed(format!(
                    "PFX password environment variable '{}' is not set. \
                     Set it before running, or use PfxPasswordSource::Empty for unprotected PFX files.",
                    var_name
                ))
            })
        }
        PfxPasswordSource::Empty => Ok(String::new()),
    }
}

// ============================================================================
// Business logic — fully unit-testable via injected parser
// ============================================================================

/// Load a certificate from PFX bytes using an injected parser.
///
/// This is the **testable core**: resolves password, calls parser, maps result.
pub fn load_with_parser(
    parser: &dyn Pkcs12Parser,
    bytes: &[u8],
    password_source: &PfxPasswordSource,
) -> Result<Certificate, CertLocalError> {
    if bytes.is_empty() {
        return Err(CertLocalError::LoadFailed(
            "PFX data is empty".to_string(),
        ));
    }

    let password = resolve_password(password_source)?;
    let parsed = parser.parse_pkcs12(bytes, &password)?;

    // Validate: must have at least a certificate
    if parsed.cert_der.is_empty() {
        return Err(CertLocalError::LoadFailed(
            "PFX contained no certificate".to_string(),
        ));
    }

    let mut cert = match parsed.private_key_der {
        Some(key_der) if !key_der.is_empty() => {
            Certificate::with_private_key(parsed.cert_der, key_der)
        }
        _ => Certificate::new(parsed.cert_der),
    };

    if !parsed.chain_ders.is_empty() {
        cert = cert.with_chain(parsed.chain_ders);
    }

    Ok(cert)
}

/// Load a certificate from a PFX file path using an injected parser.
pub fn load_file_with_parser<P: AsRef<Path>>(
    parser: &dyn Pkcs12Parser,
    path: P,
    password_source: &PfxPasswordSource,
) -> Result<Certificate, CertLocalError> {
    let bytes =
        std::fs::read(path.as_ref()).map_err(|e| CertLocalError::IoError(e.to_string()))?;
    load_with_parser(parser, &bytes, password_source)
}

// ============================================================================
// Public convenience functions (use the real OpenSSL parser)
// ============================================================================

/// Loads a certificate and private key from a PFX file.
///
/// Password is read from the `COSESIGNTOOL_PFX_PASSWORD` environment variable.
/// For PFX files with no password, call [`load_from_pfx_no_password`] instead.
///
/// Requires the `pfx` feature.
#[cfg(feature = "pfx")]
pub fn load_from_pfx<P: AsRef<Path>>(path: P) -> Result<Certificate, CertLocalError> {
    let parser = openssl_impl::OpenSslPkcs12Parser;
    load_file_with_parser(&parser, path, &PfxPasswordSource::default())
}

/// Loads a certificate from PFX bytes with password from environment variable.
///
/// Requires the `pfx` feature.
#[cfg(feature = "pfx")]
pub fn load_from_pfx_bytes(bytes: &[u8]) -> Result<Certificate, CertLocalError> {
    let parser = openssl_impl::OpenSslPkcs12Parser;
    load_with_parser(&parser, bytes, &PfxPasswordSource::default())
}

/// Loads a certificate from a PFX file with a specific password env var name.
///
/// Requires the `pfx` feature.
#[cfg(feature = "pfx")]
pub fn load_from_pfx_with_env_var<P: AsRef<Path>>(
    path: P,
    env_var_name: &str,
) -> Result<Certificate, CertLocalError> {
    let parser = openssl_impl::OpenSslPkcs12Parser;
    let source = PfxPasswordSource::EnvironmentVariable(env_var_name.to_string());
    load_file_with_parser(&parser, path, &source)
}

/// Loads a certificate from a PFX file that has no password (null-protected).
///
/// Requires the `pfx` feature.
#[cfg(feature = "pfx")]
pub fn load_from_pfx_no_password<P: AsRef<Path>>(
    path: P,
) -> Result<Certificate, CertLocalError> {
    let parser = openssl_impl::OpenSslPkcs12Parser;
    load_file_with_parser(&parser, path, &PfxPasswordSource::Empty)
}

// ============================================================================
// Non-pfx stubs
// ============================================================================

#[cfg(not(feature = "pfx"))]
pub fn load_from_pfx<P: AsRef<Path>>(_path: P) -> Result<Certificate, CertLocalError> {
    Err(CertLocalError::LoadFailed(
        "PFX support not enabled (compile with feature=\"pfx\")".to_string(),
    ))
}

#[cfg(not(feature = "pfx"))]
pub fn load_from_pfx_bytes(_bytes: &[u8]) -> Result<Certificate, CertLocalError> {
    Err(CertLocalError::LoadFailed(
        "PFX support not enabled (compile with feature=\"pfx\")".to_string(),
    ))
}

#[cfg(not(feature = "pfx"))]
pub fn load_from_pfx_with_env_var<P: AsRef<Path>>(
    _path: P,
    _env_var_name: &str,
) -> Result<Certificate, CertLocalError> {
    Err(CertLocalError::LoadFailed(
        "PFX support not enabled (compile with feature=\"pfx\")".to_string(),
    ))
}

#[cfg(not(feature = "pfx"))]
pub fn load_from_pfx_no_password<P: AsRef<Path>>(
    _path: P,
) -> Result<Certificate, CertLocalError> {
    Err(CertLocalError::LoadFailed(
        "PFX support not enabled (compile with feature=\"pfx\")".to_string(),
    ))
}

// ============================================================================
// OpenSSL parser — thin layer (integration-test only)
// ============================================================================

#[cfg(feature = "pfx")]
pub mod openssl_impl {
    use super::*;
    use openssl::pkcs12::Pkcs12;

    /// Real PKCS#12 parser backed by OpenSSL.
    ///
    /// This is the **only** type that calls OpenSSL. Everything above it
    /// is pure Rust business logic testable with a mock `Pkcs12Parser`.
    pub struct OpenSslPkcs12Parser;

    impl Pkcs12Parser for OpenSslPkcs12Parser {
        fn parse_pkcs12(
            &self,
            bytes: &[u8],
            password: &str,
        ) -> Result<ParsedPkcs12, CertLocalError> {
            let pkcs12 = Pkcs12::from_der(bytes)
                .map_err(|e| CertLocalError::LoadFailed(format!("invalid PFX data: {}", e)))?;

            let parsed = pkcs12
                .parse2(password)
                .map_err(|e| CertLocalError::LoadFailed(format!("failed to parse PFX: {}", e)))?;

            let cert_der = parsed
                .cert
                .ok_or_else(|| {
                    CertLocalError::LoadFailed("no certificate found in PFX".to_string())
                })?
                .to_der()
                .map_err(|e| {
                    CertLocalError::LoadFailed(format!("failed to encode certificate: {}", e))
                })?;

            let key_der = parsed.pkey.and_then(|pkey| pkey.private_key_to_der().ok());

            let chain_ders = parsed
                .ca
                .map(|chain| {
                    chain
                        .into_iter()
                        .filter_map(|c| c.to_der().ok())
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default();

            Ok(ParsedPkcs12 {
                cert_der,
                private_key_der: key_der,
                chain_ders,
            })
        }
    }
}
