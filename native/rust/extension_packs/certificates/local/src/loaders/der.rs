// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! DER format certificate loading.

use crate::certificate::Certificate;
use crate::error::CertLocalError;
use std::path::Path;
use x509_parser::prelude::*;

/// Loads a certificate from a DER-encoded file.
///
/// # Arguments
///
/// * `path` - Path to the DER-encoded certificate file
///
/// # Errors
///
/// Returns `CertLocalError::IoError` if file cannot be read.
/// Returns `CertLocalError::LoadFailed` if DER parsing fails.
pub fn load_cert_from_der<P: AsRef<Path>>(path: P) -> Result<Certificate, CertLocalError> {
    let bytes = std::fs::read(path.as_ref()).map_err(|e| CertLocalError::IoError(e.to_string()))?;
    load_cert_from_der_bytes(&bytes)
}

/// Loads a certificate from DER-encoded bytes.
///
/// # Arguments
///
/// * `bytes` - DER-encoded certificate bytes
///
/// # Errors
///
/// Returns `CertLocalError::LoadFailed` if DER parsing fails.
pub fn load_cert_from_der_bytes(bytes: &[u8]) -> Result<Certificate, CertLocalError> {
    X509Certificate::from_der(bytes)
        .map_err(|e| CertLocalError::LoadFailed(format!("invalid DER certificate: {}", e)))?;

    Ok(Certificate::new(bytes.to_vec()))
}

/// Loads a certificate and private key from separate DER-encoded files.
///
/// The private key must be in PKCS#8 DER format.
///
/// # Arguments
///
/// * `cert_path` - Path to the DER-encoded certificate file
/// * `key_path` - Path to the DER-encoded private key file (PKCS#8)
///
/// # Errors
///
/// Returns `CertLocalError::IoError` if files cannot be read.
/// Returns `CertLocalError::LoadFailed` if DER parsing fails.
pub fn load_cert_and_key_from_der<P: AsRef<Path>>(
    cert_path: P,
    key_path: P,
) -> Result<Certificate, CertLocalError> {
    let cert_bytes =
        std::fs::read(cert_path.as_ref()).map_err(|e| CertLocalError::IoError(e.to_string()))?;
    let key_bytes =
        std::fs::read(key_path.as_ref()).map_err(|e| CertLocalError::IoError(e.to_string()))?;

    X509Certificate::from_der(&cert_bytes)
        .map_err(|e| CertLocalError::LoadFailed(format!("invalid DER certificate: {}", e)))?;

    Ok(Certificate::with_private_key(cert_bytes, key_bytes))
}
