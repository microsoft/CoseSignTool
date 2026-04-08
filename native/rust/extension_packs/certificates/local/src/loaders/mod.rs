// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Certificate loading from various formats.
//!
//! This module provides functions for loading X.509 certificates and private keys
//! from common storage formats:
//!
//! - **DER** - Binary X.509 certificate format
//! - **PEM** - Base64-encoded X.509 with BEGIN/END markers
//! - **PFX** - PKCS#12 archives (password-protected, feature-gated)
//! - **Windows Store** - Windows certificate store (platform-specific, feature-gated)
//!
//! ## Format Support
//!
//! | Format | Function | Feature Flag | Platform |
//! |--------|----------|--------------|----------|
//! | DER | `der::load_cert_from_der()` | Always available | All |
//! | PEM | `pem::load_cert_from_pem()` | Always available | All |
//! | PFX | `pfx::load_from_pfx()` | `pfx` | All |
//! | Windows Store | `windows_store::load_from_store_by_thumbprint()` | `windows-store` | Windows only |
//!
//! ## Example
//!
//! ```ignore
//! use cose_sign1_certificates_local::loaders;
//!
//! // Load from PEM file
//! let cert = loaders::pem::load_cert_from_pem("cert.pem")?;
//!
//! // Load from DER with separate key
//! let cert = loaders::der::load_cert_and_key_from_der("cert.der", "key.der")?;
//!
//! // Load from PFX (requires pfx feature + COSESIGNTOOL_PFX_PASSWORD env var)
//! #[cfg(feature = "pfx")]
//! let cert = loaders::pfx::load_from_pfx("cert.pfx")?;
//!
//! // Load from PFX with no password
//! #[cfg(feature = "pfx")]
//! let cert = loaders::pfx::load_from_pfx_no_password("cert.pfx")?;
//! ```

pub mod der;
pub mod pem;
pub mod pfx;
pub mod windows_store;

use crate::Certificate;

/// A loaded certificate with metadata about its source.
///
/// This is a convenience wrapper around `Certificate` that tracks
/// how the certificate was loaded.
#[derive(Clone, Debug)]
pub struct LoadedCertificate {
    /// The loaded certificate
    pub certificate: Certificate,
    /// Source format identifier
    pub source_format: CertificateFormat,
}

/// Certificate source format.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CertificateFormat {
    /// DER-encoded certificate
    Der,
    /// PEM-encoded certificate
    Pem,
    /// PFX/PKCS#12 archive
    Pfx,
    /// Windows certificate store
    WindowsStore,
}

impl LoadedCertificate {
    /// Creates a new loaded certificate.
    pub fn new(certificate: Certificate, source_format: CertificateFormat) -> Self {
        Self {
            certificate,
            source_format,
        }
    }
}
