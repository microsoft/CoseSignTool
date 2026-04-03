// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Certificate chain builder — maps V2 ICertificateChainBuilder.

use std::sync::Arc;

use crate::error::CertificateError;

/// Builds certificate chains from a signing certificate.
/// Maps V2 `ICertificateChainBuilder`.
pub trait CertificateChainBuilder: Send + Sync {
    /// Build a certificate chain from the given DER-encoded signing certificate.
    /// Returns a vector of DER-encoded certificates ordered leaf-first.
    fn build_chain(&self, certificate_der: &[u8]) -> Result<Vec<Vec<u8>>, CertificateError>;
}

/// Chain builder that uses an explicit pre-built chain.
/// Maps V2 `ExplicitCertificateChainBuilder`.
///
/// The chain is stored behind `Arc` so that `build_chain()` clones the
/// `Arc` pointer (ref-count bump) rather than deep-copying every certificate.
pub struct ExplicitCertificateChainBuilder {
    certificates: Arc<Vec<Vec<u8>>>,
}

impl ExplicitCertificateChainBuilder {
    /// Create from a list of DER-encoded certificates (leaf-first order).
    pub fn new(certificates: Vec<Vec<u8>>) -> Self {
        Self {
            certificates: Arc::new(certificates),
        }
    }
}

impl CertificateChainBuilder for ExplicitCertificateChainBuilder {
    fn build_chain(&self, _certificate_der: &[u8]) -> Result<Vec<Vec<u8>>, CertificateError> {
        // Clone the inner Vec via Arc — if the caller only needs a read,
        // Arc::unwrap_or_clone avoids copying when refcount == 1.
        Ok(Arc::unwrap_or_clone(self.certificates.clone()))
    }
}
