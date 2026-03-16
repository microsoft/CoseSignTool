// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Certificate chain builder — maps V2 ICertificateChainBuilder.

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
pub struct ExplicitCertificateChainBuilder {
    pub(crate) certificates: Vec<Vec<u8>>,
}

impl ExplicitCertificateChainBuilder {
    /// Create from a list of DER-encoded certificates (leaf-first order).
    pub fn new(certificates: Vec<Vec<u8>>) -> Self {
        Self { certificates }
    }
}

impl CertificateChainBuilder for ExplicitCertificateChainBuilder {
    fn build_chain(&self, _certificate_der: &[u8]) -> Result<Vec<Vec<u8>>, CertificateError> {
        Ok(self.certificates.clone())
    }
}


