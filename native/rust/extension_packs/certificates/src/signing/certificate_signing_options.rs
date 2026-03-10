// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Certificate signing options.

use cose_sign1_headers::CwtClaims;

/// Options for certificate-based signing.
///
/// Maps V2 `CertificateSigningOptions`.
pub struct CertificateSigningOptions {
    /// Enable SCITT compliance (adds CWT claims header with DID:X509 issuer).
    /// Default: true per V2.
    pub enable_scitt_compliance: bool,
    /// Custom CWT claims to merge with auto-generated claims.
    pub custom_cwt_claims: Option<CwtClaims>,
}

impl Default for CertificateSigningOptions {
    fn default() -> Self {
        Self {
            enable_scitt_compliance: true,
            custom_cwt_claims: None,
        }
    }
}

impl CertificateSigningOptions {
    /// Creates new default options.
    pub fn new() -> Self {
        Self::default()
    }
}
