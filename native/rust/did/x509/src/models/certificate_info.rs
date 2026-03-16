// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use crate::models::{SubjectAlternativeName, X509Name};

/// Information extracted from an X.509 certificate
#[derive(Debug, Clone, PartialEq)]
pub struct CertificateInfo {
    /// The subject Distinguished Name
    pub subject: X509Name,
    
    /// The issuer Distinguished Name
    pub issuer: X509Name,
    
    /// The certificate fingerprint (SHA-256 hash)
    pub fingerprint: Vec<u8>,
    
    /// The certificate fingerprint as hex string
    pub fingerprint_hex: String,
    
    /// Subject Alternative Names
    pub subject_alternative_names: Vec<SubjectAlternativeName>,
    
    /// Extended Key Usage OIDs
    pub extended_key_usage: Vec<String>,
    
    /// Whether this is a CA certificate
    pub is_ca: bool,
    
    /// Fulcio issuer value, if present
    pub fulcio_issuer: Option<String>,
}

impl CertificateInfo {
    /// Create a new certificate info
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        subject: X509Name,
        issuer: X509Name,
        fingerprint: Vec<u8>,
        fingerprint_hex: String,
        subject_alternative_names: Vec<SubjectAlternativeName>,
        extended_key_usage: Vec<String>,
        is_ca: bool,
        fulcio_issuer: Option<String>,
    ) -> Self {
        Self {
            subject,
            issuer,
            fingerprint,
            fingerprint_hex,
            subject_alternative_names,
            extended_key_usage,
            is_ca,
            fulcio_issuer,
        }
    }
}
