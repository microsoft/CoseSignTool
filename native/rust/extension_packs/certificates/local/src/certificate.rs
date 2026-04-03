// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Certificate type with DER storage.

use crate::error::CertLocalError;
use x509_parser::prelude::*;

/// A certificate with optional private key and chain.
#[derive(Clone)]
pub struct Certificate {
    /// DER-encoded certificate.
    pub cert_der: Vec<u8>,
    /// Optional DER-encoded private key (PKCS#8).
    pub private_key_der: Option<Vec<u8>>,
    /// Chain of DER-encoded certificates (excluding this certificate).
    pub chain: Vec<Vec<u8>>,
}

impl Certificate {
    /// Creates a new certificate from DER-encoded bytes.
    pub fn new(cert_der: Vec<u8>) -> Self {
        Self {
            cert_der,
            private_key_der: None,
            chain: Vec::new(),
        }
    }

    /// Creates a certificate with a private key.
    pub fn with_private_key(cert_der: Vec<u8>, private_key_der: Vec<u8>) -> Self {
        Self {
            cert_der,
            private_key_der: Some(private_key_der),
            chain: Vec::new(),
        }
    }

    /// Returns the subject name of the certificate.
    ///
    /// # Errors
    ///
    /// Returns `CertLocalError::LoadFailed` if parsing fails.
    pub fn subject(&self) -> Result<String, CertLocalError> {
        let (_, cert) = X509Certificate::from_der(&self.cert_der)
            .map_err(|e| CertLocalError::LoadFailed(format!("failed to parse cert: {}", e)))?;
        Ok(cert.subject().to_string())
    }

    /// Returns the SHA-256 thumbprint of the certificate.
    pub fn thumbprint_sha256(&self) -> [u8; 32] {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(&self.cert_der);
        hasher.finalize().into()
    }

    /// Returns true if this certificate has a private key.
    pub fn has_private_key(&self) -> bool {
        self.private_key_der.is_some()
    }

    /// Sets the certificate chain.
    pub fn with_chain(mut self, chain: Vec<Vec<u8>>) -> Self {
        self.chain = chain;
        self
    }
}

impl std::fmt::Debug for Certificate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Certificate")
            .field("cert_der_len", &self.cert_der.len())
            .field("has_private_key", &self.has_private_key())
            .field("chain_len", &self.chain.len())
            .finish()
    }
}
