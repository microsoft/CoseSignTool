// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! X.509 certificate COSE key factory.
//!
//! Maps V2 `X509CertificateCoseKeyFactory` - provides factory functions to create
//! CryptoVerifier implementations from X.509 certificates for verification.

use crate::error::CertificateError;
use cose_sign1_crypto_openssl::OpenSslCryptoProvider;
use crypto_primitives::{CryptoProvider, CryptoVerifier};

/// Factory functions for creating COSE keys from X.509 certificates.
///
/// Maps V2 `X509CertificateCoseKeyFactory`.
pub struct X509CertificateCoseKeyFactory;

impl X509CertificateCoseKeyFactory {
    /// Creates a CryptoVerifier from a certificate's public key for verification.
    ///
    /// Supports RSA, ECDSA (P-256, P-384, P-521), EdDSA, and optionally ML-DSA (via OpenSSL).
    ///
    /// # Arguments
    ///
    /// * `cert_der` - DER-encoded X.509 certificate bytes
    ///
    /// # Returns
    ///
    /// A CryptoVerifier implementation suitable for verification operations.
    pub fn create_from_public_key(
        cert_der: &[u8],
    ) -> Result<Box<dyn CryptoVerifier>, CertificateError> {
        // Parse certificate using OpenSSL to extract public key
        let cert = openssl::x509::X509::from_der(cert_der).map_err(|e| {
            CertificateError::InvalidCertificate(format!("Failed to parse certificate: {}", e))
        })?;

        let public_pkey = cert.public_key().map_err(|e| {
            CertificateError::InvalidCertificate(format!("Failed to extract public key: {}", e))
        })?;

        // Convert to DER format for the crypto provider
        let public_key_der = public_pkey.public_key_to_der().map_err(|e| {
            CertificateError::InvalidCertificate(format!(
                "Failed to convert public key to DER: {}",
                e
            ))
        })?;

        // Create verifier using OpenSslCryptoProvider
        let provider = OpenSslCryptoProvider;
        let verifier = provider.verifier_from_der(&public_key_der).map_err(|e| {
            CertificateError::InvalidCertificate(format!("Failed to create verifier: {}", e))
        })?;

        Ok(verifier)
    }

    /// Gets the recommended hash algorithm for the given key size.
    ///
    /// Maps V2's `GetHashAlgorithmForKeySize()` logic:
    /// - 4096+ bits → SHA-512
    /// - 3072+ bits or ECDSA P-521 → SHA-384
    /// - Otherwise → SHA-256
    pub fn get_hash_algorithm_for_key_size(
        key_size_bits: usize,
        is_ec_p521: bool,
    ) -> HashAlgorithm {
        if key_size_bits >= 4096 {
            HashAlgorithm::Sha512
        } else if key_size_bits >= 3072 || is_ec_p521 {
            HashAlgorithm::Sha384
        } else {
            HashAlgorithm::Sha256
        }
    }
}

/// Hash algorithm selection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HashAlgorithm {
    Sha256,
    Sha384,
    Sha512,
}

impl HashAlgorithm {
    /// Returns the COSE algorithm identifier for this hash algorithm.
    pub fn cose_algorithm_id(&self) -> i64 {
        match self {
            Self::Sha256 => -16,
            Self::Sha384 => -43,
            Self::Sha512 => -44,
        }
    }
}
