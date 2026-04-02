// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Traits for key generation and certificate creation.

use crate::certificate::Certificate;
use crate::error::CertLocalError;
use crate::key_algorithm::KeyAlgorithm;
use crate::options::CertificateOptions;

/// A generated cryptographic key with public and private key material.
#[derive(Debug, Clone)]
pub struct GeneratedKey {
    /// DER-encoded private key (PKCS#8 format).
    pub private_key_der: Vec<u8>,
    /// DER-encoded public key (SubjectPublicKeyInfo format).
    pub public_key_der: Vec<u8>,
    /// The algorithm used to generate this key.
    pub algorithm: KeyAlgorithm,
    /// The key size in bits.
    pub key_size: u32,
}

/// Provides cryptographic key generation functionality.
///
/// Implementations can customize key storage (TPM, HSM, software memory).
pub trait PrivateKeyProvider: Send + Sync {
    /// Returns a human-readable name for this key provider.
    fn name(&self) -> &str;

    /// Returns true if the provider supports the specified algorithm.
    fn supports_algorithm(&self, algorithm: KeyAlgorithm) -> bool;

    /// Generates a new key with the specified algorithm and optional key size.
    ///
    /// If key_size is None, uses the algorithm's default size.
    ///
    /// # Errors
    ///
    /// Returns `CertLocalError::KeyGenerationFailed` if key generation fails.
    /// Returns `CertLocalError::UnsupportedAlgorithm` if the algorithm is not supported.
    fn generate_key(
        &self,
        algorithm: KeyAlgorithm,
        key_size: Option<u32>,
    ) -> Result<GeneratedKey, CertLocalError>;
}

/// Factory interface for creating X.509 certificates.
pub trait CertificateFactory: Send + Sync {
    /// Returns the private key provider used by this factory.
    fn key_provider(&self) -> &dyn PrivateKeyProvider;

    /// Creates a certificate with the specified options.
    ///
    /// # Errors
    ///
    /// Returns `CertLocalError::CertificateCreationFailed` if certificate creation fails.
    /// Returns `CertLocalError::InvalidOptions` if options are invalid.
    fn create_certificate(
        &self,
        options: CertificateOptions,
    ) -> Result<Certificate, CertLocalError>;

    /// Creates a certificate with default options.
    ///
    /// # Errors
    ///
    /// Returns `CertLocalError::CertificateCreationFailed` if certificate creation fails.
    fn create_certificate_default(&self) -> Result<Certificate, CertLocalError> {
        self.create_certificate(CertificateOptions::default())
    }
}
