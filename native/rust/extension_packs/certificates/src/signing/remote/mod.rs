// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Remote certificate source abstraction for cloud-based signing services.

use crate::error::CertificateError;
use crate::signing::source::CertificateSource;

/// Extension trait for certificate sources backed by remote signing services.
///
/// Remote sources delegate private key operations to a cloud service (e.g.,
/// Azure Key Vault, AWS KMS) while providing local access to the public
/// certificate and chain.
pub trait RemoteCertificateSource: CertificateSource {
    /// Signs data using RSA with the specified hash algorithm.
    ///
    /// # Arguments
    ///
    /// * `data` - The pre-computed hash digest to sign
    /// * `hash_algorithm` - Hash algorithm name (e.g., "SHA-256", "SHA-384", "SHA-512")
    ///
    /// # Returns
    ///
    /// The signature bytes on success.
    fn sign_data_rsa(&self, data: &[u8], hash_algorithm: &str) -> Result<Vec<u8>, CertificateError>;

    /// Signs data using ECDSA with the specified hash algorithm.
    ///
    /// # Arguments
    ///
    /// * `data` - The pre-computed hash digest to sign
    /// * `hash_algorithm` - Hash algorithm name (e.g., "SHA-256", "SHA-384", "SHA-512")
    ///
    /// # Returns
    ///
    /// The signature bytes on success.
    fn sign_data_ecdsa(&self, data: &[u8], hash_algorithm: &str) -> Result<Vec<u8>, CertificateError>;
}
