// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Azure Key Vault certificate source for remote certificate-based signing.
//! Maps V2 AzureKeyVaultCertificateSource.

use cose_sign1_certificates::signing::source::CertificateSource;
use cose_sign1_certificates::signing::remote::RemoteCertificateSource;
use cose_sign1_certificates::chain_builder::{CertificateChainBuilder, ExplicitCertificateChainBuilder};
use cose_sign1_certificates::error::CertificateError;
use crate::common::{crypto_client::KeyVaultCryptoClient, error::AkvError};

/// Remote certificate source backed by Azure Key Vault.
/// Fetches certificate + chain from AKV, delegates signing to AKV REST API.
pub struct AzureKeyVaultCertificateSource {
    crypto_client: Box<dyn KeyVaultCryptoClient>,
    certificate_der: Vec<u8>,
    chain: Vec<Vec<u8>>,
    chain_builder: ExplicitCertificateChainBuilder,
    initialized: bool,
}

impl AzureKeyVaultCertificateSource {
    /// Create a new AKV certificate source.
    /// Call `initialize()` or `fetch_certificate()` before use to fetch the certificate.
    pub fn new(crypto_client: Box<dyn KeyVaultCryptoClient>) -> Self {
        Self {
            crypto_client,
            certificate_der: Vec::new(),
            chain: Vec::new(),
            chain_builder: ExplicitCertificateChainBuilder::new(Vec::new()),
            initialized: false,
        }
    }

    /// Fetch the signing certificate and its chain from AKV.
    ///
    /// Returns `(leaf_cert_der, chain_ders)` where chain_ders is ordered leaf-first.
    pub fn fetch_certificate(&self) -> Result<(Vec<u8>, Vec<Vec<u8>>), AkvError> {
        // TODO: Use AKV Certificates REST API to fetch the certificate
        // GET https://{vault-url}/certificates/{name}/{version}?api-version=7.4
        // The response includes the CER (public cert) and optionally the full chain.
        Err(AkvError::CertificateSourceError(
            format!("AKV certificate fetch pending: {}", self.crypto_client.name())
        ))
    }

    /// Initialize by fetching certificate and chain from AKV.
    /// Must be called before using as CertificateSource.
    pub fn initialize(
        &mut self,
        certificate_der: Vec<u8>,
        chain: Vec<Vec<u8>>,
    ) -> Result<(), CertificateError> {
        // In a real impl, this would fetch from AKV.
        // For now, accept pre-fetched data (enables mock testing).
        self.certificate_der = certificate_der.clone();
        self.chain = chain.clone();
        let mut full_chain = vec![certificate_der];
        full_chain.extend(chain);
        self.chain_builder = ExplicitCertificateChainBuilder::new(full_chain);
        self.initialized = true;
        Ok(())
    }
}

impl CertificateSource for AzureKeyVaultCertificateSource {
    fn get_signing_certificate(&self) -> Result<&[u8], CertificateError> {
        if !self.initialized {
            return Err(CertificateError::InvalidCertificate("Not initialized".into()));
        }
        Ok(&self.certificate_der)
    }

    fn has_private_key(&self) -> bool {
        true // Remote services always have access to private key operations
    }

    fn get_chain_builder(&self) -> &dyn CertificateChainBuilder {
        &self.chain_builder
    }
}

impl RemoteCertificateSource for AzureKeyVaultCertificateSource {
    fn sign_data_rsa(&self, data: &[u8], hash_algorithm: &str) -> Result<Vec<u8>, CertificateError> {
        let akv_alg = match hash_algorithm {
            "SHA-256" => "RS256",
            "SHA-384" => "RS384",
            "SHA-512" => "RS512",
            _ => return Err(CertificateError::SigningError(format!("Unknown hash: {}", hash_algorithm))),
        };
        self.crypto_client.sign(akv_alg, data)
            .map_err(|e| CertificateError::SigningError(e.to_string()))
    }

    fn sign_data_ecdsa(&self, data: &[u8], hash_algorithm: &str) -> Result<Vec<u8>, CertificateError> {
        let akv_alg = match hash_algorithm {
            "SHA-256" => "ES256",
            "SHA-384" => "ES384",
            "SHA-512" => "ES512",
            _ => return Err(CertificateError::SigningError(format!("Unknown hash: {}", hash_algorithm))),
        };
        self.crypto_client.sign(akv_alg, data)
            .map_err(|e| CertificateError::SigningError(e.to_string()))
    }
}
