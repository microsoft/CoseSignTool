// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Azure Key Vault certificate source for remote certificate-based signing.
//! Maps V2 AzureKeyVaultCertificateSource.

use crate::common::{crypto_client::KeyVaultCryptoClient, error::AkvError};
use cose_sign1_certificates::chain_builder::{
    CertificateChainBuilder, ExplicitCertificateChainBuilder,
};
use cose_sign1_certificates::error::CertificateError;
use cose_sign1_certificates::signing::remote::RemoteCertificateSource;
use cose_sign1_certificates::signing::source::CertificateSource;

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
    /// Call `initialize()` before use to provide the certificate data.
    pub fn new(crypto_client: Box<dyn KeyVaultCryptoClient>) -> Self {
        Self {
            crypto_client,
            certificate_der: Vec::new(),
            chain: Vec::new(),
            chain_builder: ExplicitCertificateChainBuilder::new(Vec::new()),
            initialized: false,
        }
    }

    /// Fetch the signing certificate from AKV.
    ///
    /// Uses the Azure Key Vault Certificates SDK to retrieve the certificate
    /// associated with the key. Constructs the certificate name from the key
    /// URL pattern: `https://{vault}/keys/{name}/{version}`.
    ///
    /// Returns `(leaf_cert_der, chain_ders)` where chain_ders is ordered leaf-first.
    /// Currently returns the leaf certificate only — full chain extraction
    /// requires parsing the PKCS#12 bundle from the certificate's secret.
    #[cfg_attr(coverage_nightly, coverage(off))]
    pub fn fetch_certificate(
        &self,
        vault_url: &str,
        cert_name: &str,
        credential: std::sync::Arc<dyn azure_core::credentials::TokenCredential>,
    ) -> Result<(Vec<u8>, Vec<Vec<u8>>), AkvError> {
        use azure_security_keyvault_certificates::CertificateClient;

        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|e| AkvError::General(e.to_string()))?;

        let client = CertificateClient::new(vault_url, credential, None)
            .map_err(|e| AkvError::CertificateSourceError(e.to_string()))?;

        let response = runtime
            .block_on(client.get_certificate(cert_name, None))
            .map_err(|e| {
                AkvError::CertificateSourceError(format!(
                    "failed to get certificate '{}': {}",
                    cert_name, e
                ))
            })?;

        let certificate = response.into_model().map_err(|e| {
            AkvError::CertificateSourceError(format!(
                "failed to deserialize certificate '{}': {}",
                cert_name, e
            ))
        })?;

        // The `cer` field contains the DER-encoded X.509 certificate
        let cert_der: Vec<u8> = certificate.cer.ok_or_else(|| {
            AkvError::CertificateSourceError(
                "certificate response missing 'cer' (DER) field".into(),
            )
        })?;

        // Return leaf cert with empty chain — full chain extraction from
        // PKCS#12 secret would require an additional get_secret() call.
        // Callers should use initialize() with the full chain when available.
        Ok((cert_der, Vec::new()))
    }

    /// Initialize with pre-fetched certificate and chain data.
    ///
    /// Use either `fetch_certificate()` to retrieve from AKV, or call this
    /// method directly with certificate data obtained through another source.
    pub fn initialize(
        &mut self,
        certificate_der: Vec<u8>,
        chain: Vec<Vec<u8>>,
    ) -> Result<(), CertificateError> {
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
            return Err(CertificateError::InvalidCertificate(
                "Not initialized".into(),
            ));
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
    fn sign_data_rsa(
        &self,
        data: &[u8],
        hash_algorithm: &str,
    ) -> Result<Vec<u8>, CertificateError> {
        let akv_alg = match hash_algorithm {
            "SHA-256" => "RS256",
            "SHA-384" => "RS384",
            "SHA-512" => "RS512",
            _ => {
                return Err(CertificateError::SigningError(format!(
                    "Unknown hash: {}",
                    hash_algorithm
                )))
            }
        };
        self.crypto_client
            .sign(akv_alg, data)
            .map_err(|e| CertificateError::SigningError(e.to_string()))
    }

    fn sign_data_ecdsa(
        &self,
        data: &[u8],
        hash_algorithm: &str,
    ) -> Result<Vec<u8>, CertificateError> {
        let akv_alg = match hash_algorithm {
            "SHA-256" => "ES256",
            "SHA-384" => "ES384",
            "SHA-512" => "ES512",
            _ => {
                return Err(CertificateError::SigningError(format!(
                    "Unknown hash: {}",
                    hash_algorithm
                )))
            }
        };
        self.crypto_client
            .sign(akv_alg, data)
            .map_err(|e| CertificateError::SigningError(e.to_string()))
    }
}
