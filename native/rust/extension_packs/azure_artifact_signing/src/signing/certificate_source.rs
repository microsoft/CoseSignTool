// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use crate::error::AasError;
use crate::options::AzureArtifactSigningOptions;
use azure_core::credentials::TokenCredential;
use azure_artifact_signing_client::{
    CertificateProfileClient, CertificateProfileClientOptions, SignStatus,
};
use std::sync::Arc;

pub struct AzureArtifactSigningCertificateSource {
    client: CertificateProfileClient,
}

impl AzureArtifactSigningCertificateSource {
    /// Create with DefaultAzureCredential (for local dev / managed identity).
    #[cfg_attr(coverage_nightly, coverage(off))]
    pub fn new(options: AzureArtifactSigningOptions) -> Result<Self, AasError> {
        let client_options = CertificateProfileClientOptions::new(
            &options.endpoint,
            &options.account_name,
            &options.certificate_profile_name,
        );
        let client = CertificateProfileClient::new_dev(client_options)
            .map_err(|e| AasError::CertificateFetchFailed(e.to_string()))?;
        Ok(Self { client })
    }

    /// Create with an explicit Azure credential.
    #[cfg_attr(coverage_nightly, coverage(off))]
    pub fn with_credential(
        options: AzureArtifactSigningOptions,
        credential: Arc<dyn TokenCredential>,
    ) -> Result<Self, AasError> {
        let client_options = CertificateProfileClientOptions::new(
            &options.endpoint,
            &options.account_name,
            &options.certificate_profile_name,
        );
        let client = CertificateProfileClient::new(client_options, credential, None)
            .map_err(|e| AasError::CertificateFetchFailed(e.to_string()))?;
        Ok(Self { client })
    }

    /// Fetch the certificate chain (PKCS#7 bytes).
    #[cfg_attr(coverage_nightly, coverage(off))]
    pub fn fetch_certificate_chain_pkcs7(&self) -> Result<Vec<u8>, AasError> {
        self.client
            .get_certificate_chain()
            .map_err(|e| AasError::CertificateFetchFailed(e.to_string()))
    }

    /// Fetch the root certificate (DER bytes).
    #[cfg_attr(coverage_nightly, coverage(off))]
    pub fn fetch_root_certificate(&self) -> Result<Vec<u8>, AasError> {
        self.client
            .get_root_certificate()
            .map_err(|e| AasError::CertificateFetchFailed(e.to_string()))
    }

    /// Fetch the EKU OIDs for this certificate profile.
    #[cfg_attr(coverage_nightly, coverage(off))]
    pub fn fetch_eku(&self) -> Result<Vec<String>, AasError> {
        self.client
            .get_eku()
            .map_err(|e| AasError::CertificateFetchFailed(e.to_string()))
    }

    /// Sign a digest using the AAS HSM (sync — blocks on the Poller internally).
    ///
    /// Returns `(signature_bytes, signing_cert_der)`.
    #[cfg_attr(coverage_nightly, coverage(off))]
    pub fn sign_digest(
        &self,
        algorithm: &str,
        digest: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>), AasError> {
        let status = self.client
            .sign(algorithm, digest)
            .map_err(|e| AasError::SigningFailed(e.to_string()))?;
        Self::decode_sign_status(status)
    }

    /// Start a sign operation and return the `Poller<SignStatus>` for async callers.
    ///
    /// Callers can `await` the poller or stream intermediate status updates.
    #[cfg_attr(coverage_nightly, coverage(off))]
    pub fn start_sign(
        &self,
        algorithm: &str,
        digest: &[u8],
    ) -> Result<azure_core::http::poller::Poller<SignStatus>, AasError> {
        self.client
            .start_sign(algorithm, digest, None)
            .map_err(|e| AasError::SigningFailed(e.to_string()))
    }

    /// Decode base64 fields from a completed SignStatus.
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn decode_sign_status(status: SignStatus) -> Result<(Vec<u8>, Vec<u8>), AasError> {
        let sig_b64 = status.signature
            .ok_or_else(|| AasError::SigningFailed("No signature in response".into()))?;
        let cert_b64 = status.signing_certificate
            .ok_or_else(|| AasError::SigningFailed("No signing certificate in response".into()))?;

        use base64::Engine;
        let signature = base64::engine::general_purpose::STANDARD.decode(&sig_b64)
            .map_err(|e| AasError::SigningFailed(format!("Invalid base64 signature: {}", e)))?;
        let cert_der = base64::engine::general_purpose::STANDARD.decode(&cert_b64)
            .map_err(|e| AasError::SigningFailed(format!("Invalid base64 certificate: {}", e)))?;

        Ok((signature, cert_der))
    }

    /// Access the underlying client (for advanced callers who want direct Poller access).
    #[cfg_attr(coverage_nightly, coverage(off))]
    pub fn client(&self) -> &CertificateProfileClient {
        &self.client
    }
}