// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Local certificate signing providers: PFX, PEM, ephemeral.
//!
//! Bridges the `cose_sign1_certificates_local` loaders to `CertificateSigningService`
//! by implementing `CertificateSource` and `SigningKeyProvider` adapters.

use anyhow::{Context, Result};
use cose_sign1_certificates::chain_builder::ExplicitCertificateChainBuilder;
use cose_sign1_certificates::error::CertificateError;
use cose_sign1_certificates::signing::certificate_signing_options::CertificateSigningOptions;
use cose_sign1_certificates::signing::certificate_signing_service::CertificateSigningService;
use cose_sign1_certificates::signing::signing_key_provider::SigningKeyProvider;
use cose_sign1_certificates::signing::source::CertificateSource;
use cose_sign1_certificates_local::{
    Certificate, CertificateFactory, CertificateOptions, EphemeralCertificateFactory,
    SoftwareKeyProvider,
    loaders::{pfx, pem},
};
use cose_sign1_crypto_openssl::OpenSslCryptoProvider;
use crypto_primitives::{CryptoError, CryptoProvider, CryptoSigner, SigningContext};

// ============================================================================
// CertificateSource adapter for local Certificate
// ============================================================================

/// Adapts a local `Certificate` to the `CertificateSource` trait.
struct LocalCertificateSource {
    cert: Certificate,
    chain_builder: ExplicitCertificateChainBuilder,
}

impl LocalCertificateSource {
    fn new(cert: Certificate) -> Self {
        // Build chain: leaf DER first, then chain DERs
        let mut chain_ders = vec![cert.cert_der.clone()];
        chain_ders.extend(cert.chain.iter().cloned());
        let chain_builder = ExplicitCertificateChainBuilder::new(chain_ders);
        Self { cert, chain_builder }
    }
}

impl CertificateSource for LocalCertificateSource {
    fn get_signing_certificate(&self) -> std::result::Result<&[u8], CertificateError> {
        Ok(&self.cert.cert_der)
    }

    fn has_private_key(&self) -> bool {
        self.cert.has_private_key()
    }

    fn get_chain_builder(
        &self,
    ) -> &dyn cose_sign1_certificates::chain_builder::CertificateChainBuilder {
        &self.chain_builder
    }
}

// ============================================================================
// SigningKeyProvider adapter for local private keys
// ============================================================================

/// Adapts a local private key (via OpenSSL EvpSigner) to `SigningKeyProvider`.
struct LocalSigningKeyProvider {
    signer: Box<dyn CryptoSigner>,
}

impl CryptoSigner for LocalSigningKeyProvider {
    fn sign(&self, data: &[u8]) -> std::result::Result<Vec<u8>, CryptoError> {
        self.signer.sign(data)
    }

    fn algorithm(&self) -> i64 {
        self.signer.algorithm()
    }

    fn key_id(&self) -> Option<&[u8]> {
        self.signer.key_id()
    }

    fn key_type(&self) -> &str {
        self.signer.key_type()
    }

    fn supports_streaming(&self) -> bool {
        self.signer.supports_streaming()
    }

    fn sign_init(&self) -> std::result::Result<Box<dyn SigningContext>, CryptoError> {
        self.signer.sign_init()
    }
}

impl SigningKeyProvider for LocalSigningKeyProvider {
    fn is_remote(&self) -> bool {
        false
    }
}

// ============================================================================
// Provider factory functions
// ============================================================================

/// Create a `CertificateSigningService` from a PFX file.
pub fn create_pfx_service(
    pfx_path: &str,
    password: Option<&str>,
) -> Result<CertificateSigningService> {
    let cert = match password {
        Some("") => pfx::load_from_pfx_no_password(pfx_path),
        Some(pw) => {
            let env_var_name = "COSESIGNTOOL_CLI_PFX_PASSWORD";
            std::env::set_var(env_var_name, pw);
            let result = pfx::load_from_pfx_with_env_var(pfx_path, env_var_name);
            std::env::remove_var(env_var_name);
            result
        }
        None => pfx::load_from_pfx(pfx_path),
    }
    .with_context(|| format!("Failed to load PFX certificate: {pfx_path}"))?;

    build_service_from_cert(cert)
}

/// Create a `CertificateSigningService` from PEM files.
pub fn create_pem_service(
    cert_path: &str,
    key_path: &str,
) -> Result<CertificateSigningService> {
    let mut cert = pem::load_cert_from_pem(cert_path)
        .with_context(|| format!("Failed to load PEM certificate: {cert_path}"))?;

    // If the key is in a separate file, load and merge it
    if cert.private_key_der.is_none() {
        let key_pem = std::fs::read(key_path)
            .with_context(|| format!("Failed to read PEM key file: {key_path}"))?;
        let key_cert = pem::load_cert_from_pem_bytes(&key_pem)
            .context("Failed to parse PEM private key")?;
        cert.private_key_der = key_cert.private_key_der;
    }

    build_service_from_cert(cert)
}

/// Create a `CertificateSigningService` with an ephemeral (in-memory) certificate.
pub fn create_ephemeral_service(subject: &str) -> Result<CertificateSigningService> {
    let key_provider = Box::new(SoftwareKeyProvider::new());
    let factory = EphemeralCertificateFactory::new(key_provider);

    let options = CertificateOptions::default().with_subject_name(subject);
    let cert = factory
        .create_certificate(options)
        .map_err(|e| anyhow::anyhow!("Failed to create ephemeral certificate: {e}"))?;

    build_service_from_cert(cert)
}

/// Build a CertificateSigningService from a loaded Certificate.
fn build_service_from_cert(cert: Certificate) -> Result<CertificateSigningService> {
    let key_der = cert
        .private_key_der
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("Certificate does not contain a private key"))?;

    let crypto_provider = OpenSslCryptoProvider;
    let signer = crypto_provider
        .signer_from_der(key_der)
        .map_err(|e| anyhow::anyhow!("Failed to create signer from private key: {e}"))?;

    let signing_key: std::sync::Arc<dyn SigningKeyProvider> =
        std::sync::Arc::new(LocalSigningKeyProvider { signer });

    let cert_source: Box<dyn CertificateSource> = Box::new(LocalCertificateSource::new(cert));

    let options = CertificateSigningOptions {
        enable_scitt_compliance: true,
        ..Default::default()
    };

    Ok(CertificateSigningService::new(
        cert_source,
        signing_key,
        options,
    ))
}
