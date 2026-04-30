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
    loaders::{pem, pfx},
    Certificate, CertificateFactory, CertificateOptions, EphemeralCertificateFactory,
    SoftwareKeyProvider,
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
        Self {
            cert,
            chain_builder,
        }
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
pub fn create_pem_service(cert_path: &str, key_path: &str) -> Result<CertificateSigningService> {
    let mut cert = pem::load_cert_from_pem(cert_path)
        .with_context(|| format!("Failed to load PEM certificate: {cert_path}"))?;

    // If the key is in a separate file, load and merge it
    if cert.private_key_der.is_none() {
        let key_pem = std::fs::read(key_path)
            .with_context(|| format!("Failed to read PEM key file: {key_path}"))?;
        let key_cert =
            pem::load_cert_from_pem_bytes(&key_pem).context("Failed to parse PEM private key")?;
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

#[cfg(test)]
mod tests {
    use super::{
        create_ephemeral_service, create_pem_service, create_pfx_service, CertificateFactory,
        CertificateOptions, EphemeralCertificateFactory, SoftwareKeyProvider,
    };
    use cose_sign1_signing::{SigningContext, SigningService};
    use std::time::{Duration, SystemTime, UNIX_EPOCH};
    use tempfile::NamedTempFile;

    #[test]
    fn create_ephemeral_service_returns_valid_signing_service() {
        let service = create_ephemeral_service("CN=Unit Test").expect("service should be created");
        assert!(!service.is_remote());

        let context = SigningContext::from_slice(b"payload");
        let signer = service
            .get_cose_signer(&context)
            .expect("service should produce a signer");
        let signature = signer
            .sign_payload(b"payload", None)
            .expect("signer should sign payloads");

        assert_ne!(signer.signer().algorithm(), 0);
        assert!(!signature.is_empty());
    }

    #[test]
    fn create_pfx_service_with_invalid_path_returns_error() {
        let path = unique_missing_path("pfx");
        let error = create_pfx_service(path.as_str(), None)
            .err()
            .expect("missing PFX should fail");

        assert!(error.to_string().contains("Failed to load PFX certificate"));
        assert!(error.to_string().contains(path.as_str()));
    }

    #[test]
    fn create_pem_service_with_invalid_certificate_path_returns_error() {
        let cert_path = unique_missing_path("pem");
        let key_path = unique_missing_path("key");
        let error = create_pem_service(cert_path.as_str(), key_path.as_str())
            .err()
            .expect("missing certificate should fail");

        assert!(error.to_string().contains("Failed to load PEM certificate"));
        assert!(error.to_string().contains(cert_path.as_str()));
    }

    #[test]
    fn create_pem_service_with_invalid_key_path_returns_error() {
        let cert_file = NamedTempFile::new().expect("temp certificate file should be created");
        let certificate = EphemeralCertificateFactory::new(Box::new(SoftwareKeyProvider::new()))
            .create_certificate(CertificateOptions::default().with_subject_name("CN=PEM Test"))
            .expect("ephemeral certificate should be created");
        let cert_pem = openssl::x509::X509::from_der(&certificate.cert_der)
            .expect("certificate DER should parse")
            .to_pem()
            .expect("certificate should convert to PEM");
        std::fs::write(cert_file.path(), cert_pem).expect("certificate PEM should be written");

        let key_path = unique_missing_path("key");
        let error = create_pem_service(
            cert_file.path().to_str().expect("path should be UTF-8"),
            key_path.as_str(),
        )
        .err()
        .expect("missing key should fail");

        assert!(error.to_string().contains("Failed to read PEM key file"));
        assert!(error.to_string().contains(key_path.as_str()));
    }

    fn unique_missing_path(extension: &str) -> String {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::from_secs(0))
            .as_nanos();
        std::env::current_dir()
            .expect("current directory should resolve")
            .join(format!(
                ".cosesigntool-local-provider-test-{}-{}.{}",
                std::process::id(),
                timestamp,
                extension
            ))
            .to_string_lossy()
            .into_owned()
    }
}
