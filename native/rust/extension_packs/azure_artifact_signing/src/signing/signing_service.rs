// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Azure Artifact Signing service implementation.
//!
//! Composes over `CertificateSigningService` from the certificates pack,
//! inheriting all standard certificate header contribution (x5chain, x5t,
//! SCITT CWT claims) — just like the V2 C# `AzureArtifactSigningService`
//! inherits from `CertificateSigningService`.

use crate::options::AzureArtifactSigningOptions;
use crate::signing::aas_crypto_signer::AasCryptoSigner;
use crate::signing::certificate_source::AzureArtifactSigningCertificateSource;
use crate::signing::did_x509_helper::build_did_x509_from_ats_chain;
use azure_core::credentials::TokenCredential;
use cose_sign1_certificates::chain_builder::ExplicitCertificateChainBuilder;
use cose_sign1_certificates::error::CertificateError;
use cose_sign1_certificates::signing::certificate_signing_options::CertificateSigningOptions;
use cose_sign1_certificates::signing::certificate_signing_service::CertificateSigningService;
use cose_sign1_certificates::signing::signing_key_provider::SigningKeyProvider;
use cose_sign1_certificates::signing::source::CertificateSource;
use cose_sign1_headers::CwtClaims;
use cose_sign1_signing::{
    CoseSigner, SigningContext, SigningError, SigningService, SigningServiceMetadata,
};
use crypto_primitives::{CryptoError, CryptoSigner};
use std::sync::Arc;

// ============================================================================
// AAS as a CertificateSource (provides cert + chain from the AAS service)
// ============================================================================

/// Wraps `AzureArtifactSigningCertificateSource` to implement the certificates
/// pack's `CertificateSource` trait.
struct AasCertificateSourceAdapter {
    inner: Arc<AzureArtifactSigningCertificateSource>,
    /// Cached leaf cert DER (fetched lazily).
    leaf_cert: std::sync::OnceLock<Vec<u8>>,
    /// Chain builder populated from AAS cert chain.
    chain_builder: std::sync::OnceLock<ExplicitCertificateChainBuilder>,
}

impl AasCertificateSourceAdapter {
    fn new(inner: Arc<AzureArtifactSigningCertificateSource>) -> Self {
        Self {
            inner,
            leaf_cert: std::sync::OnceLock::new(),
            chain_builder: std::sync::OnceLock::new(),
        }
    }

    fn ensure_fetched(&self) -> Result<(), CertificateError> {
        if self.leaf_cert.get().is_some() {
            return Ok(());
        }

        // Fetch the PKCS#7 certificate chain from AAS
        let pkcs7_bytes = self
            .inner
            .fetch_certificate_chain_pkcs7()
            .map_err(|e| CertificateError::ChainBuildFailed(e.to_string()))?;

        // Parse PKCS#7 DER to extract individual certificates
        let certs = parse_pkcs7_chain(&pkcs7_bytes).map_err(|e| {
            CertificateError::ChainBuildFailed(format!("PKCS#7 parse failed: {}", e))
        })?;

        if certs.is_empty() {
            return Err(CertificateError::ChainBuildFailed(
                "PKCS#7 chain contains no certificates".into(),
            ));
        }

        // First certificate is the leaf (signing cert), rest are intermediates/root
        let leaf_cert = certs[0].clone();
        let _ = self.leaf_cert.set(leaf_cert);
        let _ = self
            .chain_builder
            .set(ExplicitCertificateChainBuilder::new(certs));

        Ok(())
    }
}

impl CertificateSource for AasCertificateSourceAdapter {
    fn get_signing_certificate(&self) -> Result<&[u8], CertificateError> {
        self.ensure_fetched()?;
        Ok(self
            .leaf_cert
            .get()
            .expect("leaf_cert must be set after successful ensure_fetched"))
    }

    fn has_private_key(&self) -> bool {
        false // remote — private key lives in HSM
    }

    fn get_chain_builder(
        &self,
    ) -> &dyn cose_sign1_certificates::chain_builder::CertificateChainBuilder {
        self.ensure_fetched().ok();
        self.chain_builder
            .get()
            .expect("chain_builder should be initialized after ensure_fetched")
    }
}

// ============================================================================
// AAS CryptoSigner as a SigningKeyProvider
// ============================================================================

/// Wraps `AasCryptoSigner` to implement `SigningKeyProvider` (which extends
/// `CryptoSigner` with `is_remote()`).
struct AasSigningKeyProviderAdapter {
    signer: AasCryptoSigner,
}

impl CryptoSigner for AasSigningKeyProviderAdapter {
    fn sign(&self, data: &[u8]) -> Result<Vec<u8>, CryptoError> {
        self.signer.sign(data)
    }

    fn algorithm(&self) -> i64 {
        self.signer.algorithm()
    }

    fn key_type(&self) -> &str {
        self.signer.key_type()
    }
}

impl SigningKeyProvider for AasSigningKeyProviderAdapter {
    fn is_remote(&self) -> bool {
        true
    }
}

// ============================================================================
// AzureArtifactSigningService — composes over CertificateSigningService
// ============================================================================

/// Azure Artifact Signing service.
///
/// Maps V2 `AzureArtifactSigningService` which extends `CertificateSigningService`.
///
/// In Rust, we compose over `CertificateSigningService` rather than inheriting,
/// so that all standard certificate headers (x5chain, x5t, SCITT CWT claims)
/// are consistently applied by the base implementation.
pub struct AzureArtifactSigningService {
    inner: CertificateSigningService,
}

impl AzureArtifactSigningService {
    /// Create a new AAS signing service with DefaultAzureCredential.
    #[cfg_attr(coverage_nightly, coverage(off))]
    pub fn new(options: AzureArtifactSigningOptions) -> Result<Self, SigningError> {
        let cert_source = Arc::new(
            AzureArtifactSigningCertificateSource::new(options.clone()).map_err(|e| {
                SigningError::KeyError {
                    detail: e.to_string().into(),
                }
            })?,
        );

        Self::from_source(cert_source, options)
    }

    /// Create with an explicit Azure credential.
    #[cfg_attr(coverage_nightly, coverage(off))]
    pub fn with_credential(
        options: AzureArtifactSigningOptions,
        credential: Arc<dyn TokenCredential>,
    ) -> Result<Self, SigningError> {
        let cert_source = Arc::new(
            AzureArtifactSigningCertificateSource::with_credential(options.clone(), credential)
                .map_err(|e| SigningError::KeyError {
                    detail: e.to_string().into(),
                })?,
        );

        Self::from_source(cert_source, options)
    }

    /// Create from a pre-configured client (for testing with mock transports).
    ///
    /// This bypasses credential setup and uses the provided client directly,
    /// allowing tests to inject `SequentialMockTransport` without Azure credentials.
    pub fn from_client(
        client: azure_artifact_signing_client::CertificateProfileClient,
    ) -> Result<Self, SigningError> {
        let cert_source = Arc::new(AzureArtifactSigningCertificateSource::with_client(client));
        let options = AzureArtifactSigningOptions {
            endpoint: String::new(),
            account_name: String::new(),
            certificate_profile_name: String::new(),
        };
        Self::from_source(cert_source, options)
    }

    fn from_source(
        cert_source: Arc<AzureArtifactSigningCertificateSource>,
        _options: AzureArtifactSigningOptions,
    ) -> Result<Self, SigningError> {
        // Create the certificate source adapter
        let source_adapter = Box::new(AasCertificateSourceAdapter::new(Arc::clone(&cert_source)));

        // Create the signing key provider (remote signer via AAS)
        let aas_signer = AasCryptoSigner::new(
            cert_source.clone(),
            "PS256".to_string(), // AAS primarily uses RSA-PSS
            -37,                 // COSE PS256
            "RSA".to_string(),
        );
        let key_provider: Arc<dyn SigningKeyProvider> =
            Arc::new(AasSigningKeyProviderAdapter { signer: aas_signer });

        // Build AAS-specific DID:x509 issuer from the certificate chain.
        // This uses the "deepest greatest" Microsoft EKU selection logic
        // from V2 AzureArtifactSigningDidX509.Generate().
        let aas_did_issuer = Self::build_ats_did_issuer(&cert_source);

        // Create CertificateSigningOptions with:
        // - SCITT compliance enabled
        // - Custom CWT claims with the AAS-specific DID:x509 issuer
        let cert_options = CertificateSigningOptions {
            enable_scitt_compliance: true,
            custom_cwt_claims: Some(CwtClaims::new().with_issuer(
                aas_did_issuer.unwrap_or_else(|_| "did:x509:ats:pending".to_string()),
            )),
        };

        // Compose: CertificateSigningService handles all the header logic
        let inner = CertificateSigningService::new(source_adapter, key_provider, cert_options);

        Ok(Self { inner })
    }

    /// Build the AAS-specific DID:x509 issuer from the certificate chain.
    ///
    /// Fetches the root cert from AAS and uses the Microsoft EKU selection
    /// logic to build a DID:x509 identifier.
    fn build_ats_did_issuer(
        cert_source: &AzureArtifactSigningCertificateSource,
    ) -> Result<String, SigningError> {
        // Fetch root certificate to build the chain for DID:x509
        let root_der =
            cert_source
                .fetch_root_certificate()
                .map_err(|e| SigningError::KeyError {
                    detail: format!("Failed to fetch AAS root cert for DID:x509: {}", e).into(),
                })?;

        let chain_refs: Vec<&[u8]> = vec![root_der.as_slice()];
        build_did_x509_from_ats_chain(&chain_refs).map_err(|e| SigningError::KeyError {
            detail: format!("AAS DID:x509 generation failed: {}", e).into(),
        })
    }
}

/// Delegate all `SigningService` methods to the inner `CertificateSigningService`.
impl SigningService for AzureArtifactSigningService {
    fn get_cose_signer(&self, ctx: &SigningContext) -> Result<CoseSigner, SigningError> {
        self.inner.get_cose_signer(ctx)
    }

    fn is_remote(&self) -> bool {
        true
    }

    fn service_metadata(&self) -> &SigningServiceMetadata {
        self.inner.service_metadata()
    }

    fn verify_signature(
        &self,
        message_bytes: &[u8],
        ctx: &SigningContext,
    ) -> Result<bool, SigningError> {
        // Delegate to CertificateSigningService — standard cert-based verification
        self.inner.verify_signature(message_bytes, ctx)
    }
}

/// Parse a DER-encoded PKCS#7 (SignedData) bundle or single certificate to
/// extract individual DER-encoded X.509 certificates, ordered leaf-first.
///
/// AAS returns certificate chains as `application/pkcs7-mime` DER or as a
/// single `application/x-x509-ca-cert` DER certificate.
///
/// Extraction strategy:
/// 1. Try parsing as a single X.509 DER certificate (simplest case)
/// 2. Try parsing as PKCS#7 DER and scan for embedded X.509 certificates
///    using ASN.1 SEQUENCE tag markers within the structure
fn parse_pkcs7_chain(response_bytes: &[u8]) -> Result<Vec<Vec<u8>>, String> {
    // Strategy 1: Single X.509 DER certificate
    if let Ok(x509) = openssl::x509::X509::from_der(response_bytes) {
        return Ok(vec![x509
            .to_der()
            .map_err(|e| format!("cert to DER: {}", e))?]);
    }

    // Strategy 2: PKCS#7 signed-data — extract certs via ASN.1 scanning.
    //
    // PKCS#7 SignedData contains a SET OF Certificate in its `certificates`
    // field. Each certificate is an ASN.1 SEQUENCE. We verify the outer
    // structure is valid PKCS#7 first, then scan for embedded certificates
    // by trying X509::from_der at each SEQUENCE tag offset.
    let _pkcs7 = openssl::pkcs7::Pkcs7::from_der(response_bytes)
        .map_err(|e| format!("invalid PKCS#7 DER: {}", e))?;

    // Scan the DER bytes for embedded X.509 certificate SEQUENCE structures.
    // This is a robust approach that works regardless of the openssl crate's
    // level of PKCS#7 API support.
    let certs = extract_embedded_certificates(response_bytes);

    if certs.is_empty() {
        Err("no certificates found in PKCS#7 bundle".into())
    } else {
        Ok(certs)
    }
}

/// Scan DER bytes for embedded X.509 certificate structures.
///
/// Walks the byte buffer looking for ASN.1 SEQUENCE tags (0x30) followed by
/// valid multi-byte lengths, and attempts to parse each candidate region as
/// an X.509 certificate. This handles both PKCS#7 and raw DER cert bundles.
fn extract_embedded_certificates(der: &[u8]) -> Vec<Vec<u8>> {
    let mut certs = Vec::new();
    let mut offset = 0;

    while offset < der.len() {
        // Look for ASN.1 SEQUENCE tag (0x30)
        if der[offset] != 0x30 {
            offset += 1;
            continue;
        }

        // Determine the length of this SEQUENCE
        if let Some(seq_len) = read_asn1_length(der, offset + 1) {
            let header_len = asn1_header_length(der, offset + 1);
            let total_len = 1 + header_len + seq_len;

            if offset + total_len <= der.len() {
                let candidate = &der[offset..offset + total_len];
                if let Ok(x509) = openssl::x509::X509::from_der(candidate) {
                    if let Ok(cert_der) = x509.to_der() {
                        certs.push(cert_der);
                        offset += total_len;
                        continue;
                    }
                }
            }
        }
        offset += 1;
    }
    certs
}

/// Read an ASN.1 length value starting at `offset` in `der`.
fn read_asn1_length(der: &[u8], offset: usize) -> Option<usize> {
    if offset >= der.len() {
        return None;
    }
    let first = der[offset] as usize;
    if first < 0x80 {
        // Short form
        Some(first)
    } else if first == 0x80 {
        // Indefinite length — not supported for certificates
        None
    } else {
        // Long form: first byte = 0x80 | num_length_bytes
        let num_bytes = first & 0x7F;
        if num_bytes > 4 || offset + 1 + num_bytes > der.len() {
            return None;
        }
        let mut length = 0usize;
        for i in 0..num_bytes {
            length = (length << 8) | (der[offset + 1 + i] as usize);
        }
        Some(length)
    }
}

/// Calculate the number of bytes used by the ASN.1 length encoding.
fn asn1_header_length(der: &[u8], offset: usize) -> usize {
    if offset >= der.len() {
        return 0;
    }
    let first = der[offset] as usize;
    if first < 0x80 {
        1
    } else {
        1 + (first & 0x7F)
    }
}
