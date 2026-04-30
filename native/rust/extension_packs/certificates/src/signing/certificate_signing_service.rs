// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Certificate signing service.
//!
//! Maps V2 `CertificateSigningService`.

use std::sync::Arc;

use cose_sign1_signing::{
    CoseSigner, HeaderContributor, HeaderContributorContext, SigningContext, SigningError,
    SigningService, SigningServiceMetadata,
};
use crypto_primitives::{CryptoSigner, CryptoVerifier};

use crate::signing::certificate_header_contributor::CertificateHeaderContributor;
use crate::signing::certificate_signing_options::CertificateSigningOptions;
use crate::signing::scitt;
use crate::signing::signing_key_provider::SigningKeyProvider;
use crate::signing::source::CertificateSource;

/// Certificate-based signing service.
///
/// Maps V2 `CertificateSigningService`.
pub struct CertificateSigningService {
    certificate_source: Box<dyn CertificateSource>,
    signing_key_provider: Arc<dyn SigningKeyProvider>,
    options: CertificateSigningOptions,
    metadata: SigningServiceMetadata,
    is_remote: bool,
}

impl CertificateSigningService {
    /// Creates a new certificate signing service.
    ///
    /// # Arguments
    ///
    /// * `certificate_source` - Source of the certificate
    /// * `signing_key_provider` - Provider for signing operations
    /// * `options` - Signing options
    /// * `provider` - CBOR provider for encoding
    pub fn new(
        certificate_source: Box<dyn CertificateSource>,
        signing_key_provider: Arc<dyn SigningKeyProvider>,
        options: CertificateSigningOptions,
    ) -> Self {
        let is_remote = signing_key_provider.is_remote();
        let metadata = SigningServiceMetadata::new(
            "CertificateSigningService".into(),
            "X.509 certificate-based signing service".into(),
        );
        Self {
            certificate_source,
            signing_key_provider,
            options,
            metadata,
            is_remote,
        }
    }
}

impl SigningService for CertificateSigningService {
    fn get_cose_signer(&self, context: &SigningContext) -> Result<CoseSigner, SigningError> {
        // Get certificate for headers
        let cert = self
            .certificate_source
            .get_signing_certificate()
            .map_err(|e| SigningError::SigningFailed {
                detail: e.to_string().into(),
            })?;
        let chain_builder = self.certificate_source.get_chain_builder();
        let chain = chain_builder
            .build_chain(&[])
            .map_err(|e| SigningError::SigningFailed {
                detail: e.to_string().into(),
            })?;
        let chain_refs: Vec<&[u8]> = chain.iter().map(|c| c.as_slice()).collect();

        // Initialize header maps
        let mut protected_headers = cose_sign1_primitives::CoseHeaderMap::new();
        let mut unprotected_headers = cose_sign1_primitives::CoseHeaderMap::new();

        // Set the algorithm in protected headers (required by RFC 9052)
        let algorithm = self.signing_key_provider.algorithm();
        if algorithm != 0 {
            protected_headers.set_alg(algorithm);
        }

        // Create header contributor context
        let contributor_context =
            HeaderContributorContext::new(context, &*self.signing_key_provider);

        // 1. Add certificate headers (x5t + x5chain) to PROTECTED
        let cert_contributor =
            CertificateHeaderContributor::new(cert, &chain_refs).map_err(|e| {
                SigningError::SigningFailed {
                    detail: e.to_string().into(),
                }
            })?;

        cert_contributor.contribute_protected_headers(&mut protected_headers, &contributor_context);

        // 2. If SCITT compliance enabled, add CWT claims to PROTECTED
        if self.options.enable_scitt_compliance {
            let scitt_contributor = scitt::create_scitt_contributor(
                &chain_refs,
                self.options.custom_cwt_claims.as_ref(),
            )
            .map_err(|e| SigningError::SigningFailed {
                detail: e.to_string().into(),
            })?;

            scitt_contributor
                .contribute_protected_headers(&mut protected_headers, &contributor_context);
        }

        // 3. Run additional contributors from context
        for contributor in &context.additional_header_contributors {
            contributor.contribute_protected_headers(&mut protected_headers, &contributor_context);
            contributor
                .contribute_unprotected_headers(&mut unprotected_headers, &contributor_context);
        }

        // Create signer with cloned Arc<dyn CryptoSigner>
        let crypto_signer: Arc<dyn CryptoSigner> = self.signing_key_provider.clone();
        // Convert Arc to Box for CoseSigner
        // This is a bit awkward but necessary due to CoseSigner's API
        let boxed_signer: Box<dyn CryptoSigner> = Box::new(ArcSignerWrapper {
            signer: crypto_signer,
        });
        Ok(CoseSigner::new(
            boxed_signer,
            protected_headers,
            unprotected_headers,
        ))
    }

    fn is_remote(&self) -> bool {
        self.is_remote
    }

    fn service_metadata(&self) -> &SigningServiceMetadata {
        &self.metadata
    }

    fn verify_signature(
        &self,
        message_bytes: &[u8],
        _context: &SigningContext,
    ) -> Result<bool, SigningError> {
        // Parse the COSE_Sign1 message
        let msg = cose_sign1_primitives::CoseSign1Message::parse(message_bytes).map_err(|e| {
            SigningError::VerificationFailed {
                detail: format!("failed to parse COSE_Sign1: {}", e).into(),
            }
        })?;

        // Extract the public key from the signing certificate
        let cert_der = self
            .certificate_source
            .get_signing_certificate()
            .map_err(|e| SigningError::VerificationFailed {
                detail: format!("certificate source: {}", e).into(),
            })?;

        let x509 = openssl::x509::X509::from_der(cert_der).map_err(|e| {
            SigningError::VerificationFailed {
                detail: format!("failed to parse certificate: {}", e).into(),
            }
        })?;

        let public_key_der = x509
            .public_key()
            .map_err(|e| SigningError::VerificationFailed {
                detail: format!("failed to extract public key: {}", e).into(),
            })?
            .public_key_to_der()
            .map_err(|e| SigningError::VerificationFailed {
                detail: format!("failed to encode public key: {}", e).into(),
            })?;

        // Determine algorithm from the signing key provider
        let algorithm = self.signing_key_provider.algorithm();

        // Create verifier from the certificate's public key
        let verifier = cose_sign1_crypto_openssl::evp_verifier::EvpVerifier::from_der(
            &public_key_der,
            algorithm,
        )
        .map_err(|e| SigningError::VerificationFailed {
            detail: format!("verifier creation: {}", e).into(),
        })?;

        // Build Sig_structure and verify
        let payload = msg.payload().unwrap_or_default();
        let sig_structure = msg.sig_structure_bytes(payload, None).map_err(|e| {
            SigningError::VerificationFailed {
                detail: format!("sig_structure: {}", e).into(),
            }
        })?;

        verifier
            .verify(&sig_structure, msg.signature())
            .map_err(|e| SigningError::VerificationFailed {
                detail: format!("verify: {}", e).into(),
            })
    }
}

/// Wrapper to convert Arc<dyn CryptoSigner> to Box<dyn CryptoSigner> for CoseSigner.
struct ArcSignerWrapper {
    signer: Arc<dyn CryptoSigner>,
}

impl CryptoSigner for ArcSignerWrapper {
    fn sign(&self, data: &[u8]) -> Result<Vec<u8>, crypto_primitives::CryptoError> {
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
}
