// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Certificate signing service.
//!
//! Maps V2 `CertificateSigningService`.

use std::sync::Arc;

use crypto_primitives::CryptoSigner;
use cose_sign1_signing::{
    CoseSigner, HeaderContributor, HeaderContributorContext, SigningContext, SigningError,
    SigningService, SigningServiceMetadata,
};

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
            "CertificateSigningService".to_string(),
            "X.509 certificate-based signing service".to_string(),
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
            .map_err(|e| SigningError::SigningFailed(e.to_string()))?;
        let chain_builder = self.certificate_source.get_chain_builder();
        let chain = chain_builder
            .build_chain(&[])
            .map_err(|e| SigningError::SigningFailed(e.to_string()))?;
        let chain_refs: Vec<&[u8]> = chain.iter().map(|c| c.as_slice()).collect();

        // Initialize header maps
        let mut protected_headers = cose_sign1_primitives::CoseHeaderMap::new();
        let mut unprotected_headers = cose_sign1_primitives::CoseHeaderMap::new();

        // Create header contributor context
        let contributor_context =
            HeaderContributorContext::new(context, &*self.signing_key_provider);

        // 1. Add certificate headers (x5t + x5chain) to PROTECTED
        let cert_contributor =
            CertificateHeaderContributor::new(cert, &chain_refs)
                .map_err(|e| SigningError::SigningFailed(e.to_string()))?;

        cert_contributor.contribute_protected_headers(&mut protected_headers, &contributor_context);

        // 2. If SCITT compliance enabled, add CWT claims to PROTECTED
        if self.options.enable_scitt_compliance {
            let scitt_contributor = scitt::create_scitt_contributor(
                &chain_refs,
                self.options.custom_cwt_claims.as_ref(),
            )
            .map_err(|e| SigningError::SigningFailed(e.to_string()))?;

            scitt_contributor.contribute_protected_headers(
                &mut protected_headers,
                &contributor_context,
            );
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
        let boxed_signer: Box<dyn CryptoSigner> = Box::new(ArcSignerWrapper { signer: crypto_signer });
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
        _message_bytes: &[u8],
        _context: &SigningContext,
    ) -> Result<bool, SigningError> {
        // TODO: Implement post-sign verification
        Ok(true)
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
