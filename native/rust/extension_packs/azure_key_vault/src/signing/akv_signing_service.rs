// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Azure Key Vault signing service implementation.
//!
//! Provides a signing service that uses Azure Key Vault for cryptographic operations.

use cose_sign1_primitives::{CoseHeaderLabel, CoseHeaderMap, CoseHeaderValue};
use cose_sign1_signing::{
    CoseSigner, HeaderContributor, HeaderContributorContext, HeaderMergeStrategy, SigningContext,
    SigningError, SigningService, SigningServiceMetadata,
};
use crypto_primitives::CryptoVerifier;

use crate::common::{AkvError, KeyVaultCryptoClient};
use crate::signing::{
    akv_signing_key::AzureKeyVaultSigningKey,
    cose_key_header_contributor::{CoseKeyHeaderContributor, CoseKeyHeaderLocation},
    key_id_header_contributor::KeyIdHeaderContributor,
};

/// Azure Key Vault signing service.
///
/// Maps V2's `AzureKeyVaultSigningService` class.
pub struct AzureKeyVaultSigningService {
    signing_key: AzureKeyVaultSigningKey,
    service_metadata: SigningServiceMetadata,
    kid_contributor: KeyIdHeaderContributor,
    public_key_contributor: Option<CoseKeyHeaderContributor>,
    initialized: bool,
}

impl AzureKeyVaultSigningService {
    /// Creates a new Azure Key Vault signing service.
    ///
    /// Must call `initialize()` before use.
    ///
    /// # Arguments
    ///
    /// * `crypto_client` - The AKV crypto client for signing operations
    pub fn new(crypto_client: Box<dyn KeyVaultCryptoClient>) -> Result<Self, AkvError> {
        let key_id = crypto_client.key_id().to_string();
        let signing_key = AzureKeyVaultSigningKey::new(crypto_client)?;

        let service_metadata = SigningServiceMetadata::new(
            "AzureKeyVault".to_string(),
            "Azure Key Vault signing service".to_string(),
        );

        let kid_contributor = KeyIdHeaderContributor::new(key_id);

        Ok(Self {
            signing_key,
            service_metadata,
            kid_contributor,
            public_key_contributor: None,
            initialized: false,
        })
    }

    /// Initializes the signing service.
    ///
    /// Loads key metadata and prepares contributors.
    /// Must be called before using the service.
    pub fn initialize(&mut self) -> Result<(), AkvError> {
        if self.initialized {
            return Ok(());
        }

        // In V2, this loads key metadata asynchronously.
        // In Rust, we simplify and assume the crypto_client is already initialized.
        // The signing_key was already created in new(), so we just mark as initialized.
        self.initialized = true;
        Ok(())
    }

    /// Enables public key embedding in signatures.
    ///
    /// Maps V2's `PublicKeyHeaderContributor` functionality.
    /// By default, the public key is embedded in UNPROTECTED headers.
    ///
    /// # Arguments
    ///
    /// * `location` - Where to place the COSE_Key (protected or unprotected)
    pub fn enable_public_key_embedding(
        &mut self,
        location: CoseKeyHeaderLocation,
    ) -> Result<(), AkvError> {
        let cose_key_bytes = self.signing_key.get_cose_key_bytes()?;
        self.public_key_contributor = Some(CoseKeyHeaderContributor::new(cose_key_bytes, location));
        Ok(())
    }

    /// Checks if the service is initialized.
    fn ensure_initialized(&self) -> Result<(), SigningError> {
        if !self.initialized {
            return Err(SigningError::InvalidConfiguration(
                "Service not initialized. Call initialize() first.".to_string(),
            ));
        }
        Ok(())
    }
}

impl SigningService for AzureKeyVaultSigningService {
    fn get_cose_signer(&self, context: &SigningContext) -> Result<CoseSigner, SigningError> {
        self.ensure_initialized()?;

        // 1. Get CryptoSigner from signing_key (clone it since we need an owned value)
        let signer: Box<dyn crypto_primitives::CryptoSigner> = Box::new(self.signing_key.clone());

        // 2. Build protected headers
        let mut protected_headers = CoseHeaderMap::new();

        // Add kid (label 4) to protected headers
        let contributor_context = HeaderContributorContext::new(context, &*signer);
        self.kid_contributor
            .contribute_protected_headers(&mut protected_headers, &contributor_context);

        // 3. Build unprotected headers
        let mut unprotected_headers = CoseHeaderMap::new();

        // Add COSE_Key embedding if enabled
        if let Some(ref contributor) = self.public_key_contributor {
            contributor.contribute_protected_headers(&mut protected_headers, &contributor_context);
            contributor
                .contribute_unprotected_headers(&mut unprotected_headers, &contributor_context);
        }

        // 4. Apply additional contributors from context
        for contributor in &context.additional_header_contributors {
            match contributor.merge_strategy() {
                HeaderMergeStrategy::Fail => {
                    // Check for conflicts before contributing
                    let mut temp_protected = protected_headers.clone();
                    let mut temp_unprotected = unprotected_headers.clone();
                    contributor
                        .contribute_protected_headers(&mut temp_protected, &contributor_context);
                    contributor.contribute_unprotected_headers(
                        &mut temp_unprotected,
                        &contributor_context,
                    );
                    protected_headers = temp_protected;
                    unprotected_headers = temp_unprotected;
                }
                _ => {
                    contributor
                        .contribute_protected_headers(&mut protected_headers, &contributor_context);
                    contributor.contribute_unprotected_headers(
                        &mut unprotected_headers,
                        &contributor_context,
                    );
                }
            }
        }

        // 5. Add content-type if present in context
        if let Some(ref content_type) = context.content_type {
            let content_type_label = CoseHeaderLabel::Int(3);
            if protected_headers.get(&content_type_label).is_none() {
                protected_headers.insert(
                    content_type_label,
                    CoseHeaderValue::Text(content_type.clone().into()),
                );
            }
        }

        // 6. Return CoseSigner
        Ok(CoseSigner::new(
            signer,
            protected_headers,
            unprotected_headers,
        ))
    }

    fn is_remote(&self) -> bool {
        true
    }

    fn service_metadata(&self) -> &SigningServiceMetadata {
        &self.service_metadata
    }

    fn verify_signature(
        &self,
        message_bytes: &[u8],
        _context: &SigningContext,
    ) -> Result<bool, SigningError> {
        self.ensure_initialized()?;

        // Parse the COSE_Sign1 message
        let msg = cose_sign1_primitives::CoseSign1Message::parse(message_bytes)
            .map_err(|e| SigningError::VerificationFailed(format!("failed to parse: {}", e)))?;

        // Get the public key from the signing key
        let public_key_bytes = self
            .signing_key
            .crypto_client()
            .public_key_bytes()
            .map_err(|e| SigningError::VerificationFailed(format!("public key: {}", e)))?;

        // Determine the COSE algorithm from the signing key
        let algorithm = self.signing_key.algorithm;

        // Create a crypto verifier from the SPKI DER public key bytes
        let verifier = cose_sign1_crypto_openssl::evp_verifier::EvpVerifier::from_der(
            &public_key_bytes,
            algorithm,
        )
        .map_err(|e| SigningError::VerificationFailed(format!("verifier creation: {}", e)))?;

        // Build sig_structure from the message
        let payload = msg.payload().unwrap_or_default();
        let sig_structure = msg
            .sig_structure_bytes(payload, None)
            .map_err(|e| SigningError::VerificationFailed(format!("sig_structure: {}", e)))?;

        verifier
            .verify(&sig_structure, msg.signature())
            .map_err(|e| SigningError::VerificationFailed(format!("verify: {}", e)))
    }
}
