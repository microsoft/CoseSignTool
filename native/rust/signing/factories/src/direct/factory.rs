// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Direct signature factory implementation.

use tracing::info;

use std::sync::Arc;

use cose_sign1_primitives::{CoseSign1Builder, CoseSign1Message};
use cose_sign1_signing::{
    transparency::{add_proof_with_receipt_merge, TransparencyProvider},
    HeaderContributor, HeaderContributorContext, SigningContext, SigningService,
};

use crate::{
    direct::{ContentTypeHeaderContributor, DirectSignatureOptions},
    FactoryError,
};

/// Factory for creating direct COSE_Sign1 signatures.
///
/// Maps V2 `DirectSignatureFactory`. Signs the payload directly (embedded or detached).
pub struct DirectSignatureFactory {
    signing_service: Arc<dyn SigningService>,
    transparency_providers: Vec<Box<dyn TransparencyProvider>>,
}

impl DirectSignatureFactory {
    /// Creates a new direct signature factory.
    pub fn new(signing_service: Arc<dyn SigningService>) -> Self {
        Self {
            signing_service,
            transparency_providers: vec![],
        }
    }

    /// Creates a new direct signature factory with transparency providers.
    pub fn with_transparency_providers(
        signing_service: Arc<dyn SigningService>,
        providers: Vec<Box<dyn TransparencyProvider>>,
    ) -> Self {
        Self {
            signing_service,
            transparency_providers: providers,
        }
    }

    /// Returns a reference to the transparency providers.
    pub fn transparency_providers(&self) -> &[Box<dyn TransparencyProvider>] {
        &self.transparency_providers
    }

    /// Creates a COSE_Sign1 message with a direct signature and returns it as bytes.
    ///
    /// # Arguments
    ///
    /// * `payload` - The payload bytes to sign
    /// * `content_type` - Content type of the payload (added to protected headers)
    /// * `options` - Optional signing options (uses defaults if None)
    ///
    /// # Returns
    ///
    /// The COSE_Sign1 message bytes, or an error if signing or verification fails.
    pub fn create_bytes(
        &self,
        payload: &[u8],
        content_type: &str,
        options: Option<DirectSignatureOptions>,
    ) -> Result<Vec<u8>, FactoryError> {
        info!(method = "sign_direct", payload_len = payload.len(), content_type = %content_type, "Signing payload");
        let options = options.unwrap_or_default();

        // Create signing context (zero-copy borrow of caller's payload)
        let mut context = SigningContext::from_slice(payload);
        context.content_type = Some(content_type.to_string());

        // Add content type contributor (always first)
        let content_type_contributor = ContentTypeHeaderContributor::new(content_type);

        // Get signer from signing service
        info!(
            service = self.signing_service.service_metadata().service_name,
            "Creating CoseSigner"
        );
        let signer = self.signing_service.get_cose_signer(&context)?;

        info!(
            method = "sign_direct",
            algorithm = signer.signer().algorithm(),
            key_id = ?signer.signer().key_id(),
            "Signer created"
        );

        // Build headers by applying contributors
        let mut protected = signer.protected_headers().clone();
        let mut unprotected = signer.unprotected_headers().clone();

        let header_ctx = HeaderContributorContext::new(&context, signer.signer());

        // Apply content type contributor first
        content_type_contributor.contribute_protected_headers(&mut protected, &header_ctx);
        content_type_contributor.contribute_unprotected_headers(&mut unprotected, &header_ctx);

        // Apply additional header contributors
        for contributor in &options.additional_header_contributors {
            contributor.contribute_protected_headers(&mut protected, &header_ctx);
            contributor.contribute_unprotected_headers(&mut unprotected, &header_ctx);
        }

        // Build COSE_Sign1 message
        let mut builder = CoseSign1Builder::new()
            .protected(protected)
            .unprotected(unprotected)
            .detached(!options.embed_payload);

        // Move external AAD if provided (avoids clone)
        if !options.additional_data.is_empty() {
            builder = builder.external_aad(options.additional_data);
        }

        // Sign the payload
        let message_bytes = builder.sign(signer.signer(), payload)?;

        // POST-SIGN VERIFICATION (critical V2 alignment)
        let verification_result = self
            .signing_service
            .verify_signature(&message_bytes, &context)?;

        if !verification_result {
            return Err(FactoryError::VerificationFailed {
                detail: std::borrow::Cow::Borrowed("Post-sign verification failed"),
            });
        }

        // Apply transparency providers if configured
        if !self.transparency_providers.is_empty() {
            let disable = options.disable_transparency;
            if !disable {
                let mut current_bytes = message_bytes;
                for provider in &self.transparency_providers {
                    current_bytes = add_proof_with_receipt_merge(provider.as_ref(), &current_bytes)
                        .map_err(|e| FactoryError::TransparencyFailed {
                            detail: e.to_string().into(),
                        })?;
                }
                return Ok(current_bytes);
            }
        }

        Ok(message_bytes)
    }

    /// Creates a COSE_Sign1 message with a direct signature.
    ///
    /// # Arguments
    ///
    /// * `payload` - The payload bytes to sign
    /// * `content_type` - Content type of the payload (added to protected headers)
    /// * `options` - Optional signing options (uses defaults if None)
    ///
    /// # Returns
    ///
    /// The COSE_Sign1 message, or an error if signing or verification fails.
    pub fn create(
        &self,
        payload: &[u8],
        content_type: &str,
        options: Option<DirectSignatureOptions>,
    ) -> Result<CoseSign1Message, FactoryError> {
        let bytes = self.create_bytes(payload, content_type, options)?;
        CoseSign1Message::parse(&bytes).map_err(|e| FactoryError::SigningFailed {
            detail: e.to_string().into(),
        })
    }

    /// Creates a COSE_Sign1 message with a direct signature from a streaming payload and returns it as bytes.
    ///
    /// # Arguments
    ///
    /// * `payload` - The streaming payload to sign
    /// * `content_type` - Content type of the payload (added to protected headers)
    /// * `options` - Optional signing options (uses defaults if None)
    ///
    /// # Returns
    ///
    /// The COSE_Sign1 message bytes, or an error if signing or verification fails.
    pub fn create_streaming_bytes(
        &self,
        payload: std::sync::Arc<dyn cose_sign1_primitives::StreamingPayload>,
        content_type: &str,
        options: Option<DirectSignatureOptions>,
    ) -> Result<Vec<u8>, FactoryError> {
        use cose_sign1_primitives::MAX_EMBED_PAYLOAD_SIZE;

        let options = options.unwrap_or_default();
        let max_embed_size = options.max_embed_size.unwrap_or(MAX_EMBED_PAYLOAD_SIZE);

        // Enforce embed size limit
        if options.embed_payload && payload.size() > max_embed_size {
            return Err(FactoryError::PayloadTooLargeForEmbedding {
                actual: payload.size(),
                max: max_embed_size,
            });
        }

        // Create signing context (use empty vec for context since we'll stream)
        let mut context = SigningContext::from_bytes(Vec::new());
        context.content_type = Some(content_type.to_string());

        // Add content type contributor (always first)
        let content_type_contributor = ContentTypeHeaderContributor::new(content_type);

        // Get signer from signing service
        let signer = self.signing_service.get_cose_signer(&context)?;

        // Build headers by applying contributors
        let mut protected = signer.protected_headers().clone();
        let mut unprotected = signer.unprotected_headers().clone();

        let header_ctx = HeaderContributorContext::new(&context, signer.signer());

        // Apply content type contributor first
        content_type_contributor.contribute_protected_headers(&mut protected, &header_ctx);
        content_type_contributor.contribute_unprotected_headers(&mut unprotected, &header_ctx);

        // Apply additional header contributors
        for contributor in &options.additional_header_contributors {
            contributor.contribute_protected_headers(&mut protected, &header_ctx);
            contributor.contribute_unprotected_headers(&mut unprotected, &header_ctx);
        }

        // Build COSE_Sign1 message using streaming
        let mut builder = CoseSign1Builder::new()
            .protected(protected)
            .unprotected(unprotected)
            .detached(!options.embed_payload);

        // Set max embed size
        if let Some(max_size) = options.max_embed_size {
            builder = builder.max_embed_size(max_size);
        }

        // Move external AAD if provided (avoids clone)
        if !options.additional_data.is_empty() {
            builder = builder.external_aad(options.additional_data);
        }

        // Sign the streaming payload
        let message_bytes = builder.sign_streaming(signer.signer(), payload)?;

        // POST-SIGN VERIFICATION (critical V2 alignment)
        let verification_result = self
            .signing_service
            .verify_signature(&message_bytes, &context)?;

        if !verification_result {
            return Err(FactoryError::VerificationFailed {
                detail: std::borrow::Cow::Borrowed("Post-sign verification failed"),
            });
        }

        // Apply transparency providers if configured
        if !self.transparency_providers.is_empty() {
            let disable = options.disable_transparency;
            if !disable {
                let mut current_bytes = message_bytes;
                for provider in &self.transparency_providers {
                    current_bytes = add_proof_with_receipt_merge(provider.as_ref(), &current_bytes)
                        .map_err(|e| FactoryError::TransparencyFailed {
                            detail: e.to_string().into(),
                        })?;
                }
                return Ok(current_bytes);
            }
        }

        Ok(message_bytes)
    }

    /// Creates a COSE_Sign1 message with a direct signature from a streaming payload.
    ///
    /// # Arguments
    ///
    /// * `payload` - The streaming payload to sign
    /// * `content_type` - Content type of the payload (added to protected headers)
    /// * `options` - Optional signing options (uses defaults if None)
    ///
    /// # Returns
    ///
    /// The COSE_Sign1 message, or an error if signing or verification fails.
    pub fn create_streaming(
        &self,
        payload: std::sync::Arc<dyn cose_sign1_primitives::StreamingPayload>,
        content_type: &str,
        options: Option<DirectSignatureOptions>,
    ) -> Result<CoseSign1Message, FactoryError> {
        let bytes = self.create_streaming_bytes(payload, content_type, options)?;
        CoseSign1Message::parse(&bytes).map_err(|e| FactoryError::SigningFailed {
            detail: e.to_string().into(),
        })
    }
}
