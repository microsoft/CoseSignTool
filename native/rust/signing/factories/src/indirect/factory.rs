// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Indirect signature factory implementation.

use std::sync::Arc;

use cose_sign1_primitives::CoseSign1Message;
use cose_sign1_signing::SigningService;
use sha2::{Digest, Sha256, Sha384, Sha512};

use crate::{
    direct::DirectSignatureFactory,
    indirect::{HashAlgorithm, HashEnvelopeHeaderContributor, IndirectSignatureOptions},
    FactoryError,
};

/// Factory for creating indirect COSE_Sign1 signatures.
///
/// Maps V2 `IndirectSignatureFactory`. Hashes the payload and signs the hash,
/// adding hash envelope headers to indicate the original content.
pub struct IndirectSignatureFactory {
    direct_factory: DirectSignatureFactory,
}

impl IndirectSignatureFactory {
    /// Creates a new indirect signature factory from a DirectSignatureFactory.
    ///
    /// This is the primary constructor that follows the V2 pattern where
    /// IndirectSignatureFactory wraps a DirectSignatureFactory.
    pub fn new(direct_factory: DirectSignatureFactory) -> Self {
        Self { direct_factory }
    }

    /// Creates a new indirect signature factory from a signing service.
    ///
    /// This is a convenience constructor that creates a DirectSignatureFactory
    /// internally. Use this when you don't need to share the DirectSignatureFactory
    /// with other components.
    pub fn from_signing_service(signing_service: Arc<dyn SigningService>) -> Self {
        Self::new(DirectSignatureFactory::new(signing_service))
    }

    /// Access the underlying direct factory for direct signing operations.
    ///
    /// This allows the router factory to access the direct factory without
    /// creating a separate instance.
    pub fn direct_factory(&self) -> &DirectSignatureFactory {
        &self.direct_factory
    }

    /// Creates a COSE_Sign1 message with an indirect signature and returns it as bytes.
    ///
    /// # Arguments
    ///
    /// * `payload` - The payload bytes to hash and sign
    /// * `content_type` - Original content type of the payload
    /// * `options` - Optional signing options (uses defaults if None)
    ///
    /// # Returns
    ///
    /// The COSE_Sign1 message bytes, or an error if signing or verification fails.
    ///
    /// # Process
    ///
    /// 1. Hash the payload using the specified algorithm
    /// 2. Create HashEnvelopeHeaderContributor with envelope headers
    /// 3. Delegate to DirectSignatureFactory with the hash as the payload
    /// 4. The signed content is the hash, not the original payload
    pub fn create_bytes(
        &self,
        payload: &[u8],
        content_type: &str,
        options: Option<IndirectSignatureOptions>,
    ) -> Result<Vec<u8>, FactoryError> {
        let options = options.unwrap_or_default();

        // Hash the payload
        let hash_bytes = match options.payload_hash_algorithm {
            HashAlgorithm::Sha256 => {
                let mut hasher = Sha256::new();
                hasher.update(payload);
                hasher.finalize().to_vec()
            }
            HashAlgorithm::Sha384 => {
                let mut hasher = Sha384::new();
                hasher.update(payload);
                hasher.finalize().to_vec()
            }
            HashAlgorithm::Sha512 => {
                let mut hasher = Sha512::new();
                hasher.update(payload);
                hasher.finalize().to_vec()
            }
        };

        // Create hash envelope contributor
        let hash_envelope_contributor = HashEnvelopeHeaderContributor::new(
            options.payload_hash_algorithm,
            content_type,
            options.payload_location.clone(),
        );

        // Create modified direct options with hash envelope contributor
        let mut direct_options = options.base;
        direct_options
            .additional_header_contributors
            .insert(0, Box::new(hash_envelope_contributor));

        // The content type for the signed message is "application/octet-stream"
        // since we're signing a hash, not the original content
        let signed_content_type = "application/octet-stream";

        // Delegate to direct factory with the hash as the payload
        self.direct_factory
            .create_bytes(&hash_bytes, signed_content_type, Some(direct_options))
    }

    /// Creates a COSE_Sign1 message with an indirect signature.
    ///
    /// # Arguments
    ///
    /// * `payload` - The payload bytes to hash and sign
    /// * `content_type` - Original content type of the payload
    /// * `options` - Optional signing options (uses defaults if None)
    ///
    /// # Returns
    ///
    /// The COSE_Sign1 message, or an error if signing or verification fails.
    ///
    /// # Process
    ///
    /// 1. Hash the payload using the specified algorithm
    /// 2. Create HashEnvelopeHeaderContributor with envelope headers
    /// 3. Delegate to DirectSignatureFactory with the hash as the payload
    /// 4. The signed content is the hash, not the original payload
    pub fn create(
        &self,
        payload: &[u8],
        content_type: &str,
        options: Option<IndirectSignatureOptions>,
    ) -> Result<CoseSign1Message, FactoryError> {
        let bytes = self.create_bytes(payload, content_type, options)?;
        CoseSign1Message::parse(&bytes).map_err(|e| FactoryError::SigningFailed(e.to_string()))
    }

    /// Creates a COSE_Sign1 message with an indirect signature from a streaming payload and returns it as bytes.
    ///
    /// # Arguments
    ///
    /// * `payload` - The streaming payload to hash and sign
    /// * `content_type` - Original content type of the payload
    /// * `options` - Optional signing options (uses defaults if None)
    ///
    /// # Returns
    ///
    /// The COSE_Sign1 message bytes, or an error if signing or verification fails.
    ///
    /// # Process
    ///
    /// 1. Stream the payload through the hash algorithm
    /// 2. Create HashEnvelopeHeaderContributor with envelope headers
    /// 3. Delegate to DirectSignatureFactory with the hash as the payload
    /// 4. The signed content is the hash, not the original payload
    pub fn create_streaming_bytes(
        &self,
        payload: std::sync::Arc<dyn cose_sign1_primitives::StreamingPayload>,
        content_type: &str,
        options: Option<IndirectSignatureOptions>,
    ) -> Result<Vec<u8>, FactoryError> {
        let options = options.unwrap_or_default();

        // Hash the streaming payload
        let mut reader = payload
            .open()
            .map_err(|e| FactoryError::SigningFailed(format!("Failed to open payload: {}", e)))?;

        let hash_bytes = match options.payload_hash_algorithm {
            HashAlgorithm::Sha256 => {
                let mut hasher = Sha256::new();
                let mut buf = vec![0u8; 65536];
                loop {
                    let n = std::io::Read::read(reader.as_mut(), &mut buf).map_err(|e| {
                        FactoryError::SigningFailed(format!("Failed to read payload: {}", e))
                    })?;
                    if n == 0 {
                        break;
                    }
                    hasher.update(&buf[..n]);
                }
                hasher.finalize().to_vec()
            }
            HashAlgorithm::Sha384 => {
                let mut hasher = Sha384::new();
                let mut buf = vec![0u8; 65536];
                loop {
                    let n = std::io::Read::read(reader.as_mut(), &mut buf).map_err(|e| {
                        FactoryError::SigningFailed(format!("Failed to read payload: {}", e))
                    })?;
                    if n == 0 {
                        break;
                    }
                    hasher.update(&buf[..n]);
                }
                hasher.finalize().to_vec()
            }
            HashAlgorithm::Sha512 => {
                let mut hasher = Sha512::new();
                let mut buf = vec![0u8; 65536];
                loop {
                    let n = std::io::Read::read(reader.as_mut(), &mut buf).map_err(|e| {
                        FactoryError::SigningFailed(format!("Failed to read payload: {}", e))
                    })?;
                    if n == 0 {
                        break;
                    }
                    hasher.update(&buf[..n]);
                }
                hasher.finalize().to_vec()
            }
        };

        // Create hash envelope contributor
        let hash_envelope_contributor = HashEnvelopeHeaderContributor::new(
            options.payload_hash_algorithm,
            content_type,
            options.payload_location.clone(),
        );

        // Create modified direct options with hash envelope contributor
        let mut direct_options = options.base;
        direct_options
            .additional_header_contributors
            .insert(0, Box::new(hash_envelope_contributor));

        // The content type for the signed message is "application/octet-stream"
        // since we're signing a hash, not the original content
        let signed_content_type = "application/octet-stream";

        // Delegate to direct factory with the hash as the payload
        self.direct_factory
            .create_bytes(&hash_bytes, signed_content_type, Some(direct_options))
    }

    /// Creates a COSE_Sign1 message with an indirect signature from a streaming payload.
    ///
    /// # Arguments
    ///
    /// * `payload` - The streaming payload to hash and sign
    /// * `content_type` - Original content type of the payload
    /// * `options` - Optional signing options (uses defaults if None)
    ///
    /// # Returns
    ///
    /// The COSE_Sign1 message, or an error if signing or verification fails.
    pub fn create_streaming(
        &self,
        payload: std::sync::Arc<dyn cose_sign1_primitives::StreamingPayload>,
        content_type: &str,
        options: Option<IndirectSignatureOptions>,
    ) -> Result<CoseSign1Message, FactoryError> {
        let bytes = self.create_streaming_bytes(payload, content_type, options)?;
        CoseSign1Message::parse(&bytes).map_err(|e| FactoryError::SigningFailed(e.to_string()))
    }
}
