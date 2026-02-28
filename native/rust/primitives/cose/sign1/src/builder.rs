// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Builder for creating COSE_Sign1 messages.
//!
//! Provides a fluent API for constructing and signing COSE_Sign1 messages.
//! Uses the compile-time-selected CBOR provider — no provider parameter needed.

use std::sync::Arc;

use cbor_primitives::{CborEncoder, CborProvider};
use crypto_primitives::CryptoSigner;

use crate::algorithms::COSE_SIGN1_TAG;
use crate::error::{CoseKeyError, CoseSign1Error};
use crate::headers::CoseHeaderMap;
use crate::payload::StreamingPayload;
use crate::provider::cbor_provider;
use crate::sig_structure::{build_sig_structure, build_sig_structure_prefix};

/// Maximum payload size for embedding (2 GB).
pub const MAX_EMBED_PAYLOAD_SIZE: u64 = 2 * 1024 * 1024 * 1024;

/// Builder for creating COSE_Sign1 messages.
///
/// # Example
///
/// ```ignore
/// use cose_sign1_primitives::{CoseSign1Builder, CoseHeaderMap, algorithms};
///
/// let mut protected = CoseHeaderMap::new();
/// protected.set_alg(algorithms::ES256);
///
/// let message = CoseSign1Builder::new()
///     .protected(protected)
///     .sign(&signer, b"Hello, World!")?;
/// ```
#[derive(Clone, Debug, Default)]
pub struct CoseSign1Builder {
    protected: CoseHeaderMap,
    unprotected: Option<CoseHeaderMap>,
    external_aad: Option<Vec<u8>>,
    detached: bool,
    tagged: bool,
    max_embed_size: u64,
}

impl CoseSign1Builder {
    /// Creates a new builder with default settings.
    pub fn new() -> Self {
        Self {
            protected: CoseHeaderMap::new(),
            unprotected: None,
            external_aad: None,
            detached: false,
            tagged: true,
            max_embed_size: MAX_EMBED_PAYLOAD_SIZE,
        }
    }

    /// Sets the protected headers.
    pub fn protected(mut self, headers: CoseHeaderMap) -> Self {
        self.protected = headers;
        self
    }

    /// Sets the unprotected headers.
    pub fn unprotected(mut self, headers: CoseHeaderMap) -> Self {
        self.unprotected = Some(headers);
        self
    }

    /// Sets external additional authenticated data.
    pub fn external_aad(mut self, aad: impl Into<Vec<u8>>) -> Self {
        self.external_aad = Some(aad.into());
        self
    }

    /// Sets whether the payload should be detached.
    pub fn detached(mut self, detached: bool) -> Self {
        self.detached = detached;
        self
    }

    /// Sets whether to include the CBOR tag (18) in the output. Default is true.
    pub fn tagged(mut self, tagged: bool) -> Self {
        self.tagged = tagged;
        self
    }

    /// Sets the maximum payload size for embedding.
    pub fn max_embed_size(mut self, size: u64) -> Self {
        self.max_embed_size = size;
        self
    }

    /// Signs the payload and returns the COSE_Sign1 message bytes.
    pub fn sign(
        self,
        signer: &dyn CryptoSigner,
        payload: &[u8],
    ) -> Result<Vec<u8>, CoseSign1Error> {
        let protected_bytes = self.protected_bytes()?;
        let external_aad = self.external_aad.as_deref();
        let sig_structure = build_sig_structure(&protected_bytes, external_aad, payload)?;
        let signature = signer.sign(&sig_structure).map_err(CoseKeyError::from)?;
        self.build_message(protected_bytes, payload, signature)
    }

    fn protected_bytes(&self) -> Result<Vec<u8>, CoseSign1Error> {
        if self.protected.is_empty() {
            Ok(Vec::new())
        } else {
            Ok(self.protected.encode()?)
        }
    }

    /// Signs a streaming payload and returns the COSE_Sign1 message bytes.
    pub fn sign_streaming(
        self,
        signer: &dyn CryptoSigner,
        payload: Arc<dyn StreamingPayload>,
    ) -> Result<Vec<u8>, CoseSign1Error> {
        let protected_bytes = self.protected_bytes()?;
        let payload_len = payload.size();
        let external_aad = self.external_aad.as_deref();

        // Enforce embed size limit
        if !self.detached && payload_len > self.max_embed_size {
            return Err(CoseSign1Error::PayloadTooLargeForEmbedding(
                payload_len,
                self.max_embed_size,
            ));
        }

        let prefix = build_sig_structure_prefix(&protected_bytes, external_aad, payload_len)?;

        let signature = if signer.supports_streaming() {
            let mut ctx = signer.sign_init().map_err(CoseKeyError::from)?;
            ctx.update(&prefix).map_err(CoseKeyError::from)?;
            let mut reader = payload.open().map_err(CoseSign1Error::from)?;
            let mut buf = vec![0u8; 65536];
            loop {
                let n = std::io::Read::read(reader.as_mut(), &mut buf)
                    .map_err(|e| CoseSign1Error::IoError(e.to_string()))?;
                if n == 0 {
                    break;
                }
                ctx.update(&buf[..n]).map_err(CoseKeyError::from)?;
            }
            ctx.finalize().map_err(CoseKeyError::from)?
        } else {
            // Fallback: buffer payload, build full sig_structure
            let mut reader = payload.open().map_err(CoseSign1Error::from)?;
            let mut payload_bytes = Vec::new();
            std::io::Read::read_to_end(reader.as_mut(), &mut payload_bytes)
                .map_err(|e| CoseSign1Error::IoError(e.to_string()))?;
            let sig_structure = build_sig_structure(&protected_bytes, external_aad, &payload_bytes)?;
            signer.sign(&sig_structure).map_err(CoseKeyError::from)?
        };

        // For embedded: re-read payload for message body
        let embed_payload = if self.detached {
            None
        } else {
            let mut reader = payload.open().map_err(CoseSign1Error::from)?;
            let mut buf = Vec::with_capacity(payload_len as usize);
            std::io::Read::read_to_end(reader.as_mut(), &mut buf)
                .map_err(|e| CoseSign1Error::IoError(e.to_string()))?;
            Some(buf)
        };

        self.build_message_opt(protected_bytes, embed_payload.as_deref(), signature)
    }

    fn build_message_opt(
        &self,
        protected_bytes: Vec<u8>,
        payload: Option<&[u8]>,
        signature: Vec<u8>,
    ) -> Result<Vec<u8>, CoseSign1Error> {
        let provider = cbor_provider();
        let mut encoder = provider.encoder();

        if self.tagged {
            encoder
                .encode_tag(COSE_SIGN1_TAG)
                .map_err(|e| CoseSign1Error::CborError(e.to_string()))?;
        }

        encoder
            .encode_array(4)
            .map_err(|e| CoseSign1Error::CborError(e.to_string()))?;
        encoder
            .encode_bstr(&protected_bytes)
            .map_err(|e| CoseSign1Error::CborError(e.to_string()))?;

        let unprotected_bytes = match &self.unprotected {
            Some(headers) => headers.encode()?,
            None => {
                let mut map_encoder = provider.encoder();
                map_encoder
                    .encode_map(0)
                    .map_err(|e| CoseSign1Error::CborError(e.to_string()))?;
                map_encoder.into_bytes()
            }
        };
        encoder
            .encode_raw(&unprotected_bytes)
            .map_err(|e| CoseSign1Error::CborError(e.to_string()))?;

        match payload {
            Some(p) => encoder
                .encode_bstr(p)
                .map_err(|e| CoseSign1Error::CborError(e.to_string()))?,
            None => encoder
                .encode_null()
                .map_err(|e| CoseSign1Error::CborError(e.to_string()))?,
        }

        encoder
            .encode_bstr(&signature)
            .map_err(|e| CoseSign1Error::CborError(e.to_string()))?;

        Ok(encoder.into_bytes())
    }

    fn build_message(
        &self,
        protected_bytes: Vec<u8>,
        payload: &[u8],
        signature: Vec<u8>,
    ) -> Result<Vec<u8>, CoseSign1Error> {
        let provider = cbor_provider();
        let mut encoder = provider.encoder();

        if self.tagged {
            encoder.encode_tag(COSE_SIGN1_TAG)
                .map_err(|e| CoseSign1Error::CborError(e.to_string()))?;
        }

        encoder.encode_array(4)
            .map_err(|e| CoseSign1Error::CborError(e.to_string()))?;
        encoder.encode_bstr(&protected_bytes)
            .map_err(|e| CoseSign1Error::CborError(e.to_string()))?;

        let unprotected_bytes = match &self.unprotected {
            Some(headers) => headers.encode()?,
            None => {
                let mut map_encoder = provider.encoder();
                map_encoder.encode_map(0)
                    .map_err(|e| CoseSign1Error::CborError(e.to_string()))?;
                map_encoder.into_bytes()
            }
        };
        encoder.encode_raw(&unprotected_bytes)
            .map_err(|e| CoseSign1Error::CborError(e.to_string()))?;

        if self.detached {
            encoder.encode_null()
                .map_err(|e| CoseSign1Error::CborError(e.to_string()))?;
        } else {
            encoder.encode_bstr(payload)
                .map_err(|e| CoseSign1Error::CborError(e.to_string()))?;
        }

        encoder.encode_bstr(&signature)
            .map_err(|e| CoseSign1Error::CborError(e.to_string()))?;

        Ok(encoder.into_bytes())
    }
}
