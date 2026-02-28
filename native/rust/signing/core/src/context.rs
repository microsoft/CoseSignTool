// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Signing context and payload types.

use cose_sign1_primitives::SizedRead;

/// Payload to be signed.
///
/// Maps V2 payload handling in `ISigningService`.
pub enum SigningPayload {
    /// In-memory payload bytes.
    Bytes(Vec<u8>),
    /// Streaming payload with known length.
    Stream(Box<dyn SizedRead + Send>),
}

/// Context for a signing operation.
///
/// Maps V2 signing context passed to `ISigningService.GetSignerAsync()`.
pub struct SigningContext {
    /// The payload to be signed.
    pub payload: SigningPayload,
    /// Content type of the payload (COSE header 3).
    pub content_type: Option<String>,
    /// Additional header contributors for this signing operation.
    pub additional_header_contributors: Vec<Box<dyn crate::HeaderContributor>>,
}

impl SigningContext {
    /// Creates a signing context from in-memory bytes.
    pub fn from_bytes(payload: Vec<u8>) -> Self {
        Self {
            payload: SigningPayload::Bytes(payload),
            content_type: None,
            additional_header_contributors: Vec::new(),
        }
    }

    /// Creates a signing context from a streaming payload.
    pub fn from_stream(stream: Box<dyn SizedRead + Send>) -> Self {
        Self {
            payload: SigningPayload::Stream(stream),
            content_type: None,
            additional_header_contributors: Vec::new(),
        }
    }

    /// Returns the payload as bytes if available.
    ///
    /// Returns `None` for streaming payloads.
    pub fn payload_bytes(&self) -> Option<&[u8]> {
        match &self.payload {
            SigningPayload::Bytes(b) => Some(b),
            SigningPayload::Stream(_) => None,
        }
    }

    /// Checks if the payload is a stream.
    pub fn has_stream(&self) -> bool {
        matches!(self.payload, SigningPayload::Stream(_))
    }
}
