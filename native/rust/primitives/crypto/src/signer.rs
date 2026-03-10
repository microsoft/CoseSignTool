// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Signing traits for cryptographic backends.

use crate::error::CryptoError;

/// A cryptographic signer. Backend-agnostic — knows nothing about COSE.
///
/// Implementations: OpenSSL EvpSigner, AKV remote signer, callback signer.
pub trait CryptoSigner: Send + Sync {
    /// Sign the given data bytes. For COSE, this is the complete Sig_structure.
    fn sign(&self, data: &[u8]) -> Result<Vec<u8>, CryptoError>;

    /// COSE algorithm identifier (e.g., -7 for ES256).
    fn algorithm(&self) -> i64;

    /// Optional key identifier bytes.
    fn key_id(&self) -> Option<&[u8]> {
        None
    }

    /// Human-readable key type (e.g., "EC", "RSA", "Ed25519", "ML-DSA-44").
    fn key_type(&self) -> &str;

    /// Whether this signer supports streaming via `sign_init()`.
    fn supports_streaming(&self) -> bool {
        false
    }

    /// Begin a streaming sign operation.
    /// Returns a `SigningContext` that accepts data chunks.
    fn sign_init(&self) -> Result<Box<dyn SigningContext>, CryptoError> {
        Err(CryptoError::UnsupportedOperation(
            "streaming not supported by this signer".into(),
        ))
    }
}

/// Streaming signing context: init -> update(chunk)* -> finalize() -> signature.
///
/// The builder feeds Sig_structure bytes through this:
/// 1. update(cbor_prefix)  — array header + context + headers + aad + bstr header
/// 2. update(payload_chunk) * N — raw payload bytes
/// 3. finalize() — produces the signature
pub trait SigningContext: Send {
    /// Feed a chunk of data to the signer.
    fn update(&mut self, chunk: &[u8]) -> Result<(), CryptoError>;

    /// Finalize and produce the signature.
    fn finalize(self: Box<Self>) -> Result<Vec<u8>, CryptoError>;
}
