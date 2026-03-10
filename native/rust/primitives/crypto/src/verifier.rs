// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Verification traits for cryptographic backends.

use crate::error::CryptoError;

/// A cryptographic verifier. Backend-agnostic — knows nothing about COSE.
///
/// Implementations: OpenSSL EvpVerifier, X.509 certificate verifier, callback verifier.
pub trait CryptoVerifier: Send + Sync {
    /// Verify the given signature against data bytes.
    /// For COSE, data is the complete Sig_structure.
    ///
    /// # Returns
    /// - `Ok(true)` if signature is valid
    /// - `Ok(false)` if signature is invalid
    /// - `Err(_)` if verification could not be performed
    fn verify(&self, data: &[u8], signature: &[u8]) -> Result<bool, CryptoError>;

    /// COSE algorithm identifier (e.g., -7 for ES256).
    fn algorithm(&self) -> i64;

    /// Whether this verifier supports streaming via `verify_init()`.
    fn supports_streaming(&self) -> bool {
        false
    }

    /// Begin a streaming verification operation.
    /// Returns a `VerifyingContext` that accepts data chunks.
    fn verify_init(&self, _signature: &[u8]) -> Result<Box<dyn VerifyingContext>, CryptoError> {
        Err(CryptoError::UnsupportedOperation(
            "streaming not supported by this verifier".into(),
        ))
    }
}

/// Streaming verification context: init(sig) -> update(chunk)* -> finalize() -> bool.
///
/// The validator feeds Sig_structure bytes through this:
/// 1. update(cbor_prefix)  — array header + context + headers + aad + bstr header
/// 2. update(payload_chunk) * N — raw payload bytes
/// 3. finalize() — returns true if signature is valid
pub trait VerifyingContext: Send {
    /// Feed a chunk of data to the verifier.
    fn update(&mut self, chunk: &[u8]) -> Result<(), CryptoError>;

    /// Finalize and return verification result.
    ///
    /// # Returns
    /// - `Ok(true)` if signature is valid
    /// - `Ok(false)` if signature is invalid
    /// - `Err(_)` if verification could not be completed
    fn finalize(self: Box<Self>) -> Result<bool, CryptoError>;
}
