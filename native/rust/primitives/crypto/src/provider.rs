// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Crypto provider trait and default implementations.

use crate::error::CryptoError;
use crate::signer::CryptoSigner;
use crate::verifier::CryptoVerifier;

/// A cryptographic backend provider.
///
/// Implementations: OpenSSL provider, Ring provider, BoringSSL provider.
pub trait CryptoProvider: Send + Sync {
    /// Create a signer from PKCS#8 DER-encoded private key.
    fn signer_from_der(&self, private_key_der: &[u8])
        -> Result<Box<dyn CryptoSigner>, CryptoError>;

    /// Create a verifier from SubjectPublicKeyInfo DER-encoded public key.
    fn verifier_from_der(
        &self,
        public_key_der: &[u8],
    ) -> Result<Box<dyn CryptoVerifier>, CryptoError>;

    /// Provider name for diagnostics.
    fn name(&self) -> &str;
}

/// Stub provider when no crypto feature is enabled.
///
/// All operations return `UnsupportedOperation` errors.
/// This allows compilation when no crypto backend is selected.
#[derive(Default)]
pub struct NullCryptoProvider;

impl CryptoProvider for NullCryptoProvider {
    fn signer_from_der(&self, _: &[u8]) -> Result<Box<dyn CryptoSigner>, CryptoError> {
        Err(CryptoError::UnsupportedOperation(
            "no crypto provider enabled".into(),
        ))
    }

    fn verifier_from_der(&self, _: &[u8]) -> Result<Box<dyn CryptoVerifier>, CryptoError> {
        Err(CryptoError::UnsupportedOperation(
            "no crypto provider enabled".into(),
        ))
    }

    fn name(&self) -> &str {
        "null"
    }
}
