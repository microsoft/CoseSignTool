// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! COSE signer and header contribution.

use cose_sign1_primitives::CoseHeaderMap;
use crypto_primitives::CryptoSigner;

use crate::{SigningContext, SigningError};

/// Strategy for merging contributed headers.
///
/// Maps V2 header merge behavior.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HeaderMergeStrategy {
    /// Fail if a header with the same label already exists.
    Fail,
    /// Keep existing header value, ignore contributed value.
    KeepExisting,
    /// Replace existing header value with contributed value.
    Replace,
    /// Custom merge logic (implementation-defined).
    Custom,
}

/// Context for header contribution.
///
/// Provides access to signing context and key metadata during header contribution.
pub struct HeaderContributorContext<'a> {
    /// Reference to the signing context.
    pub signing_context: &'a SigningContext<'a>,
    /// Reference to the signing key.
    pub signing_key: &'a dyn CryptoSigner,
}

impl<'a> HeaderContributorContext<'a> {
    /// Creates a new header contributor context.
    pub fn new(signing_context: &'a SigningContext<'a>, signing_key: &'a dyn CryptoSigner) -> Self {
        Self {
            signing_context,
            signing_key,
        }
    }
}

/// A COSE signer that combines a key with header maps.
///
/// Maps V2 signer construction in `DirectSignatureFactory`.
pub struct CoseSigner {
    /// The cryptographic signer for signing operations.
    signer: Box<dyn CryptoSigner>,
    /// Protected headers to include in the signature.
    protected_headers: CoseHeaderMap,
    /// Unprotected headers (not covered by signature).
    unprotected_headers: CoseHeaderMap,
}

impl CoseSigner {
    /// Creates a new signer.
    pub fn new(
        signer: Box<dyn CryptoSigner>,
        protected_headers: CoseHeaderMap,
        unprotected_headers: CoseHeaderMap,
    ) -> Self {
        Self {
            signer,
            protected_headers,
            unprotected_headers,
        }
    }

    /// Returns a reference to the signing key.
    pub fn signer(&self) -> &dyn CryptoSigner {
        &*self.signer
    }

    /// Returns a reference to the protected headers.
    pub fn protected_headers(&self) -> &CoseHeaderMap {
        &self.protected_headers
    }

    /// Returns a reference to the unprotected headers.
    pub fn unprotected_headers(&self) -> &CoseHeaderMap {
        &self.unprotected_headers
    }

    /// Signs a payload with the configured headers.
    ///
    /// This is a convenience method that builds the Sig_structure and
    /// delegates to the signer's sign method.
    pub fn sign_payload(
        &self,
        payload: &[u8],
        external_aad: Option<&[u8]>,
    ) -> Result<Vec<u8>, SigningError> {
        use cose_sign1_primitives::build_sig_structure;

        let protected_bytes =
            self.protected_headers
                .encode()
                .map_err(|e| SigningError::SigningFailed {
                    detail: format!("Failed to encode protected headers: {}", e).into(),
                })?;

        let sig_structure =
            build_sig_structure(&protected_bytes, external_aad, payload).map_err(|e| {
                SigningError::SigningFailed {
                    detail: format!("Failed to build Sig_structure: {}", e).into(),
                }
            })?;

        self.signer
            .sign(&sig_structure)
            .map_err(|e| SigningError::SigningFailed {
                detail: format!("Signing failed: {}", e).into(),
            })
    }
}
