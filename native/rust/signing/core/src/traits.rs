// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Core signing traits.

use cose_sign1_primitives::CoseHeaderMap;
use crypto_primitives::CryptoSigner;

use crate::{
    CoseSigner, HeaderMergeStrategy, SigningContext, SigningError, SigningKeyMetadata,
    SigningServiceMetadata,
};

/// Signing service trait.
///
/// Maps V2 `ISigningService<TSigningOptions>`.
pub trait SigningService: Send + Sync {
    /// Gets a signer for the given signing context.
    ///
    /// Maps V2 `GetSignerAsync()`.
    fn get_cose_signer(&self, context: &SigningContext) -> Result<CoseSigner, SigningError>;

    /// Returns whether this is a remote signing service.
    fn is_remote(&self) -> bool;

    /// Returns metadata about this signing service.
    fn service_metadata(&self) -> &SigningServiceMetadata;

    /// Verifies a signature on a message.
    ///
    /// Maps V2 `ISigningService.VerifySignature()`.
    ///
    /// # Arguments
    ///
    /// * `message_bytes` - The complete COSE_Sign1 message bytes
    /// * `context` - The signing context used when creating the signature
    fn verify_signature(
        &self,
        message_bytes: &[u8],
        context: &SigningContext,
    ) -> Result<bool, SigningError>;
}

/// Signing key with service context.
///
/// Maps V2 `ISigningServiceKey`.
pub trait SigningServiceKey: CryptoSigner {
    /// Returns metadata about this signing key.
    fn metadata(&self) -> &SigningKeyMetadata;
}

/// Header contributor trait.
///
/// Maps V2 `IHeaderContributor`.
pub trait HeaderContributor: Send + Sync {
    /// Returns the merge strategy for this contributor.
    fn merge_strategy(&self) -> HeaderMergeStrategy;

    /// Contributes to protected headers.
    ///
    /// # Arguments
    ///
    /// * `headers` - The protected header map to contribute to
    /// * `context` - The header contributor context
    fn contribute_protected_headers(
        &self,
        headers: &mut CoseHeaderMap,
        context: &crate::HeaderContributorContext,
    );

    /// Contributes to unprotected headers.
    ///
    /// # Arguments
    ///
    /// * `headers` - The unprotected header map to contribute to
    /// * `context` - The header contributor context
    fn contribute_unprotected_headers(
        &self,
        headers: &mut CoseHeaderMap,
        context: &crate::HeaderContributorContext,
    );
}
