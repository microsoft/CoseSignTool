// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Signing key provider — maps V2 ISigningKeyProvider.
//! Separates certificate management from how signing is performed.

use crypto_primitives::CryptoSigner;

/// Provides the actual signing operation abstraction.
/// Maps V2 `ISigningKeyProvider`.
///
/// Implementations:
/// - `DirectSigningKeyProvider`: Uses X.509 private key directly (local)
/// - Remote: Delegates to remote signing services
pub trait SigningKeyProvider: CryptoSigner {
    /// Whether this is a remote signing provider.
    fn is_remote(&self) -> bool;
}
