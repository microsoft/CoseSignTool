// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Crypto provider singleton.
//!
//! This is a stub that always returns NullCryptoProvider.
//! Callers that need real crypto should use crypto_primitives directly
//! and construct their own signers/verifiers from keys.

use crypto_primitives::provider::NullCryptoProvider;
use std::sync::OnceLock;

/// The crypto provider type (always NullCryptoProvider).
pub type CryptoProviderImpl = NullCryptoProvider;

static PROVIDER: OnceLock<CryptoProviderImpl> = OnceLock::new();

/// Returns a reference to the crypto provider singleton (NullCryptoProvider).
///
/// This is a stub. Real crypto implementations should use crypto_primitives
/// directly to construct signers/verifiers from keys.
pub fn crypto_provider() -> &'static CryptoProviderImpl {
    PROVIDER.get_or_init(CryptoProviderImpl::default)
}
