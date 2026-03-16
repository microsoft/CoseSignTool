// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Compile-time crypto provider selection.
//!
//! The active provider is selected by Cargo feature flags:
//! - `crypto-openssl` → OpenSSL-based provider

use crypto_primitives::CryptoProvider;

/// Get the active crypto provider based on compile-time feature selection.
#[cfg(feature = "crypto-openssl")]
pub fn active_provider() -> Box<dyn CryptoProvider> {
    Box::new(cose_sign1_crypto_openssl::OpenSslCryptoProvider)
}

/// Get the active crypto provider based on compile-time feature selection.
#[cfg(not(feature = "crypto-openssl"))]
pub fn active_provider() -> Box<dyn CryptoProvider> {
    panic!("At least one crypto provider feature must be enabled (e.g., crypto-openssl)")
}
