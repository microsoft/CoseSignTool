// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Coverage tests for crypto provider singleton.

use cose_sign1_primitives::crypto_provider::{crypto_provider, CryptoProviderImpl};
use crypto_primitives::CryptoProvider;

#[test]
fn test_crypto_provider_singleton() {
    let provider1 = crypto_provider();
    let provider2 = crypto_provider();

    // Should return the same instance (singleton)
    assert!(std::ptr::eq(provider1, provider2));
}

#[test]
fn test_crypto_provider_is_null() {
    let provider = crypto_provider();

    // Should be NullCryptoProvider
    assert_eq!(provider.name(), "null");
}

#[test]
fn test_crypto_provider_impl_type() {
    let provider: CryptoProviderImpl = Default::default();
    assert_eq!(provider.name(), "null");

    // Should return errors for signer/verifier creation
    let signer_result = provider.signer_from_der(b"fake key");
    assert!(signer_result.is_err());

    let verifier_result = provider.verifier_from_der(b"fake key");
    assert!(verifier_result.is_err());
}

#[test]
fn test_crypto_provider_concurrent_access() {
    use std::thread;

    let handles: Vec<_> = (0..4)
        .map(|_| thread::spawn(|| crypto_provider().name()))
        .collect();

    let results: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();

    // All threads should get the same provider
    assert!(results.iter().all(|&name| name == "null"));
}
