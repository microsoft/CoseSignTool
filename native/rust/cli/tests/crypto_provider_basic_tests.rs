// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Basic unit tests for CLI crypto provider.

use cose_sign1_cli::providers::crypto;

#[test]
fn test_active_provider_exists() {
    // This test verifies that the active_provider function returns something
    // and doesn't panic (when OpenSSL feature is enabled)
    #[cfg(feature = "crypto-openssl")]
    {
        let provider = crypto::active_provider();
        // Just verify we got a provider back by checking that it's not null
        // We can't compare the contents directly, but we can verify it doesn't panic
        drop(provider);
    }
}

#[test]
#[cfg(not(feature = "crypto-openssl"))]
#[should_panic(expected = "At least one crypto provider feature must be enabled")]
fn test_active_provider_panics_without_features() {
    // This test verifies the panic behavior when no crypto features are enabled
    let _provider = crypto::active_provider();
}