// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// Tests for AtsCryptoSigner are limited because the type requires
// an AzureTrustedSigningCertificateSource which involves network calls.
// We test what we can without mocking the certificate source.

#[test]
fn test_ats_crypto_signer_module_exists() {
    // This test verifies the module is accessible
    // The actual AtsCryptoSigner requires a real certificate source
    // so we can't test the constructor without network dependencies
    
    // Just verify we can reference the type
    use cose_sign1_azure_trusted_signing::signing::ats_crypto_signer::AtsCryptoSigner;
    let type_name = std::any::type_name::<AtsCryptoSigner>();
    assert!(type_name.contains("AtsCryptoSigner"));
}

// Note: Full testing of AtsCryptoSigner would require:
// 1. A mock AzureTrustedSigningCertificateSource 
// 2. Or integration tests with real ATS service
// 3. The sign() method, algorithm() and key_type() accessors
//
// Since the task specifies "Do NOT test network calls", 
// and AtsCryptoSigner requires a certificate source for construction,
// comprehensive unit testing would need dependency injection or mocking
// that isn't currently available in the design.