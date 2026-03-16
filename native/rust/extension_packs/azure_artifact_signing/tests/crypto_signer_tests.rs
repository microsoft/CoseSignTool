// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// Tests for AasCryptoSigner are limited because the type requires
// an AzureArtifactSigningCertificateSource which involves network calls.
// We test what we can without mocking the certificate source.

#[test]
fn test_ats_crypto_signer_module_exists() {
    // This test verifies the module is accessible
    // The actual AasCryptoSigner requires a real certificate source
    // so we can't test the constructor without network dependencies
    
    // Just verify we can reference the type
    use cose_sign1_azure_artifact_signing::signing::aas_crypto_signer::AasCryptoSigner;
    let type_name = std::any::type_name::<AasCryptoSigner>();
    assert!(type_name.contains("AasCryptoSigner"));
}

// Note: Full testing of AasCryptoSigner would require:
// 1. A mock AzureArtifactSigningCertificateSource 
// 2. Or integration tests with real AAS service
// 3. The sign() method, algorithm() and key_type() accessors
//
// Since the task specifies "Do NOT test network calls", 
// and AasCryptoSigner requires a certificate source for construction,
// comprehensive unit testing would need dependency injection or mocking
// that isn't currently available in the design.
