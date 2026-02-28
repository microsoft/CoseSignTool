// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use cose_sign1_azure_trusted_signing::options::AzureTrustedSigningOptions;

#[test]
fn test_azure_trusted_signing_options_construction() {
    let options = AzureTrustedSigningOptions {
        endpoint: "https://eus.codesigning.azure.net".to_string(),
        account_name: "test-account".to_string(),
        certificate_profile_name: "test-profile".to_string(),
    };

    assert_eq!(options.endpoint, "https://eus.codesigning.azure.net");
    assert_eq!(options.account_name, "test-account");
    assert_eq!(options.certificate_profile_name, "test-profile");
}

#[test]
fn test_azure_trusted_signing_options_clone() {
    let original = AzureTrustedSigningOptions {
        endpoint: "https://eus.codesigning.azure.net".to_string(),
        account_name: "test-account".to_string(),
        certificate_profile_name: "test-profile".to_string(),
    };

    let cloned = original.clone();

    assert_eq!(original.endpoint, cloned.endpoint);
    assert_eq!(original.account_name, cloned.account_name);
    assert_eq!(original.certificate_profile_name, cloned.certificate_profile_name);
}

#[test]
fn test_azure_trusted_signing_options_debug() {
    let options = AzureTrustedSigningOptions {
        endpoint: "https://eus.codesigning.azure.net".to_string(),
        account_name: "test-account".to_string(),
        certificate_profile_name: "test-profile".to_string(),
    };

    let debug_str = format!("{:?}", options);
    assert!(debug_str.contains("AzureTrustedSigningOptions"));
    assert!(debug_str.contains("eus.codesigning.azure.net"));
    assert!(debug_str.contains("test-account"));
    assert!(debug_str.contains("test-profile"));
}