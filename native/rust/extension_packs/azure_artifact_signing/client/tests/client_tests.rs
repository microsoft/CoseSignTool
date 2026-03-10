// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use azure_artifact_signing_client::{CertificateProfileClientOptions, API_VERSION};

#[test]
fn test_certificate_profile_client_options_new_with_various_inputs() {
    // Test with String inputs
    let opts1 = CertificateProfileClientOptions::new(
        "https://eus.codesigning.azure.net".to_string(),
        "my-account".to_string(),
        "my-profile".to_string(),
    );
    
    assert_eq!(opts1.endpoint, "https://eus.codesigning.azure.net");
    assert_eq!(opts1.account_name, "my-account");
    assert_eq!(opts1.certificate_profile_name, "my-profile");
    assert_eq!(opts1.api_version, API_VERSION);
    
    // Test with &str inputs
    let opts2 = CertificateProfileClientOptions::new(
        "https://weu.codesigning.azure.net",
        "test-account",
        "test-profile",
    );
    
    assert_eq!(opts2.endpoint, "https://weu.codesigning.azure.net");
    assert_eq!(opts2.account_name, "test-account");
    assert_eq!(opts2.certificate_profile_name, "test-profile");
    assert_eq!(opts2.api_version, API_VERSION);
}

#[test]
fn test_base_url_for_different_regions() {
    let test_cases = vec![
        (
            "https://eus.codesigning.azure.net",
            "my-account", 
            "my-profile",
            "https://eus.codesigning.azure.net/codesigningaccounts/my-account/certificateprofiles/my-profile"
        ),
        (
            "https://weu.codesigning.azure.net",
            "test-account",
            "test-profile", 
            "https://weu.codesigning.azure.net/codesigningaccounts/test-account/certificateprofiles/test-profile"
        ),
        (
            "https://neu.codesigning.azure.net/",
            "another-account",
            "another-profile",
            "https://neu.codesigning.azure.net/codesigningaccounts/another-account/certificateprofiles/another-profile"
        ),
        (
            "https://scus.codesigning.azure.net",
            "final-account",
            "final-profile",
            "https://scus.codesigning.azure.net/codesigningaccounts/final-account/certificateprofiles/final-profile"
        ),
    ];
    
    for (endpoint, account, profile, expected) in test_cases {
        let opts = CertificateProfileClientOptions::new(endpoint, account, profile);
        assert_eq!(opts.base_url(), expected);
    }
}

#[test]
fn test_auth_scope_for_different_endpoints() {
    let test_cases = vec![
        ("https://eus.codesigning.azure.net", "https://eus.codesigning.azure.net/.default"),
        ("https://weu.codesigning.azure.net/", "https://weu.codesigning.azure.net/.default"),
        ("https://neu.codesigning.azure.net", "https://neu.codesigning.azure.net/.default"),
        ("https://custom.endpoint.com", "https://custom.endpoint.com/.default"),
        ("https://custom.endpoint.com/", "https://custom.endpoint.com/.default"),
    ];
    
    for (endpoint, expected_scope) in test_cases {
        let opts = CertificateProfileClientOptions::new(endpoint, "account", "profile");
        assert_eq!(opts.auth_scope(), expected_scope);
    }
}

#[test]
fn test_api_version_constant() {
    let opts = CertificateProfileClientOptions::new(
        "https://eus.codesigning.azure.net",
        "my-account",
        "my-profile",
    );
    
    // Verify API_VERSION constant value matches expected
    assert_eq!(opts.api_version, "2022-06-15-preview");
    assert_eq!(API_VERSION, "2022-06-15-preview");
}

#[test]
fn test_optional_fields_default_to_none() {
    let opts = CertificateProfileClientOptions::new(
        "https://eus.codesigning.azure.net",
        "my-account",
        "my-profile",
    );
    
    assert!(opts.correlation_id.is_none());
    assert!(opts.client_version.is_none());
}

#[test]
fn test_endpoint_slash_trimming() {
    // Test various slash combinations
    let test_cases = vec![
        ("https://example.com", "https://example.com/codesigningaccounts/acc/certificateprofiles/prof"),
        ("https://example.com/", "https://example.com/codesigningaccounts/acc/certificateprofiles/prof"),
        ("https://example.com//", "https://example.com/codesigningaccounts/acc/certificateprofiles/prof"),
        ("https://example.com///", "https://example.com/codesigningaccounts/acc/certificateprofiles/prof"),
    ];
    
    for (endpoint, expected_base_url) in test_cases {
        let opts = CertificateProfileClientOptions::new(endpoint, "acc", "prof");
        assert_eq!(opts.base_url(), expected_base_url);
        
        // Auth scope should also trim properly
        assert_eq!(opts.auth_scope(), "https://example.com/.default");
    }
}

#[test]
fn test_special_characters_in_account_and_profile_names() {
    let opts = CertificateProfileClientOptions::new(
        "https://eus.codesigning.azure.net",
        "my-account-with-dashes_and_underscores",
        "profile.with.dots-and-dashes",
    );
    
    let expected = "https://eus.codesigning.azure.net/codesigningaccounts/my-account-with-dashes_and_underscores/certificateprofiles/profile.with.dots-and-dashes";
    assert_eq!(opts.base_url(), expected);
    
    // Auth scope should remain unchanged
    assert_eq!(opts.auth_scope(), "https://eus.codesigning.azure.net/.default");
}

#[test]
fn test_clone_and_debug_traits() {
    let opts = CertificateProfileClientOptions::new(
        "https://eus.codesigning.azure.net",
        "my-account",
        "my-profile",
    );
    
    // Test Clone trait
    let cloned_opts = opts.clone();
    assert_eq!(opts.endpoint, cloned_opts.endpoint);
    assert_eq!(opts.account_name, cloned_opts.account_name);
    assert_eq!(opts.certificate_profile_name, cloned_opts.certificate_profile_name);
    assert_eq!(opts.api_version, cloned_opts.api_version);
    
    // Test Debug trait (just verify it doesn't panic)
    let debug_str = format!("{:?}", opts);
    assert!(debug_str.contains("CertificateProfileClientOptions"));
    assert!(debug_str.contains("my-account"));
    assert!(debug_str.contains("my-profile"));
}