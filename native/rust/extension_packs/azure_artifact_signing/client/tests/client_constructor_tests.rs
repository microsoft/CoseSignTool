// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use azure_artifact_signing_client::{
    CertificateProfileClientCreateOptions, CertificateProfileClientOptions,
};
use azure_core::http::ClientOptions;

#[test]
fn test_certificate_profile_client_options_new_variations() {
    // Test with different endpoint formats
    let test_cases = vec![
        ("https://eus.codesigning.azure.net", "account1", "profile1"),
        (
            "https://weu.codesigning.azure.net/",
            "account-with-dash",
            "profile_with_underscore",
        ),
        (
            "https://custom.domain.com",
            "account.with.dots",
            "profile-final",
        ),
    ];

    for (endpoint, account, profile) in test_cases {
        let options = CertificateProfileClientOptions::new(endpoint, account, profile);
        assert_eq!(options.endpoint, endpoint);
        assert_eq!(options.account_name, account);
        assert_eq!(options.certificate_profile_name, profile);
        assert_eq!(options.api_version, "2022-06-15-preview");
        assert!(options.correlation_id.is_none());
        assert!(options.client_version.is_none());
    }
}

#[test]
fn test_certificate_profile_client_options_base_url_edge_cases() {
    // Test various endpoint URL edge cases
    let test_cases = vec![
        // Basic case
        ("https://test.com", "acc", "prof", "https://test.com/codesigningaccounts/acc/certificateprofiles/prof"),
        // Trailing slash
        ("https://test.com/", "acc", "prof", "https://test.com/codesigningaccounts/acc/certificateprofiles/prof"),
        // Multiple trailing slashes
        ("https://test.com//", "acc", "prof", "https://test.com/codesigningaccounts/acc/certificateprofiles/prof"),
        // Complex names
        ("https://test.com", "my-account_123", "profile.v2-final", "https://test.com/codesigningaccounts/my-account_123/certificateprofiles/profile.v2-final"),
    ];

    for (endpoint, account, profile, expected) in test_cases {
        let options = CertificateProfileClientOptions::new(endpoint, account, profile);
        assert_eq!(options.base_url(), expected);
    }
}

#[test]
fn test_certificate_profile_client_options_auth_scope_edge_cases() {
    // Test auth scope generation with various endpoints
    let test_cases = vec![
        ("https://example.com", "https://example.com/.default"),
        ("https://example.com/", "https://example.com/.default"),
        ("https://example.com//", "https://example.com/.default"),
        ("https://sub.domain.com", "https://sub.domain.com/.default"),
        (
            "https://api.service.azure.net",
            "https://api.service.azure.net/.default",
        ),
    ];

    for (endpoint, expected_scope) in test_cases {
        let options = CertificateProfileClientOptions::new(endpoint, "acc", "prof");
        assert_eq!(options.auth_scope(), expected_scope);
    }
}

#[test]
fn test_certificate_profile_client_create_options_default() {
    let options = CertificateProfileClientCreateOptions::default();
    // Just verify it compiles and has the expected structure
    let _client_options = options.client_options;
}

#[test]
fn test_certificate_profile_client_create_options_clone_debug() {
    let options = CertificateProfileClientCreateOptions {
        client_options: ClientOptions::default(),
    };

    // Test Clone trait
    let cloned = options.clone();
    // Test Debug trait
    let debug_str = format!("{:?}", cloned);
    assert!(debug_str.contains("CertificateProfileClientCreateOptions"));
}

#[test]
fn test_certificate_profile_client_options_with_optional_fields() {
    let mut options =
        CertificateProfileClientOptions::new("https://test.com", "account", "profile");

    // Initially None
    assert!(options.correlation_id.is_none());
    assert!(options.client_version.is_none());

    // Set values
    options.correlation_id = Some("corr-123".to_string());
    options.client_version = Some("1.0.0".to_string());

    assert_eq!(options.correlation_id, Some("corr-123".to_string()));
    assert_eq!(options.client_version, Some("1.0.0".to_string()));
}

#[test]
fn test_certificate_profile_client_options_debug_trait() {
    let options =
        CertificateProfileClientOptions::new("https://test.com", "my-account", "my-profile");

    let debug_str = format!("{:?}", options);
    assert!(debug_str.contains("CertificateProfileClientOptions"));
    assert!(debug_str.contains("my-account"));
    assert!(debug_str.contains("my-profile"));
    assert!(debug_str.contains("https://test.com"));
}

#[test]
fn test_certificate_profile_client_options_clone_trait() {
    let options =
        CertificateProfileClientOptions::new("https://test.com", "my-account", "my-profile");

    let cloned = options.clone();
    assert_eq!(options.endpoint, cloned.endpoint);
    assert_eq!(options.account_name, cloned.account_name);
    assert_eq!(
        options.certificate_profile_name,
        cloned.certificate_profile_name
    );
    assert_eq!(options.api_version, cloned.api_version);
    assert_eq!(options.correlation_id, cloned.correlation_id);
    assert_eq!(options.client_version, cloned.client_version);
}
