// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Additional tests for CertificateProfileClient coverage.
//! Tests the constructor and accessor methods without requiring HTTP mocking.

use azure_core::http::ClientOptions;
use azure_trusted_signing_client::{
    models::CertificateProfileClientOptions, CertificateProfileClient,
    CertificateProfileClientCreateOptions,
};

// ========== new_with_pipeline tests ==========

#[test]
fn test_new_with_pipeline_invalid_endpoint() {
    use azure_core::http::Pipeline;
    
    let options = CertificateProfileClientOptions::new(
        "not-a-valid-url",
        "account",
        "profile",
    );

    let pipeline = Pipeline::new(
        Some("test"),
        Some("0.1.0"),
        ClientOptions::default(),
        Vec::new(),
        Vec::new(),
        None,
    );

    let result = CertificateProfileClient::new_with_pipeline(options, pipeline);
    assert!(result.is_err());
}

#[test]
fn test_new_with_pipeline_valid_endpoint() {
    use azure_core::http::Pipeline;
    
    let options = CertificateProfileClientOptions::new(
        "https://test.codesigning.azure.net",
        "test-account",
        "test-profile",
    );

    let pipeline = Pipeline::new(
        Some("test-client"),
        Some("0.1.0"),
        ClientOptions::default(),
        Vec::new(),
        Vec::new(),
        None,
    );

    let result = CertificateProfileClient::new_with_pipeline(options, pipeline);
    assert!(result.is_ok());
    
    let client = result.unwrap();
    assert_eq!(client.api_version(), "2022-06-15-preview");
}

#[test]
fn test_new_with_pipeline_different_endpoints() {
    use azure_core::http::Pipeline;
    
    let endpoints = vec![
        "https://eus.codesigning.azure.net",
        "https://weu.codesigning.azure.net",
        "https://aue.codesigning.azure.net",
        "http://localhost:8080",
    ];
    
    for endpoint in endpoints {
        let options = CertificateProfileClientOptions::new(
            endpoint,
            "account",
            "profile",
        );
        
        let pipeline = Pipeline::new(
            Some("test"),
            Some("0.1.0"),
            ClientOptions::default(),
            Vec::new(),
            Vec::new(),
            None,
        );
        
        let result = CertificateProfileClient::new_with_pipeline(options, pipeline);
        assert!(result.is_ok(), "Failed for endpoint: {}", endpoint);
    }
}

// ========== CertificateProfileClientCreateOptions tests ==========

#[test]
fn test_create_options_default() {
    let options = CertificateProfileClientCreateOptions::default();
    // Verify it can be created and has expected structure
    let _client_options = options.client_options;
}

#[test]
fn test_create_options_clone() {
    let options = CertificateProfileClientCreateOptions {
        client_options: ClientOptions::default(),
    };
    
    let cloned = options.clone();
    // Both should have default client options
    let debug_original = format!("{:?}", options);
    let debug_cloned = format!("{:?}", cloned);
    assert!(debug_original.contains("CertificateProfileClientCreateOptions"));
    assert!(debug_cloned.contains("CertificateProfileClientCreateOptions"));
}

#[test]
fn test_create_options_debug() {
    let options = CertificateProfileClientCreateOptions::default();
    let debug_str = format!("{:?}", options);
    assert!(debug_str.contains("CertificateProfileClientCreateOptions"));
}

// ========== Client options with correlation_id and client_version ==========

#[test]
fn test_options_with_correlation_id() {
    let mut options = CertificateProfileClientOptions::new(
        "https://test.codesigning.azure.net",
        "account",
        "profile",
    );
    options.correlation_id = Some("test-correlation-123".to_string());
    
    assert_eq!(options.correlation_id, Some("test-correlation-123".to_string()));
    
    // Verify base_url and auth_scope still work
    let base_url = options.base_url();
    assert!(base_url.contains("account"));
    
    let auth_scope = options.auth_scope();
    assert!(auth_scope.contains("/.default"));
}

#[test]
fn test_options_with_client_version() {
    let mut options = CertificateProfileClientOptions::new(
        "https://test.codesigning.azure.net",
        "account",
        "profile",
    );
    options.client_version = Some("1.2.3".to_string());
    
    assert_eq!(options.client_version, Some("1.2.3".to_string()));
}

#[test]
fn test_options_with_both_optional_fields() {
    let mut options = CertificateProfileClientOptions::new(
        "https://test.codesigning.azure.net",
        "account",
        "profile",
    );
    options.correlation_id = Some("corr-id".to_string());
    options.client_version = Some("2.0.0".to_string());
    
    assert_eq!(options.correlation_id, Some("corr-id".to_string()));
    assert_eq!(options.client_version, Some("2.0.0".to_string()));
    
    // Clone and verify
    let cloned = options.clone();
    assert_eq!(cloned.correlation_id, Some("corr-id".to_string()));
    assert_eq!(cloned.client_version, Some("2.0.0".to_string()));
}

// ========== Options base_url edge cases ==========

#[test]
fn test_options_base_url_with_path() {
    // Endpoint with existing path should have path replaced
    let options = CertificateProfileClientOptions::new(
        "https://test.codesigning.azure.net/some/path",
        "account",
        "profile",
    );
    
    let base_url = options.base_url();
    // The base_url should construct the correct path
    assert!(base_url.contains("codesigningaccounts"));
    assert!(base_url.contains("certificateprofiles"));
}

#[test]
fn test_options_base_url_special_characters() {
    let options = CertificateProfileClientOptions::new(
        "https://test.codesigning.azure.net",
        "account-with-dashes_and_underscores",
        "profile.with.dots",
    );
    
    let base_url = options.base_url();
    assert!(base_url.contains("account-with-dashes_and_underscores"));
    assert!(base_url.contains("profile.with.dots"));
}

// ========== Options auth_scope edge cases ==========

#[test]
fn test_options_auth_scope_with_double_trailing_slash() {
    let options = CertificateProfileClientOptions::new(
        "https://test.codesigning.azure.net//",
        "account",
        "profile",
    );
    
    let auth_scope = options.auth_scope();
    // Should produce a valid auth scope without double slashes before .default
    assert!(auth_scope.ends_with("/.default"));
    assert!(!auth_scope.contains("//.default"));
}

#[test]
fn test_options_auth_scope_with_port() {
    let options = CertificateProfileClientOptions::new(
        "https://test.codesigning.azure.net:443",
        "account",
        "profile",
    );
    
    let auth_scope = options.auth_scope();
    assert!(auth_scope.contains("443"));
    assert!(auth_scope.ends_with("/.default"));
}

// ========== API version constant tests ==========

#[test]
fn test_api_version_constant_value() {
    use azure_trusted_signing_client::models::API_VERSION;
    assert_eq!(API_VERSION, "2022-06-15-preview");
}

#[test]
fn test_auth_scope_suffix_constant_value() {
    use azure_trusted_signing_client::models::AUTH_SCOPE_SUFFIX;
    assert_eq!(AUTH_SCOPE_SUFFIX, "/.default");
}
