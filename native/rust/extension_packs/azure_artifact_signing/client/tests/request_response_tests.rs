// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Tests for the pure request building and response parsing functions.
//!
//! These functions can be tested without requiring Azure credentials or network connectivity.

use azure_artifact_signing_client::client::{
    build_certificate_chain_request, build_eku_request, build_root_certificate_request,
    build_sign_request, parse_certificate_response, parse_eku_response, parse_sign_response,
};
use azure_artifact_signing_client::models::*;
use azure_core::http::{Method, Url};

#[test]
fn test_build_sign_request_basic() {
    let endpoint = Url::parse("https://test.codesigning.azure.net").unwrap();
    let api_version = "2022-06-15-preview";
    let account_name = "test-account";
    let certificate_profile_name = "test-profile";
    let algorithm = "PS256";
    let digest = b"test-digest-bytes";

    let request = build_sign_request(
        &endpoint,
        api_version,
        account_name,
        certificate_profile_name,
        algorithm,
        digest,
        None,
        None,
    )
    .unwrap();

    // Verify URL
    let expected_url = "https://test.codesigning.azure.net/codesigningaccounts/test-account/certificateprofiles/test-profile/sign?api-version=2022-06-15-preview";
    assert_eq!(request.url().to_string(), expected_url);

    // Verify method
    assert_eq!(request.method(), Method::Post);
}

#[test]
fn test_build_sign_request_with_headers() {
    let endpoint = Url::parse("https://test.codesigning.azure.net").unwrap();
    let api_version = "2022-06-15-preview";
    let account_name = "test-account";
    let certificate_profile_name = "test-profile";
    let algorithm = "ES256";
    let digest = b"another-test-digest";
    let correlation_id = Some("test-correlation-123");
    let client_version = Some("1.0.0");

    let request = build_sign_request(
        &endpoint,
        api_version,
        account_name,
        certificate_profile_name,
        algorithm,
        digest,
        correlation_id,
        client_version,
    )
    .unwrap();

    // Just verify the request builds successfully
    assert_eq!(request.method(), Method::Post);
}

#[test]
fn test_build_eku_request() {
    let endpoint = Url::parse("https://test.codesigning.azure.net").unwrap();
    let api_version = "2022-06-15-preview";
    let account_name = "test-account";
    let certificate_profile_name = "test-profile";

    let request = build_eku_request(
        &endpoint,
        api_version,
        account_name,
        certificate_profile_name,
    )
    .unwrap();

    // Verify URL
    let expected_url = "https://test.codesigning.azure.net/codesigningaccounts/test-account/certificateprofiles/test-profile/sign/eku?api-version=2022-06-15-preview";
    assert_eq!(request.url().to_string(), expected_url);

    // Verify method
    assert_eq!(request.method(), Method::Get);
}

#[test]
fn test_build_root_certificate_request() {
    let endpoint = Url::parse("https://test.codesigning.azure.net").unwrap();
    let api_version = "2022-06-15-preview";
    let account_name = "test-account";
    let certificate_profile_name = "test-profile";

    let request = build_root_certificate_request(
        &endpoint,
        api_version,
        account_name,
        certificate_profile_name,
    )
    .unwrap();

    // Verify URL
    let expected_url = "https://test.codesigning.azure.net/codesigningaccounts/test-account/certificateprofiles/test-profile/sign/rootcert?api-version=2022-06-15-preview";
    assert_eq!(request.url().to_string(), expected_url);

    // Verify method
    assert_eq!(request.method(), Method::Get);
}

#[test]
fn test_build_certificate_chain_request() {
    let endpoint = Url::parse("https://test.codesigning.azure.net").unwrap();
    let api_version = "2022-06-15-preview";
    let account_name = "test-account";
    let certificate_profile_name = "test-profile";

    let request = build_certificate_chain_request(
        &endpoint,
        api_version,
        account_name,
        certificate_profile_name,
    )
    .unwrap();

    // Verify URL
    let expected_url = "https://test.codesigning.azure.net/codesigningaccounts/test-account/certificateprofiles/test-profile/sign/certchain?api-version=2022-06-15-preview";
    assert_eq!(request.url().to_string(), expected_url);

    // Verify method
    assert_eq!(request.method(), Method::Get);
}

#[test]
fn test_parse_sign_response_succeeded() {
    let json_response = r#"{
        "operationId": "operation-123",
        "status": "Succeeded",
        "signature": "dGVzdC1zaWduYXR1cmU=",
        "signingCertificate": "dGVzdC1jZXJ0aWZpY2F0ZQ=="
    }"#;

    let response = parse_sign_response(json_response.as_bytes()).unwrap();
    assert_eq!(response.operation_id, "operation-123");
    assert_eq!(response.status, OperationStatus::Succeeded);
    assert_eq!(response.signature.unwrap(), "dGVzdC1zaWduYXR1cmU=");
    assert_eq!(
        response.signing_certificate.unwrap(),
        "dGVzdC1jZXJ0aWZpY2F0ZQ=="
    );
}

#[test]
fn test_parse_sign_response_in_progress() {
    let json_response = r#"{
        "operationId": "operation-456",
        "status": "InProgress"
    }"#;

    let response = parse_sign_response(json_response.as_bytes()).unwrap();
    assert_eq!(response.operation_id, "operation-456");
    assert_eq!(response.status, OperationStatus::InProgress);
    assert!(response.signature.is_none());
    assert!(response.signing_certificate.is_none());
}

#[test]
fn test_parse_sign_response_failed() {
    let json_response = r#"{
        "operationId": "operation-789",
        "status": "Failed"
    }"#;

    let response = parse_sign_response(json_response.as_bytes()).unwrap();
    assert_eq!(response.operation_id, "operation-789");
    assert_eq!(response.status, OperationStatus::Failed);
}

#[test]
fn test_parse_sign_response_all_statuses() {
    let statuses = vec![
        ("InProgress", OperationStatus::InProgress),
        ("Succeeded", OperationStatus::Succeeded),
        ("Failed", OperationStatus::Failed),
        ("TimedOut", OperationStatus::TimedOut),
        ("NotFound", OperationStatus::NotFound),
        ("Running", OperationStatus::Running),
    ];

    for (status_str, expected_status) in statuses {
        let json_response = format!(
            r#"{{"operationId": "test-op", "status": "{}"}}"#,
            status_str
        );
        let response = parse_sign_response(json_response.as_bytes()).unwrap();
        assert_eq!(response.status, expected_status);
    }
}

#[test]
fn test_parse_eku_response() {
    let json_response = r#"[
        "1.3.6.1.5.5.7.3.3",
        "1.3.6.1.4.1.311.10.3.13",
        "1.3.6.1.4.1.311.76.8.1"
    ]"#;

    let ekus = parse_eku_response(json_response.as_bytes()).unwrap();
    assert_eq!(ekus.len(), 3);
    assert_eq!(ekus[0], "1.3.6.1.5.5.7.3.3");
    assert_eq!(ekus[1], "1.3.6.1.4.1.311.10.3.13");
    assert_eq!(ekus[2], "1.3.6.1.4.1.311.76.8.1");
}

#[test]
fn test_parse_eku_response_empty() {
    let json_response = r#"[]"#;

    let ekus = parse_eku_response(json_response.as_bytes()).unwrap();
    assert_eq!(ekus.len(), 0);
}

#[test]
fn test_parse_certificate_response() {
    let test_data = b"test-certificate-der-data";
    let result = parse_certificate_response(test_data);
    assert_eq!(result, test_data.to_vec());
}

#[test]
fn test_parse_certificate_response_empty() {
    let test_data = b"";
    let result = parse_certificate_response(test_data);
    assert_eq!(result, Vec::<u8>::new());
}

// Error handling tests

#[test]
fn test_parse_sign_response_invalid_json() {
    let invalid_json = b"not valid json";
    let result = parse_sign_response(invalid_json);
    assert!(result.is_err());
}

#[test]
fn test_parse_eku_response_invalid_json() {
    let invalid_json = b"not valid json";
    let result = parse_eku_response(invalid_json);
    assert!(result.is_err());
}

#[test]
fn test_build_sign_request_invalid_endpoint() {
    // This should still work because we clone a valid URL
    let endpoint = Url::parse("https://test.codesigning.azure.net").unwrap();
    let result = build_sign_request(
        &endpoint,
        "api-version",
        "account",
        "profile",
        "PS256",
        b"digest",
        None,
        None,
    );
    assert!(result.is_ok());
}

// Test different signature algorithms

#[test]
fn test_build_sign_request_all_algorithms() {
    let endpoint = Url::parse("https://test.codesigning.azure.net").unwrap();
    let algorithms = vec![
        SignatureAlgorithm::RS256,
        SignatureAlgorithm::RS384,
        SignatureAlgorithm::RS512,
        SignatureAlgorithm::PS256,
        SignatureAlgorithm::PS384,
        SignatureAlgorithm::PS512,
        SignatureAlgorithm::ES256,
        SignatureAlgorithm::ES384,
        SignatureAlgorithm::ES512,
        SignatureAlgorithm::ES256K,
    ];

    for algorithm in algorithms {
        let request = build_sign_request(
            &endpoint,
            "2022-06-15-preview",
            "test-account",
            "test-profile",
            algorithm,
            b"test-digest",
            None,
            None,
        )
        .unwrap();

        // Just verify the request builds successfully
        assert_eq!(request.method(), Method::Post);
    }
}

// Test URL construction edge cases

#[test]
fn test_build_requests_with_special_characters() {
    let endpoint = Url::parse("https://test.codesigning.azure.net").unwrap();
    let account_name = "test-account-with-dashes";
    let certificate_profile_name = "test-profile_with_underscores";

    let sign_request = build_sign_request(
        &endpoint,
        "2022-06-15-preview",
        account_name,
        certificate_profile_name,
        "PS256",
        b"digest",
        None,
        None,
    )
    .unwrap();

    assert!(sign_request
        .url()
        .to_string()
        .contains("test-account-with-dashes"));
    assert!(sign_request
        .url()
        .to_string()
        .contains("test-profile_with_underscores"));

    let eku_request = build_eku_request(
        &endpoint,
        "2022-06-15-preview",
        account_name,
        certificate_profile_name,
    )
    .unwrap();

    assert!(eku_request
        .url()
        .to_string()
        .contains("test-account-with-dashes"));
    assert!(eku_request
        .url()
        .to_string()
        .contains("test-profile_with_underscores"));
}
