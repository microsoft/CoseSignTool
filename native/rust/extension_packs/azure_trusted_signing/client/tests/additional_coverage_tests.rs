// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Additional test coverage for extracted functions and client utilities.

use azure_trusted_signing_client::{
    CertificateProfileClientCreateOptions, 
    SignOptions, SignStatus, OperationStatus, API_VERSION,
};
use azure_core::http::poller::StatusMonitor;

#[test] 
fn test_sign_options_default() {
    let options = SignOptions::default();
    assert!(options.poller_options.is_none());
}

#[test]
fn test_sign_status_status_monitor_trait() {
    let sign_status = SignStatus {
        operation_id: "test-op".to_string(),
        status: OperationStatus::InProgress,
        signature: None,
        signing_certificate: None,
    };
    
    // Test StatusMonitor implementation
    use azure_core::http::poller::PollerStatus;
    assert_eq!(sign_status.status(), PollerStatus::InProgress);
    
    let succeeded_status = SignStatus {
        operation_id: "test-op-2".to_string(),
        status: OperationStatus::Succeeded,
        signature: Some("dGVzdA==".to_string()),
        signing_certificate: Some("Y2VydA==".to_string()),
    };
    assert_eq!(succeeded_status.status(), PollerStatus::Succeeded);
    
    let failed_status = SignStatus {
        operation_id: "test-op-3".to_string(),
        status: OperationStatus::Failed,
        signature: None,
        signing_certificate: None,
    };
    assert_eq!(failed_status.status(), PollerStatus::Failed);
}

#[test]
fn test_operation_status_to_poller_status() {
    // Test all status conversions
    assert_eq!(OperationStatus::InProgress.to_poller_status(), azure_core::http::poller::PollerStatus::InProgress);
    assert_eq!(OperationStatus::Running.to_poller_status(), azure_core::http::poller::PollerStatus::InProgress);
    assert_eq!(OperationStatus::Succeeded.to_poller_status(), azure_core::http::poller::PollerStatus::Succeeded);
    assert_eq!(OperationStatus::Failed.to_poller_status(), azure_core::http::poller::PollerStatus::Failed);
    assert_eq!(OperationStatus::TimedOut.to_poller_status(), azure_core::http::poller::PollerStatus::Failed);
    assert_eq!(OperationStatus::NotFound.to_poller_status(), azure_core::http::poller::PollerStatus::Failed);
}

#[test]
fn test_certificate_profile_client_create_options_default() {
    let options = CertificateProfileClientCreateOptions::default();
    // Just verify it creates successfully - it's mostly a wrapper around ClientOptions
    assert!(options.client_options.per_call_policies.is_empty());
    assert!(options.client_options.per_try_policies.is_empty());
}

#[test]
fn test_sign_options_with_custom_poller_options() {
    use azure_core::http::poller::PollerOptions;
    use std::time::Duration;
    
    // Create custom poller options (we can't access internal fields easily)
    let custom_poller_options = PollerOptions::default();
        
    let sign_options = SignOptions {
        poller_options: Some(custom_poller_options),
    };
    
    assert!(sign_options.poller_options.is_some());
}

#[test]
fn test_build_sign_request_basic_validation() {
    use azure_trusted_signing_client::client::build_sign_request;
    use azure_core::http::{Method, Url};
    
    let endpoint = Url::parse("https://test.codesigning.azure.net").unwrap();
    let digest = b"test-digest-bytes-for-validation";
    
    let request = build_sign_request(
        &endpoint,
        "2022-06-15-preview",
        "test-account",
        "test-profile",
        "PS256",
        digest,
        Some("correlation-123"),
        Some("client-v1.0.0"),
    ).unwrap();
    
    // Verify the basic properties we can check
    assert_eq!(request.method(), Method::Post);
    assert!(request.url().to_string().contains("test-account"));
    assert!(request.url().to_string().contains("test-profile"));
    assert!(request.url().to_string().contains("sign"));
    assert!(request.url().to_string().contains("api-version=2022-06-15-preview"));
}

#[test]
fn test_build_requests_basic_validation() {
    use azure_trusted_signing_client::client::{
        build_eku_request, build_root_certificate_request, build_certificate_chain_request
    };
    use azure_core::http::{Method, Url};
    
    let endpoint = Url::parse("https://test.codesigning.azure.net").unwrap();
    
    // Test EKU request
    let eku_request = build_eku_request(
        &endpoint,
        "2022-06-15-preview", 
        "test-account",
        "test-profile",
    ).unwrap();
    
    assert_eq!(eku_request.method(), Method::Get);
    assert!(eku_request.url().to_string().contains("sign/eku"));
    
    // Test root certificate request
    let root_cert_request = build_root_certificate_request(
        &endpoint,
        "2022-06-15-preview",
        "test-account", 
        "test-profile",
    ).unwrap();
    
    assert_eq!(root_cert_request.method(), Method::Get);
    assert!(root_cert_request.url().to_string().contains("sign/rootcert"));
    
    // Test certificate chain request  
    let cert_chain_request = build_certificate_chain_request(
        &endpoint,
        "2022-06-15-preview",
        "test-account",
        "test-profile",
    ).unwrap();
    
    assert_eq!(cert_chain_request.method(), Method::Get);
    assert!(cert_chain_request.url().to_string().contains("sign/certchain"));
}

#[test]
fn test_parse_response_edge_cases() {
    use azure_trusted_signing_client::client::{parse_sign_response, parse_eku_response, parse_certificate_response};
    
    // Test empty JSON object parsing
    let empty_json = r#"{}"#;
    let result = parse_sign_response(empty_json.as_bytes());
    assert!(result.is_err()); // Should fail because operationId is required
    
    // Test EKU with single item
    let single_eku_json = r#"["1.3.6.1.5.5.7.3.3"]"#;
    let ekus = parse_eku_response(single_eku_json.as_bytes()).unwrap();
    assert_eq!(ekus.len(), 1);
    assert_eq!(ekus[0], "1.3.6.1.5.5.7.3.3");
    
    // Test certificate response with binary data
    let binary_data = vec![0x30, 0x82, 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB];
    let cert_result = parse_certificate_response(&binary_data);
    assert_eq!(cert_result, binary_data);
}

#[test]
fn test_sign_status_clone() {
    let original = SignStatus {
        operation_id: "test-clone".to_string(),
        status: OperationStatus::Succeeded, 
        signature: Some("signature-data".to_string()),
        signing_certificate: Some("cert-data".to_string()),
    };
    
    let cloned = original.clone();
    assert_eq!(cloned.operation_id, original.operation_id);
    assert_eq!(cloned.status, original.status);
    assert_eq!(cloned.signature, original.signature);
    assert_eq!(cloned.signing_certificate, original.signing_certificate);
}

#[test]
fn test_operation_status_partial_eq() {
    assert_eq!(OperationStatus::InProgress, OperationStatus::InProgress);
    assert_eq!(OperationStatus::Succeeded, OperationStatus::Succeeded);
    assert_ne!(OperationStatus::InProgress, OperationStatus::Succeeded);
    assert_ne!(OperationStatus::Failed, OperationStatus::TimedOut);
}