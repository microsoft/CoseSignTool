// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Deep coverage tests for azure_artifact_signing_client crate.
//!
//! Targets testable functions that don't require Azure credentials:
//! - AasClientError Display variants
//! - AasClientError std::error::Error impl
//! - CertificateProfileClientOptions (base_url, auth_scope, new)
//! - OperationStatus::to_poller_status all variants
//! - SignStatus StatusMonitor impl
//! - SignatureAlgorithm constants
//! - SignRequest / ErrorResponse / ErrorDetail Debug/serde
//! - build_sign_request, build_eku_request, build_root_certificate_request,
//!   build_certificate_chain_request
//! - parse_sign_response, parse_eku_response, parse_certificate_response

use azure_artifact_signing_client::error::AasClientError;
use azure_artifact_signing_client::models::*;
use azure_artifact_signing_client::client::*;
use azure_core::http::Url;

// =========================================================================
// AasClientError Display coverage
// =========================================================================

#[test]
fn error_display_http_error() {
    let e = AasClientError::HttpError("connection refused".to_string());
    let s = format!("{}", e);
    assert!(s.contains("HTTP error"));
    assert!(s.contains("connection refused"));
}

#[test]
fn error_display_authentication_failed() {
    let e = AasClientError::AuthenticationFailed("token expired".to_string());
    let s = format!("{}", e);
    assert!(s.contains("Authentication failed"));
    assert!(s.contains("token expired"));
}

#[test]
fn error_display_service_error_with_target() {
    let e = AasClientError::ServiceError {
        code: "InvalidRequest".to_string(),
        message: "bad parameter".to_string(),
        target: Some("digest".to_string()),
    };
    let s = format!("{}", e);
    assert!(s.contains("Service error [InvalidRequest]"));
    assert!(s.contains("bad parameter"));
    assert!(s.contains("target: digest"));
}

#[test]
fn error_display_service_error_without_target() {
    let e = AasClientError::ServiceError {
        code: "InternalError".to_string(),
        message: "server error".to_string(),
        target: None,
    };
    let s = format!("{}", e);
    assert!(s.contains("Service error [InternalError]"));
    assert!(!s.contains("target:"));
}

#[test]
fn error_display_operation_failed() {
    let e = AasClientError::OperationFailed {
        operation_id: "op-123".to_string(),
        status: "Failed".to_string(),
    };
    let s = format!("{}", e);
    assert!(s.contains("Operation op-123 failed"));
    assert!(s.contains("Failed"));
}

#[test]
fn error_display_operation_timeout() {
    let e = AasClientError::OperationTimeout {
        operation_id: "op-456".to_string(),
    };
    let s = format!("{}", e);
    assert!(s.contains("Operation op-456 timed out"));
}

#[test]
fn error_display_deserialization_error() {
    let e = AasClientError::DeserializationError("invalid json".to_string());
    let s = format!("{}", e);
    assert!(s.contains("Deserialization error"));
}

#[test]
fn error_display_invalid_configuration() {
    let e = AasClientError::InvalidConfiguration("missing endpoint".to_string());
    let s = format!("{}", e);
    assert!(s.contains("Invalid configuration"));
}

#[test]
fn error_display_certificate_chain_not_available() {
    let e = AasClientError::CertificateChainNotAvailable("404".to_string());
    let s = format!("{}", e);
    assert!(s.contains("Certificate chain not available"));
}

#[test]
fn error_display_sign_failed() {
    let e = AasClientError::SignFailed("HSM error".to_string());
    let s = format!("{}", e);
    assert!(s.contains("Sign failed"));
}

#[test]
fn error_is_std_error() {
    let e: Box<dyn std::error::Error> =
        Box::new(AasClientError::HttpError("test".to_string()));
    assert!(e.to_string().contains("HTTP error"));
}

#[test]
fn error_debug() {
    let e = AasClientError::SignFailed("debug test".to_string());
    let debug = format!("{:?}", e);
    assert!(debug.contains("SignFailed"));
}

// =========================================================================
// CertificateProfileClientOptions coverage
// =========================================================================

#[test]
fn options_new() {
    let opts = CertificateProfileClientOptions::new(
        "https://eus.codesigning.azure.net",
        "my-account",
        "my-profile",
    );
    assert_eq!(opts.endpoint, "https://eus.codesigning.azure.net");
    assert_eq!(opts.account_name, "my-account");
    assert_eq!(opts.certificate_profile_name, "my-profile");
    assert_eq!(opts.api_version, API_VERSION);
    assert!(opts.correlation_id.is_none());
    assert!(opts.client_version.is_none());
}

#[test]
fn options_base_url() {
    let opts = CertificateProfileClientOptions::new(
        "https://eus.codesigning.azure.net",
        "acct",
        "prof",
    );
    let url = opts.base_url();
    assert_eq!(
        url,
        "https://eus.codesigning.azure.net/codesigningaccounts/acct/certificateprofiles/prof"
    );
}

#[test]
fn options_base_url_trailing_slash() {
    let opts = CertificateProfileClientOptions::new(
        "https://eus.codesigning.azure.net/",
        "acct",
        "prof",
    );
    let url = opts.base_url();
    assert!(url.contains("codesigningaccounts/acct"));
    // Trailing slash should be trimmed
    assert!(!url.starts_with("https://eus.codesigning.azure.net//"));
}

#[test]
fn options_auth_scope() {
    let opts = CertificateProfileClientOptions::new(
        "https://eus.codesigning.azure.net",
        "acct",
        "prof",
    );
    let scope = opts.auth_scope();
    assert_eq!(scope, "https://eus.codesigning.azure.net/.default");
}

#[test]
fn options_auth_scope_trailing_slash() {
    let opts = CertificateProfileClientOptions::new(
        "https://eus.codesigning.azure.net/",
        "acct",
        "prof",
    );
    let scope = opts.auth_scope();
    assert_eq!(scope, "https://eus.codesigning.azure.net/.default");
}

#[test]
fn options_debug_and_clone() {
    let opts = CertificateProfileClientOptions::new("https://example.com", "a", "b");
    let debug = format!("{:?}", opts);
    assert!(debug.contains("example.com"));
    let cloned = opts.clone();
    assert_eq!(cloned.endpoint, opts.endpoint);
}

// =========================================================================
// OperationStatus coverage
// =========================================================================

#[test]
fn operation_status_in_progress() {
    use azure_core::http::poller::PollerStatus;
    assert_eq!(OperationStatus::InProgress.to_poller_status(), PollerStatus::InProgress);
}

#[test]
fn operation_status_running() {
    use azure_core::http::poller::PollerStatus;
    assert_eq!(OperationStatus::Running.to_poller_status(), PollerStatus::InProgress);
}

#[test]
fn operation_status_succeeded() {
    use azure_core::http::poller::PollerStatus;
    assert_eq!(OperationStatus::Succeeded.to_poller_status(), PollerStatus::Succeeded);
}

#[test]
fn operation_status_failed() {
    use azure_core::http::poller::PollerStatus;
    assert_eq!(OperationStatus::Failed.to_poller_status(), PollerStatus::Failed);
}

#[test]
fn operation_status_timed_out() {
    use azure_core::http::poller::PollerStatus;
    assert_eq!(OperationStatus::TimedOut.to_poller_status(), PollerStatus::Failed);
}

#[test]
fn operation_status_not_found() {
    use azure_core::http::poller::PollerStatus;
    assert_eq!(OperationStatus::NotFound.to_poller_status(), PollerStatus::Failed);
}

#[test]
fn operation_status_debug_eq() {
    assert_eq!(OperationStatus::InProgress, OperationStatus::InProgress);
    assert_ne!(OperationStatus::InProgress, OperationStatus::Succeeded);
    let debug = format!("{:?}", OperationStatus::Failed);
    assert_eq!(debug, "Failed");
}

// =========================================================================
// SignStatus StatusMonitor coverage
// =========================================================================

#[test]
fn sign_status_status_monitor() {
    use azure_core::http::poller::StatusMonitor;
    let status = SignStatus {
        operation_id: "op1".to_string(),
        status: OperationStatus::Succeeded,
        signature: Some("base64sig".to_string()),
        signing_certificate: Some("base64cert".to_string()),
    };
    let ps = status.status();
    assert_eq!(ps, azure_core::http::poller::PollerStatus::Succeeded);
}

#[test]
fn sign_status_debug_clone() {
    let status = SignStatus {
        operation_id: "op2".to_string(),
        status: OperationStatus::InProgress,
        signature: None,
        signing_certificate: None,
    };
    let debug = format!("{:?}", status);
    assert!(debug.contains("op2"));
    let cloned = status.clone();
    assert_eq!(cloned.operation_id, "op2");
}

// =========================================================================
// SignatureAlgorithm constants coverage
// =========================================================================

#[test]
fn signature_algorithm_constants() {
    assert_eq!(SignatureAlgorithm::RS256, "RS256");
    assert_eq!(SignatureAlgorithm::RS384, "RS384");
    assert_eq!(SignatureAlgorithm::RS512, "RS512");
    assert_eq!(SignatureAlgorithm::PS256, "PS256");
    assert_eq!(SignatureAlgorithm::PS384, "PS384");
    assert_eq!(SignatureAlgorithm::PS512, "PS512");
    assert_eq!(SignatureAlgorithm::ES256, "ES256");
    assert_eq!(SignatureAlgorithm::ES384, "ES384");
    assert_eq!(SignatureAlgorithm::ES512, "ES512");
    assert_eq!(SignatureAlgorithm::ES256K, "ES256K");
}

// =========================================================================
// API_VERSION and AUTH_SCOPE_SUFFIX constants
// =========================================================================

#[test]
fn api_version_constant() {
    assert_eq!(API_VERSION, "2022-06-15-preview");
}

#[test]
fn auth_scope_suffix_constant() {
    assert_eq!(AUTH_SCOPE_SUFFIX, "/.default");
}

// =========================================================================
// build_sign_request coverage
// =========================================================================

#[test]
fn build_sign_request_basic() {
    let endpoint = Url::parse("https://eus.codesigning.azure.net").unwrap();
    let request = build_sign_request(
        &endpoint,
        "2022-06-15-preview",
        "acct",
        "prof",
        "PS256",
        &[0xAA, 0xBB, 0xCC],
        None,
        None,
    )
    .unwrap();

    let url = request.url().to_string();
    assert!(url.contains("codesigningaccounts/acct"));
    assert!(url.contains("certificateprofiles/prof"));
    assert!(url.contains("sign"));
    assert!(url.contains("api-version=2022-06-15-preview"));
}

#[test]
fn build_sign_request_with_headers() {
    let endpoint = Url::parse("https://eus.codesigning.azure.net").unwrap();
    let request = build_sign_request(
        &endpoint,
        "2022-06-15-preview",
        "acct",
        "prof",
        "ES256",
        &[1, 2, 3],
        Some("correlation-123"),
        Some("1.0.0"),
    )
    .unwrap();

    let url = request.url().to_string();
    assert!(url.contains("sign"));
}

// =========================================================================
// build_eku_request coverage
// =========================================================================

#[test]
fn build_eku_request_basic() {
    let endpoint = Url::parse("https://eus.codesigning.azure.net").unwrap();
    let request = build_eku_request(
        &endpoint,
        "2022-06-15-preview",
        "acct",
        "prof",
    )
    .unwrap();

    let url = request.url().to_string();
    assert!(url.contains("sign/eku"));
    assert!(url.contains("api-version"));
}

// =========================================================================
// build_root_certificate_request coverage
// =========================================================================

#[test]
fn build_root_certificate_request_basic() {
    let endpoint = Url::parse("https://eus.codesigning.azure.net").unwrap();
    let request = build_root_certificate_request(
        &endpoint,
        "2022-06-15-preview",
        "acct",
        "prof",
    )
    .unwrap();

    let url = request.url().to_string();
    assert!(url.contains("sign/rootcert"));
}

// =========================================================================
// build_certificate_chain_request coverage
// =========================================================================

#[test]
fn build_certificate_chain_request_basic() {
    let endpoint = Url::parse("https://eus.codesigning.azure.net").unwrap();
    let request = build_certificate_chain_request(
        &endpoint,
        "2022-06-15-preview",
        "acct",
        "prof",
    )
    .unwrap();

    let url = request.url().to_string();
    assert!(url.contains("sign/certchain"));
}

// =========================================================================
// parse_sign_response coverage
// =========================================================================

#[test]
fn parse_sign_response_valid() {
    let json = serde_json::json!({
        "operationId": "op-123",
        "status": "Succeeded",
        "signature": "c2lnbmF0dXJl",
        "signingCertificate": "Y2VydA=="
    });
    let body = serde_json::to_vec(&json).unwrap();
    let status = parse_sign_response(&body).unwrap();
    assert_eq!(status.operation_id, "op-123");
    assert_eq!(status.status, OperationStatus::Succeeded);
    assert_eq!(status.signature.as_deref(), Some("c2lnbmF0dXJl"));
}

#[test]
fn parse_sign_response_in_progress() {
    let json = serde_json::json!({
        "operationId": "op-456",
        "status": "InProgress"
    });
    let body = serde_json::to_vec(&json).unwrap();
    let status = parse_sign_response(&body).unwrap();
    assert_eq!(status.status, OperationStatus::InProgress);
    assert!(status.signature.is_none());
}

// =========================================================================
// parse_eku_response coverage
// =========================================================================

#[test]
fn parse_eku_response_valid() {
    let json = serde_json::json!(["1.3.6.1.5.5.7.3.3", "1.3.6.1.4.1.311.76.59.1.1"]);
    let body = serde_json::to_vec(&json).unwrap();
    let ekus = parse_eku_response(&body).unwrap();
    assert_eq!(ekus.len(), 2);
    assert!(ekus.contains(&"1.3.6.1.5.5.7.3.3".to_string()));
}

// =========================================================================
// parse_certificate_response coverage
// =========================================================================

#[test]
fn parse_certificate_response_basic() {
    let body = vec![0x30, 0x82, 0x01, 0x00]; // Fake DER header
    let result = parse_certificate_response(&body);
    assert_eq!(result, body);
}

#[test]
fn parse_certificate_response_empty() {
    let result = parse_certificate_response(&[]);
    assert!(result.is_empty());
}

// =========================================================================
// SignRequest serialization coverage
// =========================================================================

#[test]
fn sign_request_serialization() {
    let req = SignRequest {
        signature_algorithm: "PS256".to_string(),
        digest: "base64digest".to_string(),
        file_hash_list: None,
        authenticode_hash_list: None,
    };
    let json = serde_json::to_string(&req).unwrap();
    assert!(json.contains("signatureAlgorithm"));
    assert!(json.contains("PS256"));
    // None fields should be skipped
    assert!(!json.contains("fileHashList"));
}

#[test]
fn sign_request_with_optional_fields() {
    let req = SignRequest {
        signature_algorithm: "ES256".to_string(),
        digest: "abc".to_string(),
        file_hash_list: Some(vec!["hash1".to_string()]),
        authenticode_hash_list: Some(vec!["auth1".to_string()]),
    };
    let json = serde_json::to_string(&req).unwrap();
    assert!(json.contains("fileHashList"));
    assert!(json.contains("authenticodeHashList"));
}

#[test]
fn sign_request_debug() {
    let req = SignRequest {
        signature_algorithm: "PS256".to_string(),
        digest: "test".to_string(),
        file_hash_list: None,
        authenticode_hash_list: None,
    };
    let debug = format!("{:?}", req);
    assert!(debug.contains("PS256"));
}

// =========================================================================
// ErrorResponse / ErrorDetail coverage
// =========================================================================

#[test]
fn error_response_deserialization() {
    let json = serde_json::json!({
        "errorDetail": {
            "code": "BadRequest",
            "message": "Invalid digest",
            "target": "digest"
        }
    });
    let body = serde_json::to_vec(&json).unwrap();
    let resp: ErrorResponse = serde_json::from_slice(&body).unwrap();
    let detail = resp.error_detail.unwrap();
    assert_eq!(detail.code.as_deref(), Some("BadRequest"));
    assert_eq!(detail.message.as_deref(), Some("Invalid digest"));
    assert_eq!(detail.target.as_deref(), Some("digest"));
}

#[test]
fn error_response_no_detail() {
    let json = serde_json::json!({});
    let body = serde_json::to_vec(&json).unwrap();
    let resp: ErrorResponse = serde_json::from_slice(&body).unwrap();
    assert!(resp.error_detail.is_none());
}

// =========================================================================
// CertificateProfileClientCreateOptions Default coverage
// =========================================================================

#[test]
fn create_options_default() {
    let opts = CertificateProfileClientCreateOptions::default();
    let debug = format!("{:?}", opts);
    assert!(debug.contains("CertificateProfileClientCreateOptions"));
}
