// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use azure_core::http::{poller::PollerStatus, Url};
use azure_artifact_signing_client::client::*;
use azure_artifact_signing_client::error::*;
use azure_artifact_signing_client::models::*;

#[test]
fn client_options_new_defaults() {
    let opts = CertificateProfileClientOptions::new("https://ats.example.com", "acct", "prof");
    assert_eq!(opts.endpoint, "https://ats.example.com");
    assert_eq!(opts.account_name, "acct");
    assert_eq!(opts.certificate_profile_name, "prof");
    assert_eq!(opts.api_version, API_VERSION);
    assert!(opts.correlation_id.is_none());
    assert!(opts.client_version.is_none());
}

#[test]
fn base_url_without_trailing_slash() {
    let opts = CertificateProfileClientOptions::new("https://ats.example.com", "acct", "prof");
    assert_eq!(opts.base_url(), "https://ats.example.com/codesigningaccounts/acct/certificateprofiles/prof");
}

#[test]
fn base_url_with_trailing_slash() {
    let opts = CertificateProfileClientOptions::new("https://ats.example.com/", "acct", "prof");
    assert_eq!(opts.base_url(), "https://ats.example.com/codesigningaccounts/acct/certificateprofiles/prof");
}

#[test]
fn auth_scope_without_trailing_slash() {
    let opts = CertificateProfileClientOptions::new("https://ats.example.com", "acct", "prof");
    assert_eq!(opts.auth_scope(), "https://ats.example.com/.default");
}

#[test]
fn auth_scope_with_trailing_slash() {
    let opts = CertificateProfileClientOptions::new("https://ats.example.com/", "acct", "prof");
    assert_eq!(opts.auth_scope(), "https://ats.example.com/.default");
}

#[test]
fn error_display_all_variants() {
    assert_eq!(format!("{}", AasClientError::HttpError("timeout".into())), "HTTP error: timeout");
    assert_eq!(format!("{}", AasClientError::AuthenticationFailed("bad token".into())), "Authentication failed: bad token");
    assert_eq!(format!("{}", AasClientError::DeserializationError("bad json".into())), "Deserialization error: bad json");
    assert_eq!(format!("{}", AasClientError::InvalidConfiguration("missing".into())), "Invalid configuration: missing");
    assert_eq!(format!("{}", AasClientError::CertificateChainNotAvailable("none".into())), "Certificate chain not available: none");
    assert_eq!(format!("{}", AasClientError::SignFailed("err".into())), "Sign failed: err");
    assert_eq!(format!("{}", AasClientError::OperationTimeout { operation_id: "op1".into() }), "Operation op1 timed out");
    assert_eq!(format!("{}", AasClientError::OperationFailed { operation_id: "op2".into(), status: "Failed".into() }), "Operation op2 failed with status: Failed");

    let with_target = AasClientError::ServiceError { code: "E01".into(), message: "bad".into(), target: Some("res".into()) };
    assert!(format!("{}", with_target).contains("(target: res)"));
    let no_target = AasClientError::ServiceError { code: "E01".into(), message: "bad".into(), target: None };
    assert!(!format!("{}", no_target).contains("target"));
}

#[test]
fn error_is_std_error() {
    let err: Box<dyn std::error::Error> = Box::new(AasClientError::HttpError("x".into()));
    assert!(err.to_string().contains("HTTP error"));
}

#[test]
fn operation_status_to_poller_status() {
    assert_eq!(OperationStatus::InProgress.to_poller_status(), PollerStatus::InProgress);
    assert_eq!(OperationStatus::Running.to_poller_status(), PollerStatus::InProgress);
    assert_eq!(OperationStatus::Succeeded.to_poller_status(), PollerStatus::Succeeded);
    assert_eq!(OperationStatus::Failed.to_poller_status(), PollerStatus::Failed);
    assert_eq!(OperationStatus::TimedOut.to_poller_status(), PollerStatus::Failed);
    assert_eq!(OperationStatus::NotFound.to_poller_status(), PollerStatus::Failed);
}

#[test]
fn signature_algorithm_constants() {
    assert_eq!(SignatureAlgorithm::RS256, "RS256");
    assert_eq!(SignatureAlgorithm::ES256, "ES256");
    assert_eq!(SignatureAlgorithm::PS512, "PS512");
    assert_eq!(SignatureAlgorithm::ES256K, "ES256K");
}

#[test]
fn parse_sign_response_valid() {
    let json = br#"{"operationId":"op1","status":"Succeeded","signature":"c2ln","signingCertificate":"Y2VydA=="}"#;
    let status = parse_sign_response(json).unwrap();
    assert_eq!(status.operation_id, "op1");
    assert_eq!(status.status, OperationStatus::Succeeded);
    assert_eq!(status.signature.as_deref(), Some("c2ln"));
}

#[test]
fn parse_sign_response_invalid_json() {
    assert!(parse_sign_response(b"not json").is_err());
}

#[test]
fn parse_sign_response_missing_fields() {
    assert!(parse_sign_response(br#"{"status":"Succeeded"}"#).is_err());
}

#[test]
fn parse_eku_response_valid() {
    let json = br#"["1.3.6.1.5.5.7.3.3","1.3.6.1.4.1.311.10.3.13"]"#;
    let ekus = parse_eku_response(json).unwrap();
    assert_eq!(ekus.len(), 2);
    assert_eq!(ekus[0], "1.3.6.1.5.5.7.3.3");
}

#[test]
fn parse_eku_response_invalid_json() {
    assert!(parse_eku_response(b"{bad}").is_err());
}

#[test]
fn parse_certificate_response_returns_bytes() {
    let raw = vec![0x30, 0x82, 0x01, 0x22];
    assert_eq!(parse_certificate_response(&raw), raw);
}

#[test]
fn build_sign_request_with_optional_headers() {
    let url = Url::parse("https://ats.example.com").unwrap();
    let req = build_sign_request(&url, API_VERSION, "acct", "prof", "ES256", b"digest", Some("corr-id"), Some("1.0")).unwrap();
    let req_url = req.url().to_string();
    assert!(req_url.contains("codesigningaccounts/acct/certificateprofiles/prof/sign"));
    assert!(req_url.contains("api-version="));
}

#[test]
fn build_sign_request_without_optional_headers() {
    let url = Url::parse("https://ats.example.com").unwrap();
    let req = build_sign_request(&url, API_VERSION, "acct", "prof", "ES256", b"digest", None, None).unwrap();
    assert!(req.url().to_string().contains("/sign"));
}

#[test]
fn build_eku_request_basic() {
    let url = Url::parse("https://ats.example.com").unwrap();
    let req = build_eku_request(&url, API_VERSION, "acct", "prof").unwrap();
    assert!(req.url().to_string().contains("/sign/eku"));
}

#[test]
fn build_root_certificate_request_basic() {
    let url = Url::parse("https://ats.example.com").unwrap();
    let req = build_root_certificate_request(&url, API_VERSION, "acct", "prof").unwrap();
    assert!(req.url().to_string().contains("/sign/rootcert"));
}

#[test]
fn build_certificate_chain_request_basic() {
    let url = Url::parse("https://ats.example.com").unwrap();
    let req = build_certificate_chain_request(&url, API_VERSION, "acct", "prof").unwrap();
    assert!(req.url().to_string().contains("/sign/certchain"));
}
