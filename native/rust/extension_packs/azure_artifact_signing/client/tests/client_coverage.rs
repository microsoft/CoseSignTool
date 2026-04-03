// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Test coverage for Azure Artifact Signing client functionality.

use azure_artifact_signing_client::models::{
    CertificateProfileClientOptions, OperationStatus, SignRequest, SignStatus, SignatureAlgorithm,
    API_VERSION, AUTH_SCOPE_SUFFIX,
};

#[test]
fn test_certificate_profile_client_options_new() {
    let options = CertificateProfileClientOptions::new(
        "https://eus.codesigning.azure.net",
        "my-account",
        "my-profile",
    );

    assert_eq!(options.endpoint, "https://eus.codesigning.azure.net");
    assert_eq!(options.account_name, "my-account");
    assert_eq!(options.certificate_profile_name, "my-profile");
    assert_eq!(options.api_version, API_VERSION);
    assert_eq!(options.correlation_id, None);
    assert_eq!(options.client_version, None);
}

#[test]
fn test_certificate_profile_client_options_base_url() {
    let options = CertificateProfileClientOptions::new(
        "https://eus.codesigning.azure.net/",
        "my-account",
        "my-profile",
    );

    let base_url = options.base_url();
    assert_eq!(
        base_url,
        "https://eus.codesigning.azure.net/codesigningaccounts/my-account/certificateprofiles/my-profile"
    );
}

#[test]
fn test_certificate_profile_client_options_base_url_no_trailing_slash() {
    let options = CertificateProfileClientOptions::new(
        "https://eus.codesigning.azure.net",
        "my-account",
        "my-profile",
    );

    let base_url = options.base_url();
    assert_eq!(
        base_url,
        "https://eus.codesigning.azure.net/codesigningaccounts/my-account/certificateprofiles/my-profile"
    );
}

#[test]
fn test_certificate_profile_client_options_auth_scope() {
    let options = CertificateProfileClientOptions::new(
        "https://eus.codesigning.azure.net/",
        "my-account",
        "my-profile",
    );

    let auth_scope = options.auth_scope();
    assert_eq!(auth_scope, "https://eus.codesigning.azure.net/.default");
}

#[test]
fn test_certificate_profile_client_options_auth_scope_no_trailing_slash() {
    let options = CertificateProfileClientOptions::new(
        "https://eus.codesigning.azure.net",
        "my-account",
        "my-profile",
    );

    let auth_scope = options.auth_scope();
    assert_eq!(auth_scope, "https://eus.codesigning.azure.net/.default");
}

#[test]
fn test_sign_request_serialization() {
    let request = SignRequest {
        signature_algorithm: "PS256".to_string(),
        digest: "dGVzdC1kaWdlc3Q=".to_string(),
        file_hash_list: None,
        authenticode_hash_list: None,
    };

    let json = serde_json::to_string(&request).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();

    assert_eq!(parsed["signatureAlgorithm"], "PS256");
    assert_eq!(parsed["digest"], "dGVzdC1kaWdlc3Q=");
    assert!(parsed["fileHashList"].is_null());
    assert!(parsed["authenticodeHashList"].is_null());
}

#[test]
fn test_sign_request_serialization_with_optional_fields() {
    let request = SignRequest {
        signature_algorithm: "ES256".to_string(),
        digest: "dGVzdC1kaWdlc3Q=".to_string(),
        file_hash_list: Some(vec!["hash1".to_string(), "hash2".to_string()]),
        authenticode_hash_list: Some(vec!["auth1".to_string()]),
    };

    let json = serde_json::to_string(&request).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();

    assert_eq!(parsed["signatureAlgorithm"], "ES256");
    assert_eq!(parsed["digest"], "dGVzdC1kaWdlc3Q=");
    assert_eq!(parsed["fileHashList"][0], "hash1");
    assert_eq!(parsed["fileHashList"][1], "hash2");
    assert_eq!(parsed["authenticodeHashList"][0], "auth1");
}

#[test]
fn test_sign_status_deserialization() {
    let json = r#"{
        "operationId": "op123",
        "status": "Succeeded",
        "signature": "c2lnbmF0dXJl",
        "signingCertificate": "Y2VydGlmaWNhdGU="
    }"#;

    let status: SignStatus = serde_json::from_str(json).unwrap();
    assert_eq!(status.operation_id, "op123");
    assert_eq!(status.status, OperationStatus::Succeeded);
    assert_eq!(status.signature, Some("c2lnbmF0dXJl".to_string()));
    assert_eq!(
        status.signing_certificate,
        Some("Y2VydGlmaWNhdGU=".to_string())
    );
}

#[test]
fn test_sign_status_deserialization_minimal() {
    let json = r#"{
        "operationId": "op456",
        "status": "InProgress"
    }"#;

    let status: SignStatus = serde_json::from_str(json).unwrap();
    assert_eq!(status.operation_id, "op456");
    assert_eq!(status.status, OperationStatus::InProgress);
    assert_eq!(status.signature, None);
    assert_eq!(status.signing_certificate, None);
}

#[test]
fn test_operation_status_to_poller_status_in_progress() {
    use azure_core::http::poller::PollerStatus;

    assert_eq!(
        OperationStatus::InProgress.to_poller_status(),
        PollerStatus::InProgress
    );
    assert_eq!(
        OperationStatus::Running.to_poller_status(),
        PollerStatus::InProgress
    );
}

#[test]
fn test_operation_status_to_poller_status_succeeded() {
    use azure_core::http::poller::PollerStatus;

    assert_eq!(
        OperationStatus::Succeeded.to_poller_status(),
        PollerStatus::Succeeded
    );
}

#[test]
fn test_operation_status_to_poller_status_failed() {
    use azure_core::http::poller::PollerStatus;

    assert_eq!(
        OperationStatus::Failed.to_poller_status(),
        PollerStatus::Failed
    );
    assert_eq!(
        OperationStatus::TimedOut.to_poller_status(),
        PollerStatus::Failed
    );
    assert_eq!(
        OperationStatus::NotFound.to_poller_status(),
        PollerStatus::Failed
    );
}

#[test]
fn test_signature_algorithm_constants() {
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

#[test]
fn test_api_version_constant() {
    assert_eq!(API_VERSION, "2022-06-15-preview");
}

#[test]
fn test_auth_scope_suffix_constant() {
    assert_eq!(AUTH_SCOPE_SUFFIX, "/.default");
}

#[test]
fn test_operation_status_equality() {
    assert_eq!(OperationStatus::InProgress, OperationStatus::InProgress);
    assert_eq!(OperationStatus::Succeeded, OperationStatus::Succeeded);
    assert_eq!(OperationStatus::Failed, OperationStatus::Failed);
    assert_eq!(OperationStatus::TimedOut, OperationStatus::TimedOut);
    assert_eq!(OperationStatus::NotFound, OperationStatus::NotFound);
    assert_eq!(OperationStatus::Running, OperationStatus::Running);

    assert_ne!(OperationStatus::InProgress, OperationStatus::Succeeded);
    assert_ne!(OperationStatus::Failed, OperationStatus::Running);
}

#[test]
fn test_operation_status_debug() {
    // Test that debug formatting works
    let status = OperationStatus::Succeeded;
    let debug_str = format!("{:?}", status);
    assert_eq!(debug_str, "Succeeded");
}

#[test]
fn test_sign_status_debug_and_clone() {
    let status = SignStatus {
        operation_id: "test123".to_string(),
        status: OperationStatus::InProgress,
        signature: None,
        signing_certificate: None,
    };

    // Test Debug formatting
    let debug_str = format!("{:?}", status);
    assert!(debug_str.contains("test123"));
    assert!(debug_str.contains("InProgress"));

    // Test Clone
    let cloned = status.clone();
    assert_eq!(cloned.operation_id, "test123");
    assert_eq!(cloned.status, OperationStatus::InProgress);
}

#[test]
fn test_certificate_profile_client_options_debug_and_clone() {
    let options = CertificateProfileClientOptions::new("https://test.com", "account", "profile");

    // Test Debug formatting
    let debug_str = format!("{:?}", options);
    assert!(debug_str.contains("https://test.com"));
    assert!(debug_str.contains("account"));
    assert!(debug_str.contains("profile"));

    // Test Clone
    let cloned = options.clone();
    assert_eq!(cloned.endpoint, "https://test.com");
    assert_eq!(cloned.account_name, "account");
    assert_eq!(cloned.certificate_profile_name, "profile");
}
