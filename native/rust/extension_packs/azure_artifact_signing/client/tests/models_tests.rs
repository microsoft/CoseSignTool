// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use azure_artifact_signing_client::{
    CertificateProfileClientOptions, ErrorDetail, ErrorResponse, OperationStatus, SignRequest,
    SignStatus, SignatureAlgorithm, API_VERSION,
};
use serde_json;

#[test]
fn test_sign_request_serialization_camelcase() {
    let request = SignRequest {
        signature_algorithm: "RS256".to_string(),
        digest: "dGVzdA==".to_string(), // base64("test")
        file_hash_list: None,
        authenticode_hash_list: None,
    };

    let json = serde_json::to_string(&request).expect("Should serialize");
    assert!(json.contains("signatureAlgorithm")); // camelCase
    assert!(json.contains("digest"));
    assert!(json.contains("RS256"));
    assert!(json.contains("dGVzdA=="));

    // Should not contain optional fields when None
    assert!(!json.contains("fileHashList"));
    assert!(!json.contains("authenticodeHashList"));
}

#[test]
fn test_sign_request_serialization_with_optional_fields() {
    let request = SignRequest {
        signature_algorithm: "ES256".to_string(),
        digest: "aGVsbG8=".to_string(),
        file_hash_list: Some(vec!["hash1".to_string(), "hash2".to_string()]),
        authenticode_hash_list: Some(vec!["auth1".to_string()]),
    };

    let json = serde_json::to_string(&request).expect("Should serialize");
    assert!(json.contains("fileHashList"));
    assert!(json.contains("authenticodeHashList"));
    assert!(json.contains("hash1"));
    assert!(json.contains("auth1"));
}

#[test]
fn test_sign_status_deserialization_full() {
    let json = r#"{
        "operationId": "op-123",
        "status": "Succeeded",
        "signature": "c2lnbmF0dXJl",
        "signingCertificate": "Y2VydA=="
    }"#;

    let status: SignStatus = serde_json::from_str(json).expect("Should deserialize");
    assert_eq!(status.operation_id, "op-123");
    assert_eq!(status.status, OperationStatus::Succeeded);
    assert_eq!(status.signature, Some("c2lnbmF0dXJl".to_string()));
    assert_eq!(status.signing_certificate, Some("Y2VydA==".to_string()));
}

#[test]
fn test_sign_status_deserialization_minimal() {
    let json = r#"{
        "operationId": "op-456",
        "status": "InProgress"
    }"#;

    let status: SignStatus = serde_json::from_str(json).expect("Should deserialize");
    assert_eq!(status.operation_id, "op-456");
    assert_eq!(status.status, OperationStatus::InProgress);
    assert_eq!(status.signature, None);
    assert_eq!(status.signing_certificate, None);
}

#[test]
fn test_operation_status_variants() {
    let test_cases = vec![
        ("InProgress", OperationStatus::InProgress),
        ("Succeeded", OperationStatus::Succeeded),
        ("Failed", OperationStatus::Failed),
        ("TimedOut", OperationStatus::TimedOut),
        ("NotFound", OperationStatus::NotFound),
        ("Running", OperationStatus::Running),
    ];

    for (json_str, expected) in test_cases {
        let json = format!(r#"{{"status": "{}"}}"#, json_str);
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        let status: OperationStatus = serde_json::from_value(parsed["status"].clone()).unwrap();
        assert_eq!(status, expected);
    }
}

#[test]
fn test_error_response_with_full_detail() {
    let json = r#"{
        "errorDetail": {
            "code": "InvalidRequest",
            "message": "The digest is invalid",
            "target": "digest"
        }
    }"#;

    let error: ErrorResponse = serde_json::from_str(json).expect("Should deserialize");
    let detail = error.error_detail.expect("Should have error detail");
    assert_eq!(detail.code, Some("InvalidRequest".to_string()));
    assert_eq!(detail.message, Some("The digest is invalid".to_string()));
    assert_eq!(detail.target, Some("digest".to_string()));
}

#[test]
fn test_error_response_with_partial_detail() {
    let json = r#"{
        "errorDetail": {
            "code": "ServerError",
            "message": "Internal server error"
        }
    }"#;

    let error: ErrorResponse = serde_json::from_str(json).expect("Should deserialize");
    let detail = error.error_detail.expect("Should have error detail");
    assert_eq!(detail.code, Some("ServerError".to_string()));
    assert_eq!(detail.message, Some("Internal server error".to_string()));
    assert_eq!(detail.target, None);
}

#[test]
fn test_error_response_empty_detail() {
    let json = r#"{"errorDetail": null}"#;

    let error: ErrorResponse = serde_json::from_str(json).expect("Should deserialize");
    assert!(error.error_detail.is_none());
}

#[test]
fn test_certificate_profile_client_options_new() {
    let opts = CertificateProfileClientOptions::new(
        "https://eus.codesigning.azure.net",
        "my-account",
        "my-profile",
    );

    assert_eq!(opts.endpoint, "https://eus.codesigning.azure.net");
    assert_eq!(opts.account_name, "my-account");
    assert_eq!(opts.certificate_profile_name, "my-profile");
    assert_eq!(opts.api_version, API_VERSION);
    assert_eq!(opts.correlation_id, None);
    assert_eq!(opts.client_version, None);
}

#[test]
fn test_certificate_profile_client_options_base_url() {
    let opts = CertificateProfileClientOptions::new(
        "https://eus.codesigning.azure.net",
        "my-account",
        "my-profile",
    );

    let expected = "https://eus.codesigning.azure.net/codesigningaccounts/my-account/certificateprofiles/my-profile";
    assert_eq!(opts.base_url(), expected);
}

#[test]
fn test_certificate_profile_client_options_base_url_trims_slash() {
    let opts = CertificateProfileClientOptions::new(
        "https://eus.codesigning.azure.net/",
        "my-account",
        "my-profile",
    );

    let expected = "https://eus.codesigning.azure.net/codesigningaccounts/my-account/certificateprofiles/my-profile";
    assert_eq!(opts.base_url(), expected);
}

#[test]
fn test_certificate_profile_client_options_auth_scope() {
    let opts = CertificateProfileClientOptions::new(
        "https://eus.codesigning.azure.net",
        "my-account",
        "my-profile",
    );

    let expected = "https://eus.codesigning.azure.net/.default";
    assert_eq!(opts.auth_scope(), expected);
}

#[test]
fn test_certificate_profile_client_options_auth_scope_trims_slash() {
    let opts = CertificateProfileClientOptions::new(
        "https://eus.codesigning.azure.net/",
        "my-account",
        "my-profile",
    );

    let expected = "https://eus.codesigning.azure.net/.default";
    assert_eq!(opts.auth_scope(), expected);
}

#[test]
fn test_various_endpoint_urls() {
    let endpoints = vec![
        "https://eus.codesigning.azure.net",
        "https://weu.codesigning.azure.net",
        "https://neu.codesigning.azure.net",
        "https://scus.codesigning.azure.net",
    ];

    for endpoint in endpoints {
        let opts = CertificateProfileClientOptions::new(endpoint, "test-account", "test-profile");

        let base_url = opts.base_url();
        let auth_scope = opts.auth_scope();

        assert!(base_url.starts_with(endpoint.trim_end_matches('/')));
        assert!(base_url.contains("/codesigningaccounts/test-account"));
        assert!(base_url.contains("/certificateprofiles/test-profile"));

        assert_eq!(
            auth_scope,
            format!("{}/.default", endpoint.trim_end_matches('/'))
        );
    }
}

#[test]
fn test_signature_algorithm_constants() {
    // Test that constants match C# SDK exactly
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
fn test_sign_request_with_file_hash_list() {
    let request = SignRequest {
        signature_algorithm: "PS256".to_string(),
        digest: "YWJjZA==".to_string(), // base64("abcd")
        file_hash_list: Some(vec![
            "hash1".to_string(),
            "hash2".to_string(),
            "hash3".to_string(),
        ]),
        authenticode_hash_list: None,
    };

    let json = serde_json::to_string(&request).expect("Should serialize");
    assert!(json.contains("fileHashList"));
    assert!(json.contains("hash1"));
    assert!(json.contains("hash2"));
    assert!(json.contains("hash3"));
    assert!(!json.contains("authenticodeHashList"));
}

#[test]
fn test_sign_request_with_authenticode_hash_list() {
    let request = SignRequest {
        signature_algorithm: "ES384".to_string(),
        digest: "ZGVmZw==".to_string(), // base64("defg")
        file_hash_list: None,
        authenticode_hash_list: Some(vec!["auth_hash1".to_string(), "auth_hash2".to_string()]),
    };

    let json = serde_json::to_string(&request).expect("Should serialize");
    assert!(json.contains("authenticodeHashList"));
    assert!(json.contains("auth_hash1"));
    assert!(json.contains("auth_hash2"));
    assert!(!json.contains("fileHashList"));
}

#[test]
fn test_sign_request_with_both_hash_lists() {
    let request = SignRequest {
        signature_algorithm: "RS512".to_string(),
        digest: "aGlqaw==".to_string(), // base64("hijk")
        file_hash_list: Some(vec!["file_hash".to_string()]),
        authenticode_hash_list: Some(vec!["auth_hash".to_string()]),
    };

    let json = serde_json::to_string(&request).expect("Should serialize");
    assert!(json.contains("fileHashList"));
    assert!(json.contains("authenticodeHashList"));
    assert!(json.contains("file_hash"));
    assert!(json.contains("auth_hash"));
}

#[test]
fn test_sign_status_all_operation_status_deserialization() {
    let test_cases = vec![
        ("InProgress", OperationStatus::InProgress),
        ("Succeeded", OperationStatus::Succeeded),
        ("Failed", OperationStatus::Failed),
        ("TimedOut", OperationStatus::TimedOut),
        ("NotFound", OperationStatus::NotFound),
        ("Running", OperationStatus::Running),
    ];

    for (status_str, expected_status) in test_cases {
        let json = format!(
            r#"{{
            "operationId": "test-op-{}",
            "status": "{}"
        }}"#,
            status_str.to_lowercase(),
            status_str
        );

        let sign_status: SignStatus = serde_json::from_str(&json).expect("Should deserialize");
        assert_eq!(sign_status.status, expected_status);
        assert_eq!(
            sign_status.operation_id,
            format!("test-op-{}", status_str.to_lowercase())
        );
    }
}

#[test]
fn test_error_detail_partial_fields() {
    let json = r#"{"code": "ErrorCode"}"#;
    let detail: ErrorDetail = serde_json::from_str(json).expect("Should deserialize");
    assert_eq!(detail.code, Some("ErrorCode".to_string()));
    assert_eq!(detail.message, None);
    assert_eq!(detail.target, None);
}

#[test]
fn test_error_detail_empty_fields() {
    let json = r#"{}"#;
    let detail: ErrorDetail = serde_json::from_str(json).expect("Should deserialize");
    assert_eq!(detail.code, None);
    assert_eq!(detail.message, None);
    assert_eq!(detail.target, None);
}
