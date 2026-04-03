// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Mock-based integration tests for `CertificateProfileClient`.
//!
//! Uses `SequentialMockTransport` to inject canned HTTP responses,
//! exercising the full pipeline path (request building → pipeline send
//! → response parsing) without hitting the network.

use azure_artifact_signing_client::{
    mock_transport::{MockResponse, SequentialMockTransport},
    CertificateProfileClient, CertificateProfileClientOptions, SignOptions,
};
use azure_core::http::Pipeline;

/// Build a `CertificateProfileClient` backed by canned mock responses.
fn mock_client(responses: Vec<MockResponse>) -> CertificateProfileClient {
    let mock = SequentialMockTransport::new(responses);
    let client_options = mock.into_client_options();
    let pipeline = Pipeline::new(
        Some("test-aas-client"),
        Some("0.1.0"),
        client_options,
        Vec::new(),
        Vec::new(),
        None,
    );

    let options = CertificateProfileClientOptions::new(
        "https://eus.codesigning.azure.net",
        "test-account",
        "test-profile",
    );

    CertificateProfileClient::new_with_pipeline(options, pipeline).unwrap()
}

/// Build `SignOptions` with a 1-second polling frequency for fast mock tests.
fn fast_sign_options() -> Option<SignOptions> {
    Some(SignOptions {
        poller_options: Some(
            azure_core::http::poller::PollerOptions {
                frequency: time::Duration::seconds(1),
                ..Default::default()
            }
            .into_owned(),
        ),
    })
}

// ========== GET /sign/eku ==========

#[test]
fn get_eku_success() {
    let eku_json =
        serde_json::to_vec(&vec!["1.3.6.1.5.5.7.3.3", "1.3.6.1.4.1.311.76.59.1.2"]).unwrap();
    let client = mock_client(vec![MockResponse::ok(eku_json)]);

    let ekus = client.get_eku().unwrap();
    assert_eq!(ekus.len(), 2);
    assert_eq!(ekus[0], "1.3.6.1.5.5.7.3.3");
    assert_eq!(ekus[1], "1.3.6.1.4.1.311.76.59.1.2");
}

#[test]
fn get_eku_empty_array() {
    let eku_json = serde_json::to_vec::<Vec<String>>(&vec![]).unwrap();
    let client = mock_client(vec![MockResponse::ok(eku_json)]);

    let ekus = client.get_eku().unwrap();
    assert!(ekus.is_empty());
}

#[test]
fn get_eku_single_oid() {
    let eku_json = serde_json::to_vec(&vec!["1.3.6.1.5.5.7.3.3"]).unwrap();
    let client = mock_client(vec![MockResponse::ok(eku_json)]);

    let ekus = client.get_eku().unwrap();
    assert_eq!(ekus.len(), 1);
    assert_eq!(ekus[0], "1.3.6.1.5.5.7.3.3");
}

// ========== GET /sign/rootcert ==========

#[test]
fn get_root_certificate_success() {
    let fake_der = vec![0x30, 0x82, 0x01, 0x22]; // DER prefix
    let client = mock_client(vec![MockResponse::ok(fake_der.clone())]);

    let cert = client.get_root_certificate().unwrap();
    assert_eq!(cert, fake_der);
}

#[test]
fn get_root_certificate_empty_body() {
    let client = mock_client(vec![MockResponse::ok(vec![])]);

    let cert = client.get_root_certificate().unwrap();
    assert!(cert.is_empty());
}

// ========== GET /sign/certchain ==========

#[test]
fn get_certificate_chain_success() {
    let fake_pkcs7 = vec![0x30, 0x82, 0x03, 0x55]; // PKCS#7 prefix
    let client = mock_client(vec![MockResponse::ok(fake_pkcs7.clone())]);

    let chain = client.get_certificate_chain().unwrap();
    assert_eq!(chain, fake_pkcs7);
}

// ========== POST /sign (LRO) ==========

#[test]
fn sign_immediate_success() {
    // Service responds with Succeeded on the first POST (no polling needed).
    use base64::Engine;
    let sig_bytes = b"fake-signature-bytes";
    let cert_bytes = b"fake-cert-der";
    let sig_b64 = base64::engine::general_purpose::STANDARD.encode(sig_bytes);
    let cert_b64 = base64::engine::general_purpose::STANDARD.encode(cert_bytes);

    let body = serde_json::json!({
        "operationId": "op-1",
        "status": "Succeeded",
        "signature": sig_b64,
        "signingCertificate": cert_b64,
    });

    let client = mock_client(vec![MockResponse::ok(serde_json::to_vec(&body).unwrap())]);

    let digest = b"sha256-digest-placeholder-----32";
    let result = client.sign("PS256", digest, None).unwrap();
    assert_eq!(result.operation_id, "op-1");
    assert_eq!(
        result.status,
        azure_artifact_signing_client::OperationStatus::Succeeded
    );
    assert!(result.signature.is_some());
    assert!(result.signing_certificate.is_some());
}

#[test]
fn sign_with_polling() {
    // First response: InProgress, second response: Succeeded
    use base64::Engine;

    let in_progress_body = serde_json::json!({
        "operationId": "op-42",
        "status": "InProgress",
    });

    let sig_b64 = base64::engine::general_purpose::STANDARD.encode(b"polled-sig");
    let cert_b64 = base64::engine::general_purpose::STANDARD.encode(b"polled-cert");
    let succeeded_body = serde_json::json!({
        "operationId": "op-42",
        "status": "Succeeded",
        "signature": sig_b64,
        "signingCertificate": cert_b64,
    });

    let client = mock_client(vec![
        MockResponse::ok(serde_json::to_vec(&in_progress_body).unwrap()),
        MockResponse::ok(serde_json::to_vec(&succeeded_body).unwrap()),
    ]);

    let result = client
        .sign("ES256", b"digest-bytes-here", fast_sign_options())
        .unwrap();
    assert_eq!(result.operation_id, "op-42");
    assert_eq!(
        result.status,
        azure_artifact_signing_client::OperationStatus::Succeeded
    );
}

#[test]
fn sign_multiple_polls_before_success() {
    use base64::Engine;

    let running1 = serde_json::json!({
        "operationId": "op-99",
        "status": "Running",
    });
    let running2 = serde_json::json!({
        "operationId": "op-99",
        "status": "InProgress",
    });

    let sig_b64 = base64::engine::general_purpose::STANDARD.encode(b"final-sig");
    let cert_b64 = base64::engine::general_purpose::STANDARD.encode(b"final-cert");
    let succeeded = serde_json::json!({
        "operationId": "op-99",
        "status": "Succeeded",
        "signature": sig_b64,
        "signingCertificate": cert_b64,
    });

    let client = mock_client(vec![
        MockResponse::ok(serde_json::to_vec(&running1).unwrap()),
        MockResponse::ok(serde_json::to_vec(&running2).unwrap()),
        MockResponse::ok(serde_json::to_vec(&succeeded).unwrap()),
    ]);

    let result = client
        .sign("PS384", b"digest", fast_sign_options())
        .unwrap();
    assert_eq!(result.operation_id, "op-99");
    assert_eq!(
        result.status,
        azure_artifact_signing_client::OperationStatus::Succeeded
    );
}

// ========== Error scenarios ==========

#[test]
fn mock_transport_exhausted_returns_error() {
    let client = mock_client(vec![]); // no responses
    let result = client.get_eku();
    assert!(result.is_err());
}

#[test]
fn get_root_certificate_transport_exhausted() {
    let client = mock_client(vec![]);
    let result = client.get_root_certificate();
    assert!(result.is_err());
}

#[test]
fn get_certificate_chain_transport_exhausted() {
    let client = mock_client(vec![]);
    let result = client.get_certificate_chain();
    assert!(result.is_err());
}

#[test]
fn sign_transport_exhausted() {
    let client = mock_client(vec![]);
    let result = client.sign("PS256", b"digest", None);
    assert!(result.is_err());
}

// ========== Multiple sequential operations on one client ==========

#[test]
fn sequential_eku_then_root_cert() {
    let eku_json = serde_json::to_vec(&vec!["1.3.6.1.5.5.7.3.3"]).unwrap();
    let fake_der = vec![0x30, 0x82, 0x01, 0x22];

    let client = mock_client(vec![
        MockResponse::ok(eku_json),
        MockResponse::ok(fake_der.clone()),
    ]);

    let ekus = client.get_eku().unwrap();
    assert_eq!(ekus.len(), 1);

    let cert = client.get_root_certificate().unwrap();
    assert_eq!(cert, fake_der);
}

// ========== Mock response construction ==========

#[test]
fn mock_response_ok() {
    let r = MockResponse::ok(b"body".to_vec());
    assert_eq!(r.status, 200);
    assert!(r.content_type.is_none());
    assert_eq!(r.body, b"body");
}

#[test]
fn mock_response_with_status() {
    let r = MockResponse::with_status(404, b"not found".to_vec());
    assert_eq!(r.status, 404);
    assert!(r.content_type.is_none());
}

#[test]
fn mock_response_with_content_type() {
    let r = MockResponse::with_content_type(200, "application/json", b"{}".to_vec());
    assert_eq!(r.status, 200);
    assert_eq!(r.content_type.as_deref(), Some("application/json"));
}

#[test]
fn mock_response_clone() {
    let r = MockResponse::ok(b"data".to_vec());
    let r2 = r.clone();
    assert_eq!(r.body, r2.body);
    assert_eq!(r.status, r2.status);
}

#[test]
fn mock_response_debug() {
    let r = MockResponse::ok(b"test".to_vec());
    let s = format!("{:?}", r);
    assert!(s.contains("MockResponse"));
}

#[test]
fn sequential_mock_transport_debug() {
    let mock = SequentialMockTransport::new(vec![
        MockResponse::ok(b"a".to_vec()),
        MockResponse::ok(b"b".to_vec()),
    ]);
    let s = format!("{:?}", mock);
    assert!(s.contains("SequentialMockTransport"));
    assert!(s.contains("2"));
}

// ========== Client with custom options ==========

#[test]
fn mock_client_with_correlation_id() {
    let eku_json = serde_json::to_vec(&vec!["1.3.6.1.5.5.7.3.3"]).unwrap();
    let mock = SequentialMockTransport::new(vec![MockResponse::ok(eku_json)]);
    let client_options = mock.into_client_options();
    let pipeline = Pipeline::new(
        Some("test"),
        Some("0.1.0"),
        client_options,
        Vec::new(),
        Vec::new(),
        None,
    );

    let mut options = CertificateProfileClientOptions::new(
        "https://eus.codesigning.azure.net",
        "test-account",
        "test-profile",
    );
    options.correlation_id = Some("corr-123".to_string());
    options.client_version = Some("1.0.0".to_string());

    let client = CertificateProfileClient::new_with_pipeline(options, pipeline).unwrap();
    let ekus = client.get_eku().unwrap();
    assert_eq!(ekus.len(), 1);
}

#[test]
fn mock_client_api_version() {
    let client = mock_client(vec![]);
    assert_eq!(client.api_version(), "2022-06-15-preview");
}
