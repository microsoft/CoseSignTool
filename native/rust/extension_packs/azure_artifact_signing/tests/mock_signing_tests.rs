// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Mock-based integration tests for the `cose_sign1_azure_artifact_signing` crate.
//!
//! Uses `SequentialMockTransport` from the client crate to inject canned HTTP
//! responses, testing `AzureArtifactSigningCertificateSource` and its methods
//! through the full pipeline path without hitting the network.

use azure_artifact_signing_client::{
    mock_transport::{MockResponse, SequentialMockTransport},
    CertificateProfileClient, CertificateProfileClientOptions, SignOptions,
};
use azure_core::http::Pipeline;
use cose_sign1_azure_artifact_signing::signing::certificate_source::AzureArtifactSigningCertificateSource;

/// Build SignOptions with a 1-second polling frequency for fast mock tests.
fn fast_sign_options() -> Option<SignOptions> {
    Some(SignOptions {
        poller_options: Some(
            azure_core::http::poller::PollerOptions {
                frequency: azure_core::time::Duration::seconds(1),
                ..Default::default()
            }
            .into_owned(),
        ),
    })
}

/// Build a `CertificateProfileClient` backed by canned mock responses.
fn mock_pipeline_client(responses: Vec<MockResponse>) -> CertificateProfileClient {
    let mock = SequentialMockTransport::new(responses);
    let client_options = mock.into_client_options();
    let pipeline = Pipeline::new(
        Some("test-aas"),
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

/// Build an `AzureArtifactSigningCertificateSource` with mock responses.
fn mock_source(responses: Vec<MockResponse>) -> AzureArtifactSigningCertificateSource {
    let client = mock_pipeline_client(responses);
    AzureArtifactSigningCertificateSource::with_client(client)
}

// ========== fetch_eku ==========

#[test]
fn fetch_eku_success() {
    let eku_json = serde_json::to_vec(&vec![
        "1.3.6.1.5.5.7.3.3",
        "1.3.6.1.4.1.311.76.59.1.2",
    ])
    .unwrap();
    let source = mock_source(vec![MockResponse::ok(eku_json)]);

    let ekus = source.fetch_eku().unwrap();
    assert_eq!(ekus.len(), 2);
    assert_eq!(ekus[0], "1.3.6.1.5.5.7.3.3");
    assert_eq!(ekus[1], "1.3.6.1.4.1.311.76.59.1.2");
}

#[test]
fn fetch_eku_empty() {
    let eku_json = serde_json::to_vec::<Vec<String>>(&vec![]).unwrap();
    let source = mock_source(vec![MockResponse::ok(eku_json)]);

    let ekus = source.fetch_eku().unwrap();
    assert!(ekus.is_empty());
}

#[test]
fn fetch_eku_transport_exhausted() {
    let source = mock_source(vec![]);
    let result = source.fetch_eku();
    assert!(result.is_err());
}

// ========== fetch_root_certificate ==========

#[test]
fn fetch_root_certificate_success() {
    let fake_der = vec![0x30, 0x82, 0x01, 0x22, 0x30, 0x81, 0xCF];
    let source = mock_source(vec![MockResponse::ok(fake_der.clone())]);

    let cert = source.fetch_root_certificate().unwrap();
    assert_eq!(cert, fake_der);
}

#[test]
fn fetch_root_certificate_empty() {
    let source = mock_source(vec![MockResponse::ok(vec![])]);
    let cert = source.fetch_root_certificate().unwrap();
    assert!(cert.is_empty());
}

#[test]
fn fetch_root_certificate_transport_exhausted() {
    let source = mock_source(vec![]);
    let result = source.fetch_root_certificate();
    assert!(result.is_err());
}

// ========== fetch_certificate_chain_pkcs7 ==========

#[test]
fn fetch_certificate_chain_pkcs7_success() {
    let fake_pkcs7 = vec![0x30, 0x82, 0x03, 0x55, 0x06, 0x09];
    let source = mock_source(vec![MockResponse::ok(fake_pkcs7.clone())]);

    let chain = source.fetch_certificate_chain_pkcs7().unwrap();
    assert_eq!(chain, fake_pkcs7);
}

#[test]
fn fetch_certificate_chain_transport_exhausted() {
    let source = mock_source(vec![]);
    let result = source.fetch_certificate_chain_pkcs7();
    assert!(result.is_err());
}

// ========== sign_digest ==========

#[test]
fn sign_digest_immediate_success() {
    use base64::Engine;
    let sig_bytes = b"mock-signature-data";
    let cert_bytes = b"mock-certificate-der";
    let sig_b64 = base64::engine::general_purpose::STANDARD.encode(sig_bytes);
    let cert_b64 = base64::engine::general_purpose::STANDARD.encode(cert_bytes);

    let body = serde_json::json!({
        "operationId": "op-sign-1",
        "status": "Succeeded",
        "signature": sig_b64,
        "signingCertificate": cert_b64,
    });

    let source = mock_source(vec![MockResponse::ok(
        serde_json::to_vec(&body).unwrap(),
    )]);

    let digest = b"sha256-digest-placeholder-----32";
    let (signature, cert_der) = source.sign_digest("PS256", digest).unwrap();
    assert_eq!(signature, sig_bytes);
    assert_eq!(cert_der, cert_bytes);
}

#[test]
fn sign_digest_with_polling() {
    use base64::Engine;

    let in_progress = serde_json::json!({
        "operationId": "op-poll",
        "status": "InProgress",
    });

    let sig_b64 = base64::engine::general_purpose::STANDARD.encode(b"polled-sig");
    let cert_b64 = base64::engine::general_purpose::STANDARD.encode(b"polled-cert");
    let succeeded = serde_json::json!({
        "operationId": "op-poll",
        "status": "Succeeded",
        "signature": sig_b64,
        "signingCertificate": cert_b64,
    });

    let source = mock_source(vec![
        MockResponse::ok(serde_json::to_vec(&in_progress).unwrap()),
        MockResponse::ok(serde_json::to_vec(&succeeded).unwrap()),
    ]);

    let (signature, cert_der) = source
        .sign_digest_with_options("ES256", b"digest", fast_sign_options())
        .unwrap();
    assert_eq!(signature, b"polled-sig");
    assert_eq!(cert_der, b"polled-cert");
}

#[test]
fn sign_digest_transport_exhausted() {
    let source = mock_source(vec![]);
    let result = source.sign_digest("PS256", b"digest");
    assert!(result.is_err());
}

// ========== decode_sign_status edge cases (via sign_digest) ==========

#[test]
fn sign_digest_missing_signature_field() {
    // Succeeded but no signature field → error
    let body = serde_json::json!({
        "operationId": "op-no-sig",
        "status": "Succeeded",
        "signingCertificate": "Y2VydA==",
    });

    let source = mock_source(vec![MockResponse::ok(
        serde_json::to_vec(&body).unwrap(),
    )]);

    let result = source.sign_digest("PS256", b"digest");
    assert!(result.is_err());
    let err_msg = format!("{}", result.unwrap_err());
    assert!(err_msg.contains("No signature"));
}

#[test]
fn sign_digest_missing_certificate_field() {
    // Succeeded but no signingCertificate field → error
    use base64::Engine;
    let sig_b64 = base64::engine::general_purpose::STANDARD.encode(b"sig");
    let body = serde_json::json!({
        "operationId": "op-no-cert",
        "status": "Succeeded",
        "signature": sig_b64,
    });

    let source = mock_source(vec![MockResponse::ok(
        serde_json::to_vec(&body).unwrap(),
    )]);

    let result = source.sign_digest("PS256", b"digest");
    assert!(result.is_err());
    let err_msg = format!("{}", result.unwrap_err());
    assert!(err_msg.contains("No signing certificate"));
}

#[test]
fn sign_digest_invalid_base64_signature() {
    let body = serde_json::json!({
        "operationId": "op-bad-b64",
        "status": "Succeeded",
        "signature": "not-valid-base64!!!",
        "signingCertificate": "Y2VydA==",
    });

    let source = mock_source(vec![MockResponse::ok(
        serde_json::to_vec(&body).unwrap(),
    )]);

    let result = source.sign_digest("PS256", b"digest");
    assert!(result.is_err());
    let err_msg = format!("{}", result.unwrap_err());
    assert!(err_msg.contains("base64"));
}

#[test]
fn sign_digest_invalid_base64_certificate() {
    use base64::Engine;
    let sig_b64 = base64::engine::general_purpose::STANDARD.encode(b"sig");
    let body = serde_json::json!({
        "operationId": "op-bad-cert",
        "status": "Succeeded",
        "signature": sig_b64,
        "signingCertificate": "not!valid!base64!!!",
    });

    let source = mock_source(vec![MockResponse::ok(
        serde_json::to_vec(&body).unwrap(),
    )]);

    let result = source.sign_digest("PS256", b"digest");
    assert!(result.is_err());
    let err_msg = format!("{}", result.unwrap_err());
    assert!(err_msg.contains("base64"));
}

// ========== client accessor ==========

#[test]
fn client_accessor_returns_reference() {
    let source = mock_source(vec![]);
    let client = source.client();
    assert_eq!(client.api_version(), "2022-06-15-preview");
}

// ========== sequential operations through source ==========

#[test]
fn sequential_eku_then_cert_then_chain() {
    let eku_json = serde_json::to_vec(&vec!["1.3.6.1.5.5.7.3.3"]).unwrap();
    let fake_root = vec![0x30, 0x82, 0x01, 0x01];
    let fake_chain = vec![0x30, 0x82, 0x02, 0x02];

    let source = mock_source(vec![
        MockResponse::ok(eku_json),
        MockResponse::ok(fake_root.clone()),
        MockResponse::ok(fake_chain.clone()),
    ]);

    let ekus = source.fetch_eku().unwrap();
    assert_eq!(ekus.len(), 1);

    let root = source.fetch_root_certificate().unwrap();
    assert_eq!(root, fake_root);

    let chain = source.fetch_certificate_chain_pkcs7().unwrap();
    assert_eq!(chain, fake_chain);
}

// ========== with_client constructor ==========

#[test]
fn with_client_constructor() {
    let client = mock_pipeline_client(vec![]);
    let source = AzureArtifactSigningCertificateSource::with_client(client);
    // Verify the source was created and the client is accessible
    assert_eq!(source.client().api_version(), "2022-06-15-preview");
}
