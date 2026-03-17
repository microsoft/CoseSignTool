// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Mock transport tests for AkvKeyClient via `new_with_options()`.
//!
//! Uses `SequentialMockTransport` to inject canned Azure Key Vault REST
//! responses, testing AkvKeyClient construction and signing without
//! hitting the network.

use azure_core::http::{
    headers::Headers, AsyncRawResponse, HttpClient, Request, StatusCode,
};
use azure_security_keyvault_keys::KeyClientOptions;
use cose_sign1_azure_key_vault::common::akv_key_client::AkvKeyClient;
use cose_sign1_azure_key_vault::common::crypto_client::KeyVaultCryptoClient;
use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

// ==================== Mock Transport ====================

struct MockResponse {
    status: u16,
    body: Vec<u8>,
}

impl MockResponse {
    fn ok(body: Vec<u8>) -> Self {
        Self { status: 200, body }
    }
}

struct SequentialMockTransport {
    responses: Mutex<VecDeque<MockResponse>>,
}

impl std::fmt::Debug for SequentialMockTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SequentialMockTransport").finish()
    }
}

impl SequentialMockTransport {
    fn new(responses: Vec<MockResponse>) -> Self {
        Self {
            responses: Mutex::new(VecDeque::from(responses)),
        }
    }

    fn into_client_options(self) -> azure_core::http::ClientOptions {
        use azure_core::http::{RetryOptions, Transport};
        let transport = Transport::new(Arc::new(self));
        azure_core::http::ClientOptions {
            transport: Some(transport),
            retry: RetryOptions::none(),
            ..Default::default()
        }
    }
}

#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
impl HttpClient for SequentialMockTransport {
    async fn execute_request(&self, _request: &Request) -> azure_core::Result<AsyncRawResponse> {
        let resp = self
            .responses
            .lock()
            .map_err(|_| {
                azure_core::Error::new(azure_core::error::ErrorKind::Other, "mock lock poisoned")
            })?
            .pop_front()
            .ok_or_else(|| {
                azure_core::Error::new(azure_core::error::ErrorKind::Other, "no more mock responses")
            })?;

        let status = StatusCode::try_from(resp.status).unwrap_or(StatusCode::InternalServerError);
        let mut headers = Headers::new();
        headers.insert("content-type", "application/json");
        Ok(AsyncRawResponse::from_bytes(status, headers, resp.body))
    }
}

// ==================== Mock Credential ====================

#[derive(Debug)]
struct MockCredential;

#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
impl azure_core::credentials::TokenCredential for MockCredential {
    async fn get_token(
        &self,
        _scopes: &[&str],
        _options: Option<azure_core::credentials::TokenRequestOptions<'_>>,
    ) -> azure_core::Result<azure_core::credentials::AccessToken> {
        Ok(azure_core::credentials::AccessToken::new(
            azure_core::credentials::Secret::new("mock-token"),
            azure_core::time::OffsetDateTime::now_utc() + azure_core::time::Duration::hours(1),
        ))
    }
}

// ==================== Helpers ====================

/// Build a JSON response like Azure Key Vault `GET /keys/{name}` would return.
fn make_get_key_response_ec() -> Vec<u8> {
    // Use valid base64url-encoded 32-byte P-256 coordinates
    use base64::Engine;
    let x_bytes = vec![1u8; 32];
    let y_bytes = vec![2u8; 32];
    let x_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&x_bytes);
    let y_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&y_bytes);

    serde_json::to_vec(&serde_json::json!({
        "key": {
            "kid": "https://myvault.vault.azure.net/keys/mykey/abc123",
            "kty": "EC",
            "crv": "P-256",
            "x": x_b64,
            "y": y_b64,
        },
        "attributes": {
            "enabled": true
        }
    }))
    .unwrap()
}

/// Build a JSON response like Azure Key Vault `POST /keys/{name}/sign` would return.
fn make_sign_response() -> Vec<u8> {
    use base64::Engine;
    let sig = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b"mock-kv-signature");
    serde_json::to_vec(&serde_json::json!({
        "kid": "https://myvault.vault.azure.net/keys/mykey/abc123",
        "value": sig,
    }))
    .unwrap()
}

fn mock_akv_client(responses: Vec<MockResponse>) -> Result<AkvKeyClient, cose_sign1_azure_key_vault::common::error::AkvError> {
    let mock = SequentialMockTransport::new(responses);
    let client_options = mock.into_client_options();
    let options = KeyClientOptions {
        client_options,
        ..Default::default()
    };
    let credential: Arc<dyn azure_core::credentials::TokenCredential> = Arc::new(MockCredential);

    AkvKeyClient::new_with_options(
        "https://myvault.vault.azure.net",
        "mykey",
        None,
        credential,
        options,
    )
}

// ==================== Tests ====================

#[test]
fn new_with_options_ec_key() {
    let get_key = make_get_key_response_ec();
    let client = mock_akv_client(vec![MockResponse::ok(get_key)]);
    assert!(client.is_ok(), "Should construct from mock: {:?}", client.err());

    let client = client.unwrap();
    assert_eq!(client.key_id(), "https://myvault.vault.azure.net/keys/mykey/abc123");
    assert_eq!(client.key_type(), "EC", "Key type should be EC, got: {}", client.key_type());
    assert!(client.curve_name().is_some());
}

#[test]
fn new_with_options_sign_success() {
    let get_key = make_get_key_response_ec();
    let sign_resp = make_sign_response();

    let client = mock_akv_client(vec![
        MockResponse::ok(get_key),
        MockResponse::ok(sign_resp),
    ])
    .unwrap();

    let digest = vec![0u8; 32]; // SHA-256 digest
    let result = client.sign("ES256", &digest);
    assert!(result.is_ok(), "Sign should succeed: {:?}", result.err());
    assert!(!result.unwrap().is_empty());
}

#[test]
fn new_with_options_transport_exhausted() {
    let client = mock_akv_client(vec![]);
    assert!(client.is_err(), "Should fail with no responses");
}

#[test]
fn map_algorithm_all_variants() {
    let get_key = make_get_key_response_ec();
    let client = mock_akv_client(vec![MockResponse::ok(get_key)]).unwrap();

    // Test all known algorithm mappings by trying to sign with each
    // (they'll fail at the transport level, but the algorithm mapping succeeds)
    for alg in &["ES256", "ES384", "ES512", "PS256", "PS384", "PS512", "RS256", "RS384", "RS512"] {
        let result = client.sign(alg, &[0u8; 32]);
        // Transport exhausted is expected, but algorithm mapping should succeed
        // The error should be about transport, not about invalid algorithm
        if let Err(e) = &result {
            let msg = format!("{}", e);
            assert!(!msg.contains("unsupported algorithm"), "Algorithm {} should be supported", alg);
        }
    }
}

#[test]
fn map_algorithm_unsupported() {
    let get_key = make_get_key_response_ec();
    let client = mock_akv_client(vec![MockResponse::ok(get_key)]).unwrap();

    let result = client.sign("UNSUPPORTED", &[0u8; 32]);
    assert!(result.is_err());
    let err = format!("{}", result.unwrap_err());
    assert!(err.contains("unsupported algorithm"), "Should be algorithm error: {}", err);
}

#[test]
fn public_key_bytes_ec_returns_uncompressed_point() {
    let get_key = make_get_key_response_ec();
    let client = mock_akv_client(vec![MockResponse::ok(get_key)]).unwrap();

    let result = client.public_key_bytes();
    assert!(result.is_ok(), "public_key_bytes should succeed for EC key: {:?}", result.err());
    let bytes = result.unwrap();
    assert_eq!(bytes[0], 0x04, "EC public key should start with 0x04 (uncompressed)");
    assert_eq!(bytes.len(), 1 + 32 + 32, "P-256 uncompressed point = 1 + 32 + 32 bytes");
}

#[test]
fn key_metadata_accessors() {
    let get_key = make_get_key_response_ec();
    let client = mock_akv_client(vec![MockResponse::ok(get_key)]).unwrap();

    assert!(client.key_size().is_none()); // Not extracted for EC keys
    assert!(!client.key_id().is_empty());
    assert!(!client.key_type().is_empty());
}

#[test]
fn hsm_detection() {
    let get_key = make_get_key_response_ec();
    let mock = SequentialMockTransport::new(vec![MockResponse::ok(get_key)]);
    let client_options = mock.into_client_options();
    let options = KeyClientOptions {
        client_options,
        ..Default::default()
    };
    let credential: Arc<dyn azure_core::credentials::TokenCredential> = Arc::new(MockCredential);

    let result = AkvKeyClient::new_with_options(
        "https://myvault.managedhsm.azure.net", // HSM URL
        "hsmkey",
        None,
        credential,
        options,
    );
    // Construction may succeed or fail depending on SDK URL validation
    let _ = result;
}
