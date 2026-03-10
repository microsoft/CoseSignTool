// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Test coverage for the start_sign method's LRO Poller logic via mock transport.
//! 
//! Tests the ~120 lines in the Poller closure that handle:
//! - Initial POST /sign request 
//! - 202 Accepted with operation_id
//! - Polling GET /sign/{operation_id} until status == Succeeded
//! - Final SignStatus with signature + cert

use azure_core::{
    credentials::{AccessToken, Secret, TokenCredential, TokenRequestOptions},
    http::{
        ClientOptions, HttpClient, Method, Pipeline, AsyncRawResponse, Request,
        StatusCode, Transport, headers::Headers,
    },
    Result,
};
use azure_trusted_signing_client::{
    models::{CertificateProfileClientOptions, OperationStatus},
    CertificateProfileClient,
};
use serde_json::json;
use std::{
    collections::HashMap,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Mutex,
    },
    time::SystemTime,
};
use time::OffsetDateTime;

// =================================================================
// Mock TokenCredential
// =================================================================

#[derive(Debug)]
struct MockTokenCredential {
    token: String,
}

impl MockTokenCredential {
    fn new(token: impl Into<String>) -> Self {
        Self {
            token: token.into(),
        }
    }
}

#[async_trait::async_trait]
impl TokenCredential for MockTokenCredential {
    async fn get_token<'a>(&'a self, _scopes: &[&str], _options: Option<TokenRequestOptions<'_>>) -> Result<AccessToken> {
        use tokio::time::Duration;
        let system_time = SystemTime::now() + Duration::from_secs(3600);
        let offset_time: OffsetDateTime = system_time.into();
        Ok(AccessToken::new(
            Secret::new(self.token.clone()),
            offset_time,
        ))
    }
}

// =================================================================
// Mock HttpClient for LRO scenarios
// =================================================================

#[derive(Debug)]
struct MockSignClient {
    call_count: AtomicUsize,
    responses: Mutex<HashMap<String, Vec<MockResponse>>>,
}

#[derive(Debug, Clone)]
struct MockResponse {
    status: StatusCode,
    body: Vec<u8>,
    headers: Option<HashMap<String, String>>,
}

impl MockSignClient {
    fn new() -> Self {
        Self {
            call_count: AtomicUsize::new(0),
            responses: Mutex::new(HashMap::new()),
        }
    }

    /// Add a sequence of responses for a URL pattern
    fn add_response_sequence(
        &self,
        url_pattern: impl Into<String>,
        responses: Vec<MockResponse>,
    ) {
        self.responses
            .lock()
            .unwrap()
            .insert(url_pattern.into(), responses);
    }

    /// Helper to create a JSON response
    fn json_response(status: StatusCode, json_value: serde_json::Value) -> MockResponse {
        MockResponse {
            status,
            body: serde_json::to_vec(&json_value).unwrap(),
            headers: Some({
                let mut headers = HashMap::new();
                headers.insert("content-type".to_string(), "application/json".to_string());
                headers
            }),
        }
    }

    /// Helper to create an error response
    fn error_response(status: StatusCode, message: &str) -> MockResponse {
        let error_json = json!({
            "errorDetail": {
                "code": "BadRequest",
                "message": message,
                "target": null
            }
        });
        Self::json_response(status, error_json)
    }
}

#[async_trait::async_trait]
impl HttpClient for MockSignClient {
    async fn execute_request(&self, request: &Request) -> Result<AsyncRawResponse> {
        let call_count = self.call_count.fetch_add(1, Ordering::SeqCst);
        let url = request.url().to_string();
        let method = request.method();

        // Route based on URL patterns
        let pattern = if url.contains("/sign/") && !url.contains("/sign?") {
            // GET /sign/{operation_id}
            "poll"
        } else if url.contains("/sign?") && method == Method::Post {
            // POST /sign
            "sign"
        } else {
            "unknown"
        };

        // Clone the responses to avoid lifetime issues
        let responses = self.responses.lock().unwrap().clone();
        
        if let Some(response_sequence) = responses.get(pattern) {
            // Get response based on call count for this pattern
            let response_index = call_count % response_sequence.len();
            let mock_response = &response_sequence[response_index];

            let mut headers = Headers::new();
            if let Some(header_map) = &mock_response.headers {
                for (key, value) in header_map {
                    headers.insert(key.clone(), value.clone());
                }
            }

            Ok(AsyncRawResponse::from_bytes(
                mock_response.status,
                headers,
                mock_response.body.clone(),
            ))
        } else {
            // Default 404 response
            Ok(AsyncRawResponse::from_bytes(
                StatusCode::NotFound,
                Headers::new(),
                b"Not Found".to_vec(),
            ))
        }
    }
}

// =================================================================
// Helper Functions
// =================================================================

fn create_mock_client_with_responses(
    sign_responses: Vec<MockResponse>,
    poll_responses: Vec<MockResponse>,
) -> CertificateProfileClient {
    let mock_client = Arc::new(MockSignClient::new());
    mock_client.add_response_sequence("sign", sign_responses);
    mock_client.add_response_sequence("poll", poll_responses);

    let transport = Transport::new(mock_client);
    
    let pipeline = Pipeline::new(
        Some("test-client"),
        Some("1.0.0"),
        ClientOptions {
            transport: Some(transport),
            ..Default::default()
        },
        Vec::new(),
        Vec::new(),
        None,
    );

    let options = CertificateProfileClientOptions::new(
        "https://test.codesigning.azure.net",
        "test-account", 
        "test-profile",
    );

    CertificateProfileClient::new_with_pipeline(options, pipeline)
        .expect("Should create client")
}

// =================================================================
// Test Cases
// =================================================================

// =================================================================
// Helper: Run test with proper runtime handling
// The CertificateProfileClient has an internal tokio runtime that cannot be
// dropped from within an async context. We use spawn_blocking to ensure
// the client is dropped in a blocking context.
// =================================================================

fn run_sign_test<F>(
    sign_responses: Vec<MockResponse>,
    poll_responses: Vec<MockResponse>,
    test_fn: F,
) where
    F: FnOnce(CertificateProfileClient) + Send + 'static,
{
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("Failed to create test runtime");
    
    rt.block_on(async {
        let client = create_mock_client_with_responses(sign_responses, poll_responses);
        
        // Run the test in a blocking context so the client can be dropped safely
        tokio::task::spawn_blocking(move || {
            test_fn(client);
        })
        .await
        .expect("Test task failed");
    });
}

// Test a much simpler scenario first to ensure our mock infrastructure works
#[test]
fn test_mock_client_basic() {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("Failed to create test runtime");
    
    rt.block_on(async {
        let mock_client = Arc::new(MockSignClient::new());
        let test_response = MockSignClient::json_response(
            StatusCode::Ok, 
            json!({"test": "value"})
        );
        mock_client.add_response_sequence("sign", vec![test_response]);
        
        // Just test that our mock works
        let request = Request::new(
            azure_core::http::Url::parse("https://test.example.com/sign?test").unwrap(),
            Method::Post
        );
        let response = mock_client.execute_request(&request).await;
        assert!(response.is_ok());
    });
}

#[test]
fn test_start_sign_and_poll_to_completion() {
    // Scenario: POST /sign -> 202 -> InProgress -> Succeeded
    
    let initial_sign_response = MockSignClient::json_response(
        StatusCode::Accepted,
        json!({
            "operationId": "op-12345",
            "status": "InProgress"
        })
    );

    let in_progress_response = MockSignClient::json_response(
        StatusCode::Ok,
        json!({
            "operationId": "op-12345", 
            "status": "InProgress"
        })
    );

    let completed_response = MockSignClient::json_response(
        StatusCode::Ok,
        json!({
            "operationId": "op-12345",
            "status": "Succeeded",
            "signature": "c2lnbmF0dXJlZGF0YQ==", // base64("signaturedata")
            "signingCertificate": "Y2VydGlmaWNhdGVkYXRh" // base64("certificatedata")
        })
    );

    run_sign_test(
        vec![initial_sign_response],
        vec![in_progress_response, completed_response],
        |client| {
            let digest = b"test-digest-sha256";
            // Use the sync sign() method which handles the internal runtime
            let result = client.sign("PS256", digest).expect("Should complete signing");

            assert_eq!(result.operation_id, "op-12345");
            assert_eq!(result.status, OperationStatus::Succeeded);
            assert_eq!(result.signature, Some("c2lnbmF0dXJlZGF0YQ==".to_string()));
            assert_eq!(result.signing_certificate, Some("Y2VydGlmaWNhdGVkYXRh".to_string()));
        },
    );
}

#[test]
fn test_start_sign_immediate_success() {
    // Scenario: POST /sign -> 200 with final status (no polling needed)
    
    let immediate_success_response = MockSignClient::json_response(
        StatusCode::Ok,
        json!({
            "operationId": "op-immediate",
            "status": "Succeeded", 
            "signature": "aW1tZWRpYXRlc2ln", // base64("immediatesig")
            "signingCertificate": "aW1tZWRpYXRlY2VydA==" // base64("immediatecert")
        })
    );

    run_sign_test(
        vec![immediate_success_response],
        vec![], // No polling needed
        |client| {
            let digest = b"another-test-digest";
            let result = client.sign("ES256", digest).expect("Should complete immediately");

            assert_eq!(result.operation_id, "op-immediate");
            assert_eq!(result.status, OperationStatus::Succeeded);
            assert_eq!(result.signature, Some("aW1tZWRpYXRlc2ln".to_string()));
            assert_eq!(result.signing_certificate, Some("aW1tZWRpYXRlY2VydA==".to_string()));
        },
    );
}

#[test]
fn test_start_sign_error_response() {
    // Scenario: POST /sign -> 400 error
    
    let error_response = MockSignClient::error_response(
        StatusCode::BadRequest,
        "Invalid signature algorithm"
    );

    run_sign_test(
        vec![error_response],
        vec![],
        |client| {
            let digest = b"test-digest";
            let result = client.sign("INVALID_ALG", digest);

            assert!(result.is_err());
            let error = result.unwrap_err();
            // The error should contain information about the HTTP failure
            assert!(error.to_string().contains("400") || error.to_string().contains("Bad"));
        },
    );
}

#[test]
fn test_start_sign_operation_failed() {
    // Scenario: POST /sign -> 202 -> InProgress -> Failed
    
    let initial_response = MockSignClient::json_response(
        StatusCode::Accepted,
        json!({
            "operationId": "op-failed",
            "status": "InProgress"
        })
    );

    let failed_response = MockSignClient::json_response(
        StatusCode::Ok,
        json!({
            "operationId": "op-failed",
            "status": "Failed"
        })
    );

    run_sign_test(
        vec![initial_response],
        vec![failed_response],
        |client| {
            let digest = b"failing-digest";
            let result = client.sign("PS256", digest);

            assert!(result.is_err());
            // The poller should detect the Failed status and return an error
        },
    );
}

#[test]
fn test_start_sign_multiple_in_progress_then_success() {
    // Scenario: POST /sign -> 202 -> InProgress x3 -> Succeeded
    // Tests polling persistence through multiple InProgress responses
    
    let initial_response = MockSignClient::json_response(
        StatusCode::Accepted,
        json!({
            "operationId": "op-long",
            "status": "InProgress"
        })
    );

    let in_progress1 = MockSignClient::json_response(
        StatusCode::Ok,
        json!({
            "operationId": "op-long",
            "status": "InProgress"
        })
    );

    let in_progress2 = MockSignClient::json_response(
        StatusCode::Ok,
        json!({
            "operationId": "op-long", 
            "status": "Running" // Alternative in-progress status
        })
    );

    let final_success = MockSignClient::json_response(
        StatusCode::Ok,
        json!({
            "operationId": "op-long",
            "status": "Succeeded",
            "signature": "bG9uZ3NpZ25hdHVyZQ==", // base64("longsignature")
            "signingCertificate": "bG9uZ2NlcnQ=" // base64("longcert")
        })
    );

    run_sign_test(
        vec![initial_response],
        vec![in_progress1, in_progress2, final_success],
        |client| {
            let digest = b"long-running-digest";
            let result = client.sign("RS256", digest).expect("Should eventually succeed");

            assert_eq!(result.operation_id, "op-long");
            assert_eq!(result.status, OperationStatus::Succeeded);
            assert_eq!(result.signature, Some("bG9uZ3NpZ25hdHVyZQ==".to_string()));
            assert_eq!(result.signing_certificate, Some("bG9uZ2NlcnQ=".to_string()));
        },
    );
}

#[test]
fn test_start_sign_timed_out_operation() {
    // Scenario: POST /sign -> 202 -> InProgress -> TimedOut
    
    let initial_response = MockSignClient::json_response(
        StatusCode::Accepted,
        json!({
            "operationId": "op-timeout",
            "status": "InProgress" 
        })
    );

    let timeout_response = MockSignClient::json_response(
        StatusCode::Ok,
        json!({
            "operationId": "op-timeout",
            "status": "TimedOut"
        })
    );

    run_sign_test(
        vec![initial_response],
        vec![timeout_response],
        |client| {
            let digest = b"timeout-digest";
            let result = client.sign("PS256", digest);

            assert!(result.is_err());
            // TimedOut status should be treated as failed by the poller
        },
    );
}

#[test]
fn test_start_sign_not_found_operation() {
    // Scenario: POST /sign -> 202 -> InProgress -> NotFound
    
    let initial_response = MockSignClient::json_response(
        StatusCode::Accepted,
        json!({
            "operationId": "op-notfound",
            "status": "InProgress"
        })
    );

    let not_found_response = MockSignClient::json_response(
        StatusCode::Ok,
        json!({
            "operationId": "op-notfound", 
            "status": "NotFound"
        })
    );

    run_sign_test(
        vec![initial_response],
        vec![not_found_response],
        |client| {
            let digest = b"notfound-digest";
            let result = client.sign("ES256", digest);

            assert!(result.is_err());
            // NotFound status should be treated as failed by the poller
        },
    );
}

#[test]
fn test_start_sign_malformed_json_response() {
    // Test error handling when the service returns invalid JSON
    
    let malformed_response = MockResponse {
        status: StatusCode::Ok,
        body: b"{ invalid json }".to_vec(),
        headers: Some({
            let mut headers = HashMap::new();
            headers.insert("content-type".to_string(), "application/json".to_string());
            headers
        }),
    };

    run_sign_test(
        vec![malformed_response],
        vec![],
        |client| {
            let digest = b"malformed-digest";
            let result = client.sign("PS256", digest);

            assert!(result.is_err());
            // Should fail to parse the malformed JSON response
        },
    );
}

#[test]
fn test_start_sign_creates_poller_sync() {
    // Test that start_sign returns a Poller without executing (sync test)
    let client = create_mock_client_with_responses(vec![], vec![]);
    
    let digest = b"sync-test-digest";
    let poller_result = client.start_sign("PS256", digest, None);
    
    assert!(poller_result.is_ok());
    // The Poller should be created successfully - actual execution happens on await
}