// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Mock HTTP transport implementing the azure_core `HttpClient` trait.
//!
//! Injected via `azure_core::http::ClientOptions::transport` to test
//! code that sends requests through the pipeline without hitting the network.
//!
//! Available only with the `test-utils` feature.

use azure_core::http::{headers::Headers, AsyncRawResponse, HttpClient, Request, StatusCode};
use std::collections::VecDeque;
use std::sync::Mutex;

/// A canned HTTP response for the mock transport.
#[derive(Clone, Debug)]
pub struct MockResponse {
    pub status: u16,
    pub content_type: Option<String>,
    pub body: Vec<u8>,
}

impl MockResponse {
    /// Create a successful response (200 OK) with a body.
    pub fn ok(body: Vec<u8>) -> Self {
        Self {
            status: 200,
            content_type: None,
            body,
        }
    }

    /// Create a response with a specific status code and body.
    pub fn with_status(status: u16, body: Vec<u8>) -> Self {
        Self {
            status,
            content_type: None,
            body,
        }
    }

    /// Create a response with status, content type, and body.
    pub fn with_content_type(status: u16, content_type: &str, body: Vec<u8>) -> Self {
        Self {
            status,
            content_type: Some(content_type.to_string()),
            body,
        }
    }
}

/// Mock HTTP client that returns sequential canned responses.
///
/// Responses are consumed in FIFO order regardless of request URL or method.
/// Use this to test client methods that make a known sequence of HTTP calls.
///
/// # Example
///
/// ```ignore
/// let mock = SequentialMockTransport::new(vec![
///     MockResponse::ok(eku_json_bytes),
///     MockResponse::ok(root_cert_der_bytes),
/// ]);
/// let client_options = mock.into_client_options();
/// let pipeline = azure_core::http::Pipeline::new(
///     Some("test"), Some("0.1.0"), client_options, vec![], vec![], None,
/// );
/// let client = CertificateProfileClient::new_with_pipeline(options, pipeline).unwrap();
/// ```
pub struct SequentialMockTransport {
    responses: Mutex<VecDeque<MockResponse>>,
}

impl std::fmt::Debug for SequentialMockTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let remaining = self.responses.lock().map(|q| q.len()).unwrap_or(0);
        f.debug_struct("SequentialMockTransport")
            .field("remaining_responses", &remaining)
            .finish()
    }
}

impl SequentialMockTransport {
    /// Create a mock transport with a sequence of canned responses.
    pub fn new(responses: Vec<MockResponse>) -> Self {
        Self {
            responses: Mutex::new(VecDeque::from(responses)),
        }
    }

    /// Convert into `ClientOptions` with no retry (for predictable mock sequencing).
    pub fn into_client_options(self) -> azure_core::http::ClientOptions {
        use azure_core::http::{RetryOptions, Transport};
        let transport = Transport::new(std::sync::Arc::new(self));
        azure_core::http::ClientOptions {
            transport: Some(transport),
            retry: RetryOptions::none(),
            ..Default::default()
        }
    }
}

#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
impl HttpClient for SequentialMockTransport {
    async fn execute_request(&self, _request: &Request) -> azure_core::Result<AsyncRawResponse> {
        let resp = self
            .responses
            .lock()
            .map_err(|_| {
                azure_core::Error::new(
                    azure_core::error::ErrorKind::Other,
                    "mock lock poisoned",
                )
            })?
            .pop_front()
            .ok_or_else(|| {
                azure_core::Error::new(
                    azure_core::error::ErrorKind::Other,
                    "no more mock responses",
                )
            })?;

        let status =
            StatusCode::try_from(resp.status).unwrap_or(StatusCode::InternalServerError);

        let mut headers = Headers::new();
        if let Some(ct) = resp.content_type {
            headers.insert("content-type", ct);
        }

        Ok(AsyncRawResponse::from_bytes(status, headers, resp.body))
    }
}
