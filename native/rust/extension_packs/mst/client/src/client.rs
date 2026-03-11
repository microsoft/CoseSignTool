// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Rust port of `Azure.Security.CodeTransparency.CodeTransparencyClient`.
//!
//! Uses `azure_core::http::Pipeline` for HTTP requests with automatic retry,
//! user-agent telemetry, and logging — following the canonical Azure SDK client
//! pattern (same as `azure_security_keyvault_keys::KeyClient`).
//!
//! ## REST API
//!
//! | Method | Path | Accept |
//! |--------|------|--------|
//! | GET | `/.well-known/transparency-configuration` | `application/cbor` |
//! | GET | `/jwks` | `application/json` |
//! | POST | `/entries` | `application/cose; application/cbor` |
//! | GET | `/operations/{operationId}` | `application/cbor` |
//! | GET | `/entries/{entryId}` | `application/cose` |
//! | GET | `/entries/{entryId}/statement` | `application/cose` |

use crate::api_key_auth_policy::ApiKeyAuthPolicy;
use crate::error::CodeTransparencyError;
use crate::polling::MstPollingOptions;
use crate::transaction_not_cached_policy::TransactionNotCachedPolicy;
use azure_core::http::{
    Body, ClientOptions, Context, Method, Pipeline, Request,
};
use cbor_primitives::CborDecoder;
use std::sync::Arc;
use std::thread;
use std::time::Duration;
use url::Url;

/// Options for creating a [`CodeTransparencyClient`].
///
/// Maps C# `CodeTransparencyClientOptions`.
#[derive(Clone, Debug, Default)]
pub struct CodeTransparencyClientOptions {
    /// Azure SDK client options (retry, per-call/per-try policies, transport).
    pub client_options: ClientOptions,
}

/// Configuration for the Code Transparency service instance.
#[derive(Debug)]
pub struct CodeTransparencyClientConfig {
    /// API version to use for requests (default: `"2024-01-01"`).
    pub api_version: String,
    /// Optional API key for Bearer token authentication.
    pub api_key: Option<String>,
    /// Maximum number of polling attempts for operation status (default: 30).
    pub max_poll_retries: u32,
    /// Delay between polling attempts (default: 2 seconds).
    pub poll_delay: Duration,
    /// Optional advanced polling options. Takes precedence over `poll_delay`
    /// and `max_poll_retries` when set.
    pub polling_options: Option<MstPollingOptions>,
}

impl Default for CodeTransparencyClientConfig {
    fn default() -> Self {
        Self {
            api_version: "2024-01-01".to_string(),
            api_key: None,
            max_poll_retries: 30,
            poll_delay: Duration::from_secs(2),
            polling_options: None,
        }
    }
}

/// Result from creating a transparency entry (long-running operation).
#[derive(Debug, Clone)]
pub struct CreateEntryResult {
    /// The operation ID returned by the service.
    pub operation_id: String,
    /// The final entry ID after the operation completes.
    pub entry_id: String,
}

/// Client for the Azure Code Transparency Service.
///
/// Port of C# `Azure.Security.CodeTransparency.CodeTransparencyClient`.
///
/// The pipeline automatically provides:
/// - Exponential retry with back-off on 5xx/429
/// - `TransactionNotCachedPolicy` for fast 503 retry on `/entries/` GETs
/// - `ApiKeyAuthPolicy` for Bearer token auth (if `api_key` is configured)
/// - User-agent, request-id, and logging
pub struct CodeTransparencyClient {
    endpoint: Url,
    config: CodeTransparencyClientConfig,
    pipeline: Pipeline,
    runtime: tokio::runtime::Runtime,
}

impl std::fmt::Debug for CodeTransparencyClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CodeTransparencyClient")
            .field("endpoint", &self.endpoint)
            .field("config", &self.config)
            .finish()
    }
}

impl CodeTransparencyClient {
    /// Creates a new client with default pipeline options.
    #[cfg_attr(coverage_nightly, coverage(off))]
    pub fn new(endpoint: Url, config: CodeTransparencyClientConfig) -> Self {
        Self::with_options(endpoint, config, CodeTransparencyClientOptions::default())
    }

    /// Creates a new client with custom pipeline options.
    ///
    /// Use this to configure retry behaviour, custom policies, or inject a
    /// mock transport for testing.
    #[cfg_attr(coverage_nightly, coverage(off))]
    pub fn with_options(
        endpoint: Url,
        config: CodeTransparencyClientConfig,
        options: CodeTransparencyClientOptions,
    ) -> Self {
        // Per-call policies (run once before retry loop)
        let mut per_call: Vec<Arc<dyn azure_core::http::policies::Policy>> = Vec::new();
        if let Some(ref key) = config.api_key {
            per_call.push(Arc::new(ApiKeyAuthPolicy::new(key.clone())));
        }

        // Per-retry policies (run inside retry loop)
        let per_retry: Vec<Arc<dyn azure_core::http::policies::Policy>> =
            vec![Arc::new(TransactionNotCachedPolicy::default())];

        let pipeline = Pipeline::new(
            option_env!("CARGO_PKG_NAME"),
            option_env!("CARGO_PKG_VERSION"),
            options.client_options,
            per_call,
            per_retry,
            None,
        );

        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("failed to create tokio runtime");

        Self { endpoint, config, pipeline, runtime }
    }

    /// Creates a new client with an injected pipeline (for testing).
    pub fn with_pipeline(endpoint: Url, config: CodeTransparencyClientConfig, pipeline: Pipeline) -> Self {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("failed to create tokio runtime");
        Self { endpoint, config, pipeline, runtime }
    }

    /// Returns the service endpoint URL.
    pub fn endpoint(&self) -> &Url {
        &self.endpoint
    }

    // ========================================================================
    // REST API methods (matching C# CodeTransparencyClient)
    // ========================================================================

    /// Get the transparency service configuration (CBOR).
    ///
    /// `GET /.well-known/transparency-configuration?api-version=...`
    pub fn get_transparency_config_cbor(&self) -> Result<Vec<u8>, CodeTransparencyError> {
        let url = self.build_url("/.well-known/transparency-configuration");
        self.send_get(&url, "application/cbor")
    }

    /// Get the public keys (JWKS) used by the service to sign receipts.
    ///
    /// `GET /jwks?api-version=...`
    ///
    /// Returns the JWKS JSON string.
    pub fn get_public_keys(&self) -> Result<String, CodeTransparencyError> {
        let url = self.build_url("/jwks");
        let bytes = self.send_get(&url, "application/json")?;
        String::from_utf8(bytes)
            .map_err(|e| CodeTransparencyError::HttpError(format!("JWKS not UTF-8: {}", e)))
    }

    /// Create a transparency entry (long-running operation).
    ///
    /// `POST /entries?api-version=...`
    ///
    /// Submits COSE bytes, polls the operation to completion, and returns
    /// both the `operation_id` and `entry_id`.
    pub fn create_entry(&self, cose_bytes: &[u8]) -> Result<CreateEntryResult, CodeTransparencyError> {
        let url = self.build_url("/entries");

        let response_body = self.send_post(
            &url,
            "application/cose",
            "application/cose; application/cbor",
            cose_bytes.to_vec(),
        )?;

        let operation_id = read_cbor_text_field(&response_body, "OperationId")
            .ok_or_else(|| CodeTransparencyError::MissingField {
                field: "OperationId".to_string(),
            })?;

        let entry_id = self.poll_operation(&operation_id)?;

        Ok(CreateEntryResult { operation_id, entry_id })
    }

    /// Get the status of a long-running operation (CBOR).
    ///
    /// `GET /operations/{operationId}?api-version=...`
    pub fn get_operation(&self, operation_id: &str) -> Result<Vec<u8>, CodeTransparencyError> {
        let url = self.build_url(&format!("/operations/{}", operation_id));
        self.send_get(&url, "application/cbor")
    }

    /// Get a receipt for an entry (COSE).
    ///
    /// `GET /entries/{entryId}?api-version=...`
    pub fn get_entry(&self, entry_id: &str) -> Result<Vec<u8>, CodeTransparencyError> {
        let url = self.build_url(&format!("/entries/{}", entry_id));
        self.send_get(&url, "application/cose")
    }

    /// Get the transparent statement for an entry (COSE with embedded receipts).
    ///
    /// `GET /entries/{entryId}/statement?api-version=...`
    ///
    /// The `TransactionNotCachedPolicy` automatically handles 503 fast retry.
    pub fn get_entry_statement(&self, entry_id: &str) -> Result<Vec<u8>, CodeTransparencyError> {
        let url = self.build_url(&format!("/entries/{}/statement", entry_id));
        self.send_get(&url, "application/cose")
    }

    /// Convenience: create entry + poll + get statement.
    pub fn make_transparent(&self, cose_bytes: &[u8]) -> Result<Vec<u8>, CodeTransparencyError> {
        let result = self.create_entry(cose_bytes)?;
        self.get_entry_statement(&result.entry_id)
    }

    // ========================================================================
    // Internal helpers
    // ========================================================================

    /// Build a URL with the api-version query parameter.
    fn build_url(&self, path: &str) -> Url {
        let mut url = self.endpoint.clone();
        url.set_path(path);
        url.query_pairs_mut()
            .append_pair("api-version", &self.config.api_version);
        url
    }

    /// Send a GET through the pipeline. Returns body bytes on 2xx.
    ///
    /// Non-2xx → `check_success` → `azure_core::Error(HttpResponse{...})`
    /// → mapped to `CodeTransparencyError::ServiceError` via `from_azure_error`.
    fn send_get(&self, url: &Url, accept: &str) -> Result<Vec<u8>, CodeTransparencyError> {
        self.runtime.block_on(async {
            let mut request = Request::new(url.clone(), Method::Get);
            request.insert_header("accept", accept.to_string());
            let ctx = Context::new();
            let response = self.pipeline
                .stream(&ctx, &mut request, None)
                .await
                .map_err(CodeTransparencyError::from_azure_error)?;
            let body = response.into_body().collect().await
                .map_err(|e| CodeTransparencyError::HttpError(e.to_string()))?;
            Ok(body.to_vec())
        })
    }

    /// Send a POST through the pipeline. Returns body bytes on 2xx.
    fn send_post(&self, url: &Url, content_type: &str, accept: &str, body: Vec<u8>) -> Result<Vec<u8>, CodeTransparencyError> {
        self.runtime.block_on(async {
            let mut request = Request::new(url.clone(), Method::Post);
            request.insert_header("content-type", content_type.to_string());
            request.insert_header("accept", accept.to_string());
            request.set_body(Body::from(body));
            let ctx = Context::new();
            let response = self.pipeline
                .stream(&ctx, &mut request, None)
                .await
                .map_err(CodeTransparencyError::from_azure_error)?;
            let resp_body = response.into_body().collect().await
                .map_err(|e| CodeTransparencyError::HttpError(e.to_string()))?;
            Ok(resp_body.to_vec())
        })
    }

    /// Poll an operation until it completes or times out.
    fn poll_operation(&self, operation_id: &str) -> Result<String, CodeTransparencyError> {
        let max_retries = match &self.config.polling_options {
            Some(po) => po.effective_max_retries(self.config.max_poll_retries),
            None => self.config.max_poll_retries,
        };

        for retry in 0..max_retries {
            let response = self.get_operation(operation_id)?;

            if let Some(status) = read_cbor_text_field(&response, "Status") {
                match status.as_str() {
                    "Succeeded" => {
                        return read_cbor_text_field(&response, "EntryId")
                            .ok_or_else(|| CodeTransparencyError::MissingField {
                                field: "EntryId".to_string(),
                            });
                    }
                    "Failed" => {
                        return Err(CodeTransparencyError::OperationFailed {
                            operation_id: operation_id.to_string(),
                            status,
                        });
                    }
                    "Running" => {
                        let delay = match &self.config.polling_options {
                            Some(po) => po.delay_for_retry(retry, self.config.poll_delay),
                            None => self.config.poll_delay,
                        };
                        thread::sleep(delay);
                    }
                    _ => {
                        return Err(CodeTransparencyError::OperationFailed {
                            operation_id: operation_id.to_string(),
                            status,
                        });
                    }
                }
            } else {
                return Err(CodeTransparencyError::MissingField {
                    field: "Status".to_string(),
                });
            }
        }

        Err(CodeTransparencyError::OperationTimeout {
            operation_id: operation_id.to_string(),
            retries: max_retries,
        })
    }
}

/// Read a text field from a CBOR map.
fn read_cbor_text_field(bytes: &[u8], key: &str) -> Option<String> {
    let mut d = cose_sign1_primitives::provider::decoder(bytes);
    let map_len = d.decode_map_len().ok()?;
    for _ in 0..map_len.unwrap_or(usize::MAX) {
        let k = d.decode_tstr().ok()?;
        if k == key {
            return d.decode_tstr().ok().map(|s| s.to_string());
        }
        d.skip().ok()?;
    }
    None
}
