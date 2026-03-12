// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Rust port of `Azure.Security.CodeTransparency.CodeTransparencyClient`.
//!
//! Uses `azure_core::http::Pipeline` for HTTP requests with automatic retry,
//! user-agent telemetry, and logging — following the canonical Azure SDK client
//! pattern (same as `azure_security_keyvault_keys::KeyClient`).

use crate::api_key_auth_policy::ApiKeyAuthPolicy;
use crate::error::CodeTransparencyError;
use crate::models::{JwksDocument, JsonWebKey};
use crate::operation_status::OperationStatus;
use crate::transaction_not_cached_policy::TransactionNotCachedPolicy;
use azure_core::http::{
    Body, ClientOptions, Context, Method, Pipeline, Request,
    poller::{Poller, PollerContinuation, PollerResult, PollerState, PollerStatus, StatusMonitor},
    RawResponse, Response,
};
use cbor_primitives::CborDecoder;
use std::collections::HashMap;
use std::sync::Arc;
use url::Url;

/// Options for creating a [`CodeTransparencyClient`].
#[derive(Clone, Debug, Default)]
pub struct CodeTransparencyClientOptions {
    /// Azure SDK client options (retry, per-call/per-try policies, transport).
    pub client_options: ClientOptions,
}

/// Controls how offline keys interact with network JWKS fetching.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OfflineKeysBehavior {
    /// Try offline keys first; fall back to network if the key is not found.
    FallbackToNetwork,
    /// Use only offline keys; never make network requests for JWKS.
    OfflineOnly,
}

impl Default for OfflineKeysBehavior {
    fn default() -> Self { Self::FallbackToNetwork }
}

/// Configuration for the Code Transparency service instance.
#[derive(Debug)]
pub struct CodeTransparencyClientConfig {
    /// API version to use for requests (default: `"2024-01-01"`).
    pub api_version: String,
    /// Optional API key for Bearer token authentication.
    pub api_key: Option<String>,
    /// Offline JWKS documents keyed by issuer host.
    pub offline_keys: Option<HashMap<String, JwksDocument>>,
    /// Controls fallback behavior when offline keys don't contain the needed key.
    pub offline_keys_behavior: OfflineKeysBehavior,
}

impl Default for CodeTransparencyClientConfig {
    fn default() -> Self {
        Self {
            api_version: "2024-01-01".to_string(),
            api_key: None,
            offline_keys: None,
            offline_keys_behavior: OfflineKeysBehavior::FallbackToNetwork,
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
    #[cfg_attr(coverage_nightly, coverage(off))]
    pub fn with_options(
        endpoint: Url,
        config: CodeTransparencyClientConfig,
        options: CodeTransparencyClientOptions,
    ) -> Self {
        let per_call: Vec<Arc<dyn azure_core::http::policies::Policy>> = Vec::new();

        // Auth + TNC as per-retry (re-applied on each retry attempt)
        let mut per_retry: Vec<Arc<dyn azure_core::http::policies::Policy>> = Vec::new();
        if let Some(ref key) = config.api_key {
            per_retry.push(Arc::new(ApiKeyAuthPolicy::new(key.clone())));
        }
        per_retry.push(Arc::new(TransactionNotCachedPolicy::default()));

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
    pub fn endpoint(&self) -> &Url { &self.endpoint }

    // ========================================================================
    // REST API methods
    // ========================================================================

    /// `GET /.well-known/transparency-configuration`
    pub fn get_transparency_config_cbor(&self) -> Result<Vec<u8>, CodeTransparencyError> {
        self.send_get(&self.build_url("/.well-known/transparency-configuration"), "application/cbor")
    }

    /// `GET /jwks` — returns raw JWKS JSON string.
    pub fn get_public_keys(&self) -> Result<String, CodeTransparencyError> {
        let bytes = self.send_get(&self.build_url("/jwks"), "application/json")?;
        String::from_utf8(bytes)
            .map_err(|e| CodeTransparencyError::HttpError(format!("JWKS not UTF-8: {}", e)))
    }

    /// `GET /jwks` — returns typed [`JwksDocument`].
    pub fn get_public_keys_typed(&self) -> Result<JwksDocument, CodeTransparencyError> {
        let json = self.get_public_keys()?;
        JwksDocument::from_json(&json).map_err(CodeTransparencyError::HttpError)
    }

    /// `POST /entries` — returns a [`Poller<OperationStatus>`] for the LRO.
    ///
    /// The caller owns the poller and can `.await` it or stream intermediate status.
    /// This maps C# `CreateEntry(WaitUntil, ...)` — the `Poller` handles both
    /// `Started` (return immediately) and `Completed` (`.await`) semantics.
    #[cfg_attr(coverage_nightly, coverage(off))]
    pub fn create_entry(&self, cose_bytes: &[u8]) -> Result<Poller<OperationStatus>, CodeTransparencyError> {
        let pipeline = self.pipeline.clone();
        let api_version = self.config.api_version.clone();
        let endpoint = self.endpoint.clone();
        let cose_owned = cose_bytes.to_vec();

        Ok(Poller::new(
            move |poller_state: PollerState, poller_options| {
                let pipeline = pipeline.clone();
                let api_version = api_version.clone();
                let endpoint = endpoint.clone();
                let cose_owned = cose_owned.clone();

                Box::pin(async move {
                    let mut request = match poller_state {
                        PollerState::Initial => {
                            let mut url = endpoint.clone();
                            url.set_path("/entries");
                            url.query_pairs_mut().append_pair("api-version", &api_version);
                            let mut req = Request::new(url, Method::Post);
                            req.insert_header("content-type", "application/cose");
                            req.insert_header("accept", "application/cose; application/cbor");
                            req.set_body(Body::from(cose_owned));
                            req
                        }
                        PollerState::More(continuation) => {
                            let next_link = match continuation {
                                PollerContinuation::Links { next_link, .. } => next_link,
                                _ => return Err(azure_core::Error::new(
                                    azure_core::error::ErrorKind::Other,
                                    "unexpected poller continuation variant",
                                )),
                            };
                            let mut req = Request::new(next_link, Method::Get);
                            req.insert_header("accept", "application/cbor");
                            req
                        }
                    };

                    let rsp = pipeline.send(&poller_options.context, &mut request, None).await?;
                    let (status_code, headers, body) = rsp.deconstruct();
                    let body_bytes = body.as_ref().to_vec();

                    let op_status = read_cbor_text_field(&body_bytes, "Status").unwrap_or_default();
                    let operation_id = read_cbor_text_field(&body_bytes, "OperationId").unwrap_or_default();
                    let entry_id = read_cbor_text_field(&body_bytes, "EntryId");

                    let monitor = OperationStatus {
                        operation_id: operation_id.clone(),
                        operation_status: op_status,
                        entry_id,
                    };

                    // Re-serialize as JSON so Response<OperationStatus, JsonFormat> can deserialize
                    let monitor_json = serde_json::to_vec(&monitor)
                        .map_err(|e| azure_core::Error::new(azure_core::error::ErrorKind::DataConversion, e))?;
                    let response: Response<OperationStatus> =
                        RawResponse::from_bytes(status_code, headers, monitor_json).into();

                    match monitor.status() {
                        PollerStatus::Succeeded | PollerStatus::Failed | PollerStatus::Canceled => {
                            Ok(PollerResult::Done { response })
                        }
                        _ => {
                            let mut poll_url = endpoint.clone();
                            poll_url.set_path(&format!("/operations/{}", operation_id));
                            poll_url.query_pairs_mut().append_pair("api-version", &api_version);

                            Ok(PollerResult::InProgress {
                                response,
                                retry_after: poller_options.frequency,
                                continuation: PollerContinuation::Links {
                                    next_link: poll_url,
                                    final_link: None,
                                },
                            })
                        }
                    }
                })
            },
            None,
        ))
    }

    /// Convenience: create entry (poll to completion) + get statement.
    pub fn make_transparent(&self, cose_bytes: &[u8]) -> Result<Vec<u8>, CodeTransparencyError> {
        let poller = self.create_entry(cose_bytes)?;
        let result = self.runtime.block_on(async { poller.await })
            .map_err(CodeTransparencyError::from_azure_error)?
            .into_model()
            .map_err(CodeTransparencyError::from_azure_error)?;
        let entry_id = result.entry_id.unwrap_or_default();
        self.get_entry_statement(&entry_id)
    }

    /// `GET /operations/{operationId}`
    pub fn get_operation(&self, operation_id: &str) -> Result<Vec<u8>, CodeTransparencyError> {
        self.send_get(&self.build_url(&format!("/operations/{}", operation_id)), "application/cbor")
    }

    /// `GET /entries/{entryId}` — receipt (COSE).
    pub fn get_entry(&self, entry_id: &str) -> Result<Vec<u8>, CodeTransparencyError> {
        self.send_get(&self.build_url(&format!("/entries/{}", entry_id)), "application/cose")
    }

    /// `GET /entries/{entryId}/statement` — transparent statement (COSE with embedded receipts).
    pub fn get_entry_statement(&self, entry_id: &str) -> Result<Vec<u8>, CodeTransparencyError> {
        self.send_get(&self.build_url(&format!("/entries/{}/statement", entry_id)), "application/cose")
    }

    /// Resolve the service signing key by `kid`.
    ///
    /// Maps C# `GetServiceCertificateKey`:
    /// 1. Check offline keys (if configured)
    /// 2. Fall back to network JWKS fetch (if allowed)
    pub fn resolve_signing_key(&self, kid: &str) -> Result<JsonWebKey, CodeTransparencyError> {
        if let Some(ref offline) = self.config.offline_keys {
            for jwks in offline.values() {
                if let Some(key) = jwks.find_key(kid) {
                    return Ok(key.clone());
                }
            }
        }
        if self.config.offline_keys_behavior == OfflineKeysBehavior::OfflineOnly {
            return Err(CodeTransparencyError::HttpError(format!(
                "key '{}' not found in offline keys and network fallback is disabled", kid
            )));
        }
        let jwks = self.get_public_keys_typed()?;
        jwks.find_key(kid).cloned().ok_or_else(|| {
            CodeTransparencyError::HttpError(format!("key '{}' not found in JWKS", kid))
        })
    }

    // ========================================================================
    // Internal
    // ========================================================================

    fn build_url(&self, path: &str) -> Url {
        let mut url = self.endpoint.clone();
        url.set_path(path);
        url.query_pairs_mut().append_pair("api-version", &self.config.api_version);
        url
    }

    fn send_get(&self, url: &Url, accept: &str) -> Result<Vec<u8>, CodeTransparencyError> {
        self.runtime.block_on(async {
            let mut request = Request::new(url.clone(), Method::Get);
            request.insert_header("accept", accept.to_string());
            let ctx = Context::new();
            let response = self.pipeline.stream(&ctx, &mut request, None).await
                .map_err(CodeTransparencyError::from_azure_error)?;
            let body = response.into_body().collect().await
                .map_err(|e| CodeTransparencyError::HttpError(e.to_string()))?;
            Ok(body.to_vec())
        })
    }

    fn send_post(&self, url: &Url, content_type: &str, accept: &str, body: Vec<u8>) -> Result<Vec<u8>, CodeTransparencyError> {
        self.runtime.block_on(async {
            let mut request = Request::new(url.clone(), Method::Post);
            request.insert_header("content-type", content_type.to_string());
            request.insert_header("accept", accept.to_string());
            request.set_body(Body::from(body));
            let ctx = Context::new();
            let response = self.pipeline.stream(&ctx, &mut request, None).await
                .map_err(CodeTransparencyError::from_azure_error)?;
            let resp_body = response.into_body().collect().await
                .map_err(|e| CodeTransparencyError::HttpError(e.to_string()))?;
            Ok(resp_body.to_vec())
        })
    }
}

/// Read a text field from a CBOR map.
pub(crate) fn read_cbor_text_field(bytes: &[u8], key: &str) -> Option<String> {
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
