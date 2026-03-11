// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Pipeline policy for fast-retrying MST `TransactionNotCached` 503 responses.
//!
//! The Azure Code Transparency Service returns HTTP 503 with a CBOR problem-details
//! body containing `TransactionNotCached` when a newly registered entry hasn't
//! propagated to the serving node yet. The entry typically becomes available in
//! well under 1 second.
//!
//! This policy intercepts that specific pattern on GET `/entries/` requests and
//! performs fast retries (default: 250 ms × 8 = 2 seconds) *inside* the pipeline,
//! before the SDK's standard retry policy sees the response. This mirrors the C#
//! `MstTransactionNotCachedPolicy` behaviour.
//!
//! Registered as a **per-retry** policy so it runs inside the SDK's retry loop.

use crate::cbor_problem_details::CborProblemDetails;
use azure_core::http::{
    policies::{Policy, PolicyResult},
    AsyncRawResponse, Context, Method, Request,
};
use async_trait::async_trait;
use std::sync::Arc;
use std::time::Duration;

/// Pipeline policy that fast-retries `TransactionNotCached` 503 responses.
///
/// Only applies to GET requests whose URL path contains `/entries/`.
/// All other requests pass through with a single `next.send()` call.
#[derive(Debug, Clone)]
pub struct TransactionNotCachedPolicy {
    retry_delay: Duration,
    max_retries: u32,
}

impl Default for TransactionNotCachedPolicy {
    fn default() -> Self {
        Self {
            retry_delay: Duration::from_millis(250),
            max_retries: 8,
        }
    }
}

impl TransactionNotCachedPolicy {
    /// Creates a policy with custom retry settings.
    pub fn new(retry_delay: Duration, max_retries: u32) -> Self {
        Self { retry_delay, max_retries }
    }

    /// Checks if a response body contains the `TransactionNotCached` error code.
    pub fn is_tnc_body(body: &[u8]) -> bool {
        if body.is_empty() {
            return false;
        }
        let pd = match CborProblemDetails::try_parse(body) {
            Some(pd) => pd,
            None => return false,
        };
        let needle = "transactionnotcached";
        if pd.detail.as_ref().map_or(false, |s| s.to_lowercase().contains(needle)) {
            return true;
        }
        if pd.title.as_ref().map_or(false, |s| s.to_lowercase().contains(needle)) {
            return true;
        }
        if pd.problem_type.as_ref().map_or(false, |s| s.to_lowercase().contains(needle)) {
            return true;
        }
        pd.extensions.values().any(|v| v.to_lowercase().contains(needle))
    }

    fn is_entries_get(request: &Request) -> bool {
        request.method() == Method::Get && request.url().path().contains("/entries/")
    }

    /// Consume body and return (bytes, reconstructed response).
    async fn read_body(response: AsyncRawResponse) -> azure_core::Result<(Vec<u8>, AsyncRawResponse)> {
        let status = response.status();
        let headers = response.headers().clone();
        let body = response.into_body().collect().await?;
        let rebuilt = AsyncRawResponse::from_bytes(status, headers, body.clone());
        Ok((body.to_vec(), rebuilt))
    }
}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl Policy for TransactionNotCachedPolicy {
    async fn send(
        &self,
        ctx: &Context,
        request: &mut Request,
        next: &[Arc<dyn Policy>],
    ) -> PolicyResult {
        if !Self::is_entries_get(request) {
            return next[0].send(ctx, request, &next[1..]).await;
        }

        let response = next[0].send(ctx, request, &next[1..]).await?;
        if u16::from(response.status()) != 503 {
            return Ok(response);
        }

        let (body, rebuilt) = Self::read_body(response).await?;
        if !Self::is_tnc_body(&body) {
            return Ok(rebuilt);
        }

        let mut last = rebuilt;
        for _ in 0..self.max_retries {
            tokio::time::sleep(self.retry_delay).await;
            let r = next[0].send(ctx, request, &next[1..]).await?;
            if u16::from(r.status()) != 503 {
                return Ok(r);
            }
            let (rb, rr) = Self::read_body(r).await?;
            if !Self::is_tnc_body(&rb) {
                return Ok(rr);
            }
            last = rr;
        }

        Ok(last)
    }
}
