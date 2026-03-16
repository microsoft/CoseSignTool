// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Pipeline policy that adds an API key as a Bearer token on every request.
//!
//! Register as a **per-call** policy so the key is added once before the retry loop.

use async_trait::async_trait;
use azure_core::http::{
    policies::{Policy, PolicyResult},
    Context, Request,
};
use std::sync::Arc;

/// Pipeline policy that injects `Authorization: Bearer {api_key}` on every request.
#[derive(Debug, Clone)]
pub struct ApiKeyAuthPolicy {
    api_key: String,
}

impl ApiKeyAuthPolicy {
    /// Creates a new policy with the given API key.
    pub fn new(api_key: impl Into<String>) -> Self {
        Self { api_key: api_key.into() }
    }
}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl Policy for ApiKeyAuthPolicy {
    async fn send(
        &self,
        ctx: &Context,
        request: &mut Request,
        next: &[Arc<dyn Policy>],
    ) -> PolicyResult {
        request.insert_header("authorization", format!("Bearer {}", self.api_key));
        next[0].send(ctx, request, &next[1..]).await
    }
}
