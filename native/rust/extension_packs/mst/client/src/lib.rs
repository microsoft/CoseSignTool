// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![cfg_attr(coverage_nightly, feature(coverage_attribute))]

//! Rust port of `Azure.Security.CodeTransparency` — REST client for the
//! Azure Code Transparency Service (MST).
//!
//! This crate provides a [`CodeTransparencyClient`] that follows the canonical
//! Azure SDK client pattern, using `azure_core::http::Pipeline` for automatic
//! retry, user-agent telemetry, request-id headers, and logging.
//!
//! ## Pipeline Policies
//!
//! - [`ApiKeyAuthPolicy`] — per-call Bearer token auth (when `api_key` is set)
//! - [`TransactionNotCachedPolicy`] — per-retry fast 503 retry on `/entries/` GETs

pub mod api_key_auth_policy;
pub mod cbor_problem_details;
pub mod client;
pub mod error;
pub mod models;
pub mod operation_status;
pub mod polling;
pub mod transaction_not_cached_policy;

#[cfg(feature = "test-utils")]
pub mod mock_transport;

pub use client::{
    CodeTransparencyClient, CodeTransparencyClientConfig, CodeTransparencyClientOptions,
    CreateEntryResult, OfflineKeysBehavior,
};
pub use error::CodeTransparencyError;
pub use models::{JwksDocument, JsonWebKey};
pub use polling::{DelayStrategy, MstPollingOptions};
pub use transaction_not_cached_policy::TransactionNotCachedPolicy;
