// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![cfg_attr(coverage_nightly, feature(coverage_attribute))]
#![deny(missing_docs)]

//! `cose_sign1_trustfrontends_json` — Phase 2 (np-frontend-json) of the native Rust
//! trust-policy port.
//!
//! Workspace-member skeleton. Subsequent commits add the embedded JSON Schema, the
//! `CoseTpJsonFrontend` translator (parse + schema-validate + walk), the LRU
//! translator cache, and CLI integration.
