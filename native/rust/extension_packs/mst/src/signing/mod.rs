// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! MST transparency provider for COSE_Sign1 signing.
//!
//! Wraps `code_transparency_client::CodeTransparencyClient` to implement
//! the `TransparencyProvider` trait from `cose_sign1_signing`.

pub mod service;

pub use service::MstTransparencyProvider;
