// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! CoseSignTool — CLI for COSE_Sign1 signing, verification, and inspection.
//!
//! Mirrors the V2 .NET CoseSignTool command structure:
//! ```text
//! CoseSignTool sign x509 {pfx|pem|ats|ephemeral|akv-cert} <payload> [options]
//! CoseSignTool verify {x509|scitt} <signature> [--payload <file>]
//! CoseSignTool inspect <signature>
//! ```

pub mod commands;
pub mod output;
pub mod plugin_host;
pub mod providers;
