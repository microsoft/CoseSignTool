// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Common COSE_Sign1 parsing and encoding helpers.
//!
//! This crate is shared by higher-level verifiers.
//! It intentionally exposes only a small surface area:
//! - Parse COSE_Sign1 into a structured form.
//! - Decode COSE header maps into strongly typed values.
//! - Encode the Sig_structure bytes used for signature verification.

pub mod cose_sign1;
pub mod header_map;

// Re-export the core entry points so consumers can depend on this crate without
// needing to know the internal module layout.
pub use cose_sign1::{encode_signature1_sig_structure, parse_cose_sign1, ParsedCoseSign1, SigStructureView};
pub use header_map::{CoseHeaderMap, HeaderKey, HeaderValue};
