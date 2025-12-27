// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! High-level COSE_Sign1 verification facade.
//!
//! This crate is the primary Rust entry point for verifying COSE_Sign1 messages.
//!
//! Design note: to keep the public API simple, parsing and signature verification
//! APIs are exposed directly at the crate root (no `common` / `validation` submodules).

// Internal implementation modules.
mod header_map;
mod cose_sign1;
mod cose_sign1_verifier;

// Public API organization (lib.rs is a publisher).
mod algorithms;
mod api;
mod message;
mod read_seek;
mod settings;
mod verify_options;

pub use algorithms::{CoseAlgorithm, CoseHashAlgorithm};
pub use message::CoseSign1;
pub use read_seek::ReadSeek;
pub use settings::{SignatureVerificationSettings, VerificationSettings};
pub use verify_options::VerifyOptions;

pub use api::{
    encode_signature1_sig_structure,
    parse_cose_sign1,
    parse_cose_sign1_from_reader,
    parse_cose_sign1_from_reader_with_max_len,
    verify_cose_sign1,
    verify_parsed_cose_sign1,
    verify_parsed_cose_sign1_detached_payload_reader,
    verify_sig_structure,
};
