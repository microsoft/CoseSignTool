// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! COSE algorithm constants and Sign1-specific values.
//!
//! IANA algorithm identifiers are re-exported from `cose_primitives`.
//! This module adds Sign1-specific constants like the CBOR tag.

// Re-export all algorithm constants from cose_primitives
pub use cose_primitives::algorithms::*;

/// CBOR tag for COSE_Sign1 messages (RFC 9052).
pub const COSE_SIGN1_TAG: u64 = 18;

/// Threshold (in bytes) for considering a payload "large" for streaming.
///
/// Payloads larger than this size should use streaming APIs to avoid
/// loading the entire content into memory.
pub const LARGE_PAYLOAD_THRESHOLD: u64 = 85_000;
