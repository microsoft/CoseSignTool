// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! COSE algorithm constants (IANA registrations).
//!
//! Algorithm identifiers are re-exported from `crypto_primitives`.
//! These are RFC/IANA-level constants shared across all COSE message types.
//!
//! For Sign1-specific constants (e.g., `COSE_SIGN1_TAG`, `LARGE_PAYLOAD_THRESHOLD`),
//! see `cose_sign1_primitives::algorithms`.

// Re-export all algorithm constants from crypto_primitives
pub use crypto_primitives::algorithms::*;
