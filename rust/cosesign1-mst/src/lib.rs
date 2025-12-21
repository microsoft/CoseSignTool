// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Microsoft Signing Transparency (MST) parity crate.
//!
//! This crate exists to mirror the native MST verification APIs:
//! - `VerifyTransparentStatement`
//! - `VerifyTransparentStatementOnline`
//! - `VerifyTransparentStatementReceipt`
//!
//! The Rust port currently exposes the same surface area as the native verifier.

pub mod mst_verifier;

// Re-export the public API from the internal module.
pub use mst_verifier::{
	verify_transparent_statement, verify_transparent_statement_online, verify_transparent_statement_receipt,
	add_issuer_keys, expected_alg_from_crv, jwk_ec_to_spki_der, parse_jwks, AuthorizedReceiptBehavior, JwkEcPublicKey,
	JwksDocument, JwksFetcher, OfflineEcKeyStore, ResolvedKey,
	UnauthorizedReceiptBehavior, VerificationOptions,
};
