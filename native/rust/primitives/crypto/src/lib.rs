// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Cryptographic backend traits for pluggable crypto providers.
//!
//! This crate defines pure traits for cryptographic operations without
//! any implementation or external dependencies. It mirrors the
//! `cbor_primitives` architecture in the workspace.
//!
//! ## Purpose
//!
//! - **Zero external dependencies** — only `std` types
//! - **Backend-agnostic** — no knowledge of COSE, CBOR, or protocol details
//! - **Pluggable** — implementations can use OpenSSL, Ring, BoringSSL, or remote KMS
//! - **Streaming support** — optional trait methods for chunked signing/verification
//!
//! ## Architecture
//!
//! - `CryptoSigner` / `CryptoVerifier` — single-shot sign/verify
//! - `SigningContext` / `VerifyingContext` — streaming sign/verify
//! - `CryptoProvider` — factory for creating signers/verifiers from DER keys
//! - `CryptoError` — error type for all crypto operations
//!
//! ## Maps V2 C#
//!
//! This crate maps to the crypto abstraction layer that will be extracted
//! from `CoseSign1.Certificates` in the V2 C# codebase. The V2 C# code
//! currently uses `X509Certificate2` directly; this Rust design separates
//! the crypto primitives from X.509 certificate handling.

pub mod algorithms;
pub mod error;
pub mod provider;
pub mod signer;
pub mod verifier;

// Re-export all public types
pub use error::CryptoError;
pub use provider::{CryptoProvider, NullCryptoProvider};
pub use signer::{CryptoSigner, SigningContext};
pub use verifier::{CryptoVerifier, VerifyingContext};
