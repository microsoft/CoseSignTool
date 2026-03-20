// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![cfg_attr(coverage_nightly, feature(coverage_attribute))]

//! # CoseSign1 Primitives
//!
//! Core types and traits for CoseSign1 signing and verification with pluggable CBOR.
//!
//! This crate provides the foundational types for working with COSE_Sign1 messages
//! as defined in RFC 9052. It is designed to be minimal with only `cose_primitives`,
//! `cbor_primitives`, and `crypto_primitives` as dependencies, making it suitable
//! for constrained environments.
//!
//! ## Relationship to `cose_primitives`
//!
//! Generic COSE types (headers, algorithm constants, CBOR provider) live in
//! [`cose_primitives`] and are re-exported here for convenience. This crate adds
//! Sign1-specific functionality: message parsing, builder, Sig_structure, and
//! the `COSE_SIGN1_TAG`.
//!
//! ## Features
//!
//! - **CryptoSigner / CryptoVerifier traits** - Abstraction for signing/verification operations
//! - **CoseHeaderMap** - Protected and unprotected header handling (from `cose_primitives`)
//! - **CoseSign1Message** - Parse and verify COSE_Sign1 messages
//! - **CoseSign1Builder** - Fluent API for creating messages
//! - **Sig_structure** - RFC 9052 compliant signature structure construction
//! - **Streaming support** - Handle large payloads without full memory load
//!
//! ## Example
//!
//! ```ignore
//! use crypto_primitives::CryptoSigner;
//! use cose_sign1_primitives::{
//!     CoseSign1Builder, CoseSign1Message, CoseHeaderMap,
//!     algorithms,
//! };
//!
//! // Create protected headers
//! let mut protected = CoseHeaderMap::new();
//! protected.set_alg(algorithms::ES256);
//!
//! // Sign a message
//! let message_bytes = CoseSign1Builder::new()
//!     .protected(protected)
//!     .sign(&signer, b"payload")?;
//!
//! // Parse and verify
//! let message = CoseSign1Message::parse(&message_bytes)?;
//! let valid = message.verify(&verifier, None)?;
//! ```
//!
//! ## Architecture
//!
//! This crate is generic over the `CborProvider` trait from `cbor_primitives` and
//! the `CryptoSigner`/`CryptoVerifier` traits from `crypto_primitives`, allowing
//! pluggable CBOR and cryptographic implementations.

pub mod algorithms;
pub mod builder;
pub mod crypto_provider;
pub mod error;
pub mod headers;
pub mod message;
pub mod payload;
pub mod provider;
pub mod sig_structure;

// Re-exports
pub use algorithms::{
    COSE_SIGN1_TAG, EDDSA, ES256, ES384, ES512, LARGE_PAYLOAD_THRESHOLD, PS256, PS384, PS512,
    RS256, RS384, RS512,
};
#[cfg(feature = "pqc")]
pub use algorithms::{ML_DSA_44, ML_DSA_65, ML_DSA_87};
pub use builder::{CoseSign1Builder, MAX_EMBED_PAYLOAD_SIZE};
pub use cose_primitives::CoseError;
pub use cose_primitives::{ArcSlice, ArcStr, CoseData, LazyHeaderMap};
pub use crypto_primitives::{
    CryptoError, CryptoProvider, CryptoSigner, CryptoVerifier, NullCryptoProvider, SigningContext,
    VerifyingContext,
};
pub use error::{CoseKeyError, CoseSign1Error, PayloadError};
pub use headers::{ContentType, CoseHeaderLabel, CoseHeaderMap, CoseHeaderValue, ProtectedHeader};
pub use message::CoseSign1Message;
pub use payload::{FilePayload, MemoryPayload, Payload, StreamingPayload};
pub use sig_structure::{
    build_sig_structure, build_sig_structure_prefix, hash_sig_structure_streaming,
    hash_sig_structure_streaming_chunked, open_sized_file, sized_from_bytes,
    sized_from_read_buffered, sized_from_reader, sized_from_seekable, stream_sig_structure,
    stream_sig_structure_chunked, IntoSizedRead, SigStructureHasher, SizedRead, SizedReader,
    SizedSeekReader, DEFAULT_CHUNK_SIZE, SIG_STRUCTURE_CONTEXT,
};

/// Deprecated alias for backward compatibility.
///
/// Use `CryptoSigner` or `CryptoVerifier` instead.
#[deprecated(
    since = "0.2.0",
    note = "Use crypto_primitives::CryptoSigner or CryptoVerifier instead"
)]
pub type CoseKey = dyn CryptoSigner;
