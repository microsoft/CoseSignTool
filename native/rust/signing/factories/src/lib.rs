// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![cfg_attr(coverage_nightly, feature(coverage_attribute))]

//! Factory patterns for creating COSE_Sign1 messages.
//!
//! This crate provides factory implementations that map V2 C# factory patterns
//! for building COSE_Sign1 messages with signing services. It includes:
//!
//! - `DirectSignatureFactory`: Signs payload directly (embedded or detached)
//! - `IndirectSignatureFactory`: Signs hash of payload (indirect signature pattern)
//! - `CoseSign1MessageFactory`: Router that delegates to appropriate factory
//!
//! # Architecture
//!
//! The factories follow V2's design:
//! 1. Accept a `SigningService` that provides signers
//! 2. Use `HeaderContributor` pattern for extensible header management
//! 3. Perform post-sign verification after creating signatures
//! 4. Support both embedded and detached payloads
//!
//! # Example
//!
//! ```ignore
//! use cose_sign1_factories::{CoseSign1MessageFactory, DirectSignatureOptions};
//! use cbor_primitives_everparse::EverParseCborProvider;
//!
//! let factory = CoseSign1MessageFactory::new(signing_service);
//! let provider = EverParseCborProvider;
//!
//! let options = DirectSignatureOptions::new()
//!     .with_embed_payload(true);
//!
//! let message = factory.create_direct(
//!     &provider,
//!     b"Hello, World!",
//!     "text/plain",
//!     Some(options)
//! )?;
//! ```

pub mod direct;
pub mod error;
pub mod factory;
pub mod indirect;

pub use error::FactoryError;
pub use factory::{CoseSign1MessageFactory, SignatureFactoryProvider};
