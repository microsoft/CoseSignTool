// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! DID:x509 identifier parsing, building, validation and resolution
//!
//! This crate provides functionality for working with DID:x509 identifiers,
//! which create Decentralized Identifiers from X.509 certificate chains.
//!
//! Format: `did:x509:0:sha256:<CA_fingerprint>::eku:<eku_oid>`
//!
//! # Examples
//!
//! ```
//! use did_x509::parsing::DidX509Parser;
//!
//! let did = "did:x509:0:sha256:WE4P5dd8DnLHSkyHaIjhp4udlkor4ighed1-shouldn-tBeValidatedForRealJustAnExample::eku:1.2.3.4";
//! let parsed = DidX509Parser::parse(did);
//! // Handle the result...
//! ```

pub mod builder;
pub mod constants;
pub mod did_document;
pub mod error;
pub mod models;
pub mod parsing;
pub mod policy_validators;
pub mod resolver;
pub mod san_parser;
pub mod validator;
pub mod x509_extensions;

pub use constants::*;
pub use did_document::{DidDocument, VerificationMethod};
pub use error::DidX509Error;
pub use models::{
    CertificateInfo, DidX509ParsedIdentifier, DidX509Policy, DidX509ValidationResult,
    SanType, SubjectAlternativeName, X509Name,
};
pub use parsing::{percent_decode, percent_encode, DidX509Parser};
pub use builder::DidX509Builder;
pub use resolver::DidX509Resolver;
pub use validator::DidX509Validator;
