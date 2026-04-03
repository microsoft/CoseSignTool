// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Certificate-based signing services — maps V2 `CoseSign1.Certificates` signing namespace.
//!
//! This module provides:
//! - [`CertificateSigningService`] — Signs payloads using X.509 certificate-based keys
//! - [`CertificateHeaderContributor`] — Adds x5t and x5chain headers to protected headers
//! - [`CertificateSigningOptions`] — Configuration for certificate-based signing
//! - [`CertificateSigningKey`] trait — Extends `SigningServiceKey` with certificate access
//! - [`SigningKeyProvider`] trait — Resolves signing keys from configuration
//!
//! ## Architecture
//! ```text
//! CertificateSigningService
//!   ├── CertificateSigningKey (trait)
//!   │    └── provides signing cert + chain
//!   ├── CertificateHeaderContributor
//!   │    └── adds x5t (label 34) and x5chain (label 33)
//!   └── delegates to SigningService (from cose_sign1_signing)
//! ```

pub mod certificate_header_contributor;
pub mod certificate_signing_options;
pub mod certificate_signing_service;
pub mod remote;
pub mod scitt;
pub mod signing_key;
pub mod signing_key_provider;
pub mod source;

pub use certificate_header_contributor::*;
pub use certificate_signing_options::*;
pub use certificate_signing_service::*;
pub use scitt::*;
pub use signing_key::*;
pub use signing_key_provider::*;
pub use source::*;
