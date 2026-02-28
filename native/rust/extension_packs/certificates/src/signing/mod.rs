// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Certificate-based signing support.
//!
//! Provides `CertificateSigningService`, header contributors, key providers,
//! and SCITT CWT claims integration for X.509 certificate signing.

pub mod certificate_header_contributor;
pub mod certificate_signing_options;
pub mod certificate_signing_service;
pub mod signing_key;
pub mod signing_key_provider;
pub mod source;
pub mod scitt;
pub mod remote;

pub use certificate_header_contributor::*;
pub use certificate_signing_options::*;
pub use certificate_signing_service::*;
pub use signing_key::*;
pub use signing_key_provider::*;
pub use source::*;
pub use scitt::*;
