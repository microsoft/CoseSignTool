// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![cfg_attr(coverage_nightly, feature(coverage_attribute))]

//! Local certificate creation, ephemeral certs, chain building, and key loading.
//!
//! This crate provides functionality for creating X.509 certificates with
//! customizable options, supporting multiple key algorithms and key providers.
//!
//! ## Architecture
//!
//! - `Certificate` - DER-based certificate storage with optional private key and chain
//! - `CertificateOptions` - Fluent builder for certificate configuration
//! - `KeyAlgorithm` - RSA, ECDSA, and ML-DSA (post-quantum) key types
//! - `PrivateKeyProvider` - Trait for pluggable key generation (software, TPM, HSM)
//! - `CertificateFactory` - Trait for certificate creation
//! - `SoftwareKeyProvider` - Default in-memory key generation
//!
//! ## Maps V2 C#
//!
//! This crate corresponds to `CoseSign1.Certificates.Local` in the V2 C# codebase:
//! - `ICertificateFactory` → `CertificateFactory` trait
//! - `IPrivateKeyProvider` → `PrivateKeyProvider` trait
//! - `IGeneratedKey` → `GeneratedKey` struct
//! - `CertificateOptions` → `CertificateOptions` struct
//! - `KeyAlgorithm` → `KeyAlgorithm` enum
//! - `SoftwareKeyProvider` → `SoftwareKeyProvider` struct
//!
//! ## Design Notes
//!
//! Unlike the C# version which uses `X509Certificate2`, this Rust implementation
//! uses DER-encoded byte storage and delegates crypto operations to the
//! `crypto_primitives` abstraction. This enables:
//! - Zero hard dependencies on specific crypto backends
//! - Support for multiple crypto providers (OpenSSL, Ring, BoringSSL)
//! - Integration with hardware security modules and TPMs
//!
//! ## Feature Flags
//!
//! - `pqc` - Enables post-quantum cryptography support (ML-DSA)

pub mod certificate;
pub mod chain_factory;
pub mod error;
pub mod factory;
pub mod key_algorithm;
pub mod loaders;
pub mod options;
pub mod software_key;
pub mod traits;

// Re-export key types
pub use certificate::Certificate;
pub use chain_factory::{CertificateChainFactory, CertificateChainOptions};
pub use error::CertLocalError;
pub use factory::EphemeralCertificateFactory;
pub use key_algorithm::KeyAlgorithm;
pub use loaders::{CertificateFormat, LoadedCertificate};
pub use options::{CertificateOptions, CustomExtension, HashAlgorithm, KeyUsageFlags, SigningPadding};
pub use software_key::SoftwareKeyProvider;
pub use traits::{CertificateFactory, GeneratedKey, PrivateKeyProvider};
