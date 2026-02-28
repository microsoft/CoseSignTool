// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! # OpenSSL Cryptographic Provider for CoseSign1
//!
//! This crate provides CoseKey implementations using safe Rust bindings to OpenSSL
//! via the `openssl` crate. It is an alternative to the unsafe `cose_openssl` crate.
//!
//! ## Features
//!
//! - **Safe Rust**: Uses the `openssl` crate's safe bindings (not `openssl-sys`)
//! - **EC Support**: ECDSA with P-256, P-384, P-521 (ES256, ES384, ES512)
//! - **RSA Support**: PKCS#1 v1.5 and PSS padding (RS256/384/512, PS256/384/512)
//! - **EdDSA Support**: Ed25519 signatures
//! - **PQC Support**: Optional ML-DSA support via `pqc` feature flag
//!
//! ## Example
//!
//! ```ignore
//! use cose_sign1_crypto_openssl::{
//!     OpenSslCryptoProvider, EvpPrivateKey, EvpPublicKey
//! };
//! use cose_primitives::ES256;
//! use openssl::pkey::PKey;
//! use openssl::ec::{EcKey, EcGroup};
//! use openssl::nid::Nid;
//!
//! // Create an EC P-256 key pair
//! let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)?;
//! let ec_key = EcKey::generate(&group)?;
//! let private_key = EvpPrivateKey::from_ec(ec_key)?;
//!
//! // Create a signing key
//! let signing_key = OpenSslCryptoProvider::create_signing_key(
//!     private_key,
//!     -7, // ES256
//!     None, // No key ID
//! );
//!
//! // Use with CoseSign1Builder
//! let signature = signing_key.sign(protected_bytes, payload, None)?;
//! ```
//!
//! ## Algorithm Support
//!
//! | COSE Alg | Algorithm | Curve/Key Size | Status |
//! |----------|-----------|----------------|--------|
//! | -7 | ES256 | P-256 + SHA-256 | ✅ Supported |
//! | -35 | ES384 | P-384 + SHA-384 | ✅ Supported |
//! | -36 | ES512 | P-521 + SHA-512 | ✅ Supported |
//! | -257 | RS256 | RSA + SHA-256 | ✅ Supported |
//! | -258 | RS384 | RSA + SHA-384 | ✅ Supported |
//! | -259 | RS512 | RSA + SHA-512 | ✅ Supported |
//! | -37 | PS256 | RSA-PSS + SHA-256 | ✅ Supported |
//! | -38 | PS384 | RSA-PSS + SHA-384 | ✅ Supported |
//! | -39 | PS512 | RSA-PSS + SHA-512 | ✅ Supported |
//! | -8 | EdDSA | Ed25519 | ✅ Supported |
//!
//! ## Comparison with `cose_openssl`
//!
//! | Feature | `cose_sign1_crypto_openssl` | `cose_openssl` |
//! |---------|----------------------------|----------------|
//! | Safety | Safe Rust bindings | Unsafe `openssl-sys` FFI |
//! | API | High-level `openssl` crate | Low-level C API |
//! | CBOR | Uses `cbor_primitives` | Custom CBOR impl |
//! | Maintenance | Easier (safe abstractions) | Harder (unsafe code) |
//!
//! This crate is recommended for new projects. The `cose_openssl` crate is
//! maintained for backwards compatibility and specific low-level use cases.

pub mod ecdsa_format;
pub mod evp_key;
pub mod evp_signer;
pub mod evp_verifier;
pub mod provider;

// Re-exports
pub use evp_key::{EvpPrivateKey, EvpPublicKey, KeyType};
#[cfg(feature = "pqc")]
pub use evp_key::{MlDsaVariant, generate_mldsa_keypair};
pub use evp_signer::EvpSigner;
pub use evp_verifier::EvpVerifier;
pub use provider::OpenSslCryptoProvider;

// Re-export COSE algorithm constants for convenience
pub use cose_primitives::{
    ES256, ES384, ES512, RS256, RS384, RS512, PS256, PS384, PS512, EDDSA,
};

#[cfg(feature = "pqc")]
pub use cose_primitives::{ML_DSA_44, ML_DSA_65, ML_DSA_87};
