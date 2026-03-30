// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! COSE algorithm constants and related values.
//!
//! Algorithm identifiers are defined in:
//! - RFC 9053: COSE Algorithms
//! - IANA COSE Algorithms Registry

/// ECDSA w/ SHA-256 (secp256r1/P-256)
pub const ES256: i64 = -7;
/// ECDSA w/ SHA-384 (secp384r1/P-384)
pub const ES384: i64 = -35;
/// ECDSA w/ SHA-512 (secp521r1/P-521)
pub const ES512: i64 = -36;
/// EdDSA (Ed25519 or Ed448)
pub const EDDSA: i64 = -8;
/// RSASSA-PSS w/ SHA-256
pub const PS256: i64 = -37;
/// RSASSA-PSS w/ SHA-384
pub const PS384: i64 = -38;
/// RSASSA-PSS w/ SHA-512
pub const PS512: i64 = -39;
/// RSASSA-PKCS1-v1_5 w/ SHA-256
pub const RS256: i64 = -257;
/// RSASSA-PKCS1-v1_5 w/ SHA-384
pub const RS384: i64 = -258;
/// RSASSA-PKCS1-v1_5 w/ SHA-512
pub const RS512: i64 = -259;

// ── Post-Quantum Cryptography (FIPS 204 ML-DSA) ──
//
// These constants are gated behind the `pqc` feature flag.
// Enable with: `--features pqc`

/// ML-DSA-44 (FIPS 204, security category 2)
#[cfg(feature = "pqc")]
pub const ML_DSA_44: i64 = -48;
/// ML-DSA-65 (FIPS 204, security category 3)
#[cfg(feature = "pqc")]
pub const ML_DSA_65: i64 = -49;
/// ML-DSA-87 (FIPS 204, security category 5)
#[cfg(feature = "pqc")]
pub const ML_DSA_87: i64 = -50;
