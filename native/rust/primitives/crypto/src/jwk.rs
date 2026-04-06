// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! JSON Web Key (JWK) types and conversion traits.
//!
//! Defines backend-agnostic JWK structures and a trait for converting
//! JWK public keys to `CryptoVerifier` instances.
//!
//! Supports EC, RSA, and (feature-gated) PQC key types.
//! Implementations live in crypto backend crates (e.g., `cose_sign1_crypto_openssl`).

use crate::error::CryptoError;
use crate::verifier::CryptoVerifier;
use std::borrow::Cow;

// ============================================================================
// JWK Key Representations
// ============================================================================

/// EC JWK public key (kty = "EC").
///
/// Used for ECDSA verification with P-256, P-384, and P-521 curves.
#[derive(Debug, Clone)]
pub struct EcJwk<'a> {
    /// Key type — must be "EC".
    pub kty: Cow<'a, str>,
    /// Curve name: "P-256", "P-384", or "P-521".
    pub crv: Cow<'a, str>,
    /// Base64url-encoded x-coordinate.
    pub x: Cow<'a, str>,
    /// Base64url-encoded y-coordinate.
    pub y: Cow<'a, str>,
    /// Key ID (optional).
    pub kid: Option<Cow<'a, str>>,
}

/// RSA JWK public key (kty = "RSA").
///
/// Used for RSASSA-PKCS1-v1_5 (RS256/384/512) and RSASSA-PSS (PS256/384/512).
#[derive(Debug, Clone)]
pub struct RsaJwk {
    /// Key type — must be "RSA".
    pub kty: String,
    /// Base64url-encoded modulus.
    pub n: String,
    /// Base64url-encoded public exponent.
    pub e: String,
    /// Key ID (optional).
    pub kid: Option<String>,
}

/// PQC (ML-DSA) JWK public key (kty = "ML-DSA").
///
/// Future-proofing for FIPS 204 post-quantum signatures.
/// Gated behind `pqc` feature flag at usage sites.
#[derive(Debug, Clone)]
pub struct PqcJwk {
    /// Key type — e.g., "ML-DSA".
    pub kty: String,
    /// Algorithm variant: "ML-DSA-44", "ML-DSA-65", "ML-DSA-87".
    pub alg: String,
    /// Base64url-encoded public key bytes.
    pub pub_key: String,
    /// Key ID (optional).
    pub kid: Option<String>,
}

/// A JWK public key of any supported type.
///
/// Use this enum when accepting keys of unknown type at runtime
/// (e.g., from a JWKS document that may contain mixed key types).
#[derive(Debug, Clone)]
pub enum Jwk<'a> {
    /// Elliptic Curve key (P-256, P-384, P-521).
    Ec(EcJwk<'a>),
    /// RSA key.
    Rsa(RsaJwk),
    /// Post-Quantum key (ML-DSA). Feature-gated at usage sites.
    Pqc(PqcJwk),
}

// ============================================================================
// JWK → CryptoVerifier Factory Trait
// ============================================================================

/// Trait for creating a `CryptoVerifier` from a JWK public key.
///
/// Implementations handle all backend-specific details:
/// - Base64url decoding of key material
/// - Key construction and validation (on-curve checks, modulus parsing)
/// - DER encoding (SPKI format)
/// - Verifier creation with the appropriate COSE algorithm
///
/// This keeps all OpenSSL/ring/BoringSSL details out of consumer crates.
///
/// # Supported key types
///
/// | JWK Type | Method | COSE Algorithms |
/// |----------|--------|-----------------|
/// | EC | `verifier_from_ec_jwk()` | ES256 (-7), ES384 (-35), ES512 (-36) |
/// | RSA | `verifier_from_rsa_jwk()` | RS256 (-257), PS256 (-37), etc. |
/// | PQC | `verifier_from_pqc_jwk()` | ML-DSA variants (future) |
pub trait JwkVerifierFactory: Send + Sync {
    /// Create a `CryptoVerifier` from an EC JWK and a COSE algorithm identifier.
    fn verifier_from_ec_jwk(
        &self,
        jwk: &EcJwk<'_>,
        cose_algorithm: i64,
    ) -> Result<Box<dyn CryptoVerifier>, CryptoError>;

    /// Create a `CryptoVerifier` from an RSA JWK and a COSE algorithm identifier.
    ///
    /// Default implementation returns `UnsupportedOperation` — backends that
    /// support RSA should override.
    fn verifier_from_rsa_jwk(
        &self,
        _jwk: &RsaJwk,
        _cose_algorithm: i64,
    ) -> Result<Box<dyn CryptoVerifier>, CryptoError> {
        Err(CryptoError::UnsupportedOperation(
            "RSA JWK verification not supported by this backend".into(),
        ))
    }

    /// Create a `CryptoVerifier` from a PQC (ML-DSA) JWK.
    ///
    /// Default implementation returns `UnsupportedOperation` — backends with
    /// PQC support (feature-gated) should override.
    fn verifier_from_pqc_jwk(
        &self,
        _jwk: &PqcJwk,
        _cose_algorithm: i64,
    ) -> Result<Box<dyn CryptoVerifier>, CryptoError> {
        Err(CryptoError::UnsupportedOperation(
            "PQC JWK verification not supported by this backend".into(),
        ))
    }

    /// Create a `CryptoVerifier` from a type-erased JWK enum.
    ///
    /// Dispatches to the appropriate typed method based on `Jwk` variant.
    fn verifier_from_jwk(
        &self,
        jwk: &Jwk<'_>,
        cose_algorithm: i64,
    ) -> Result<Box<dyn CryptoVerifier>, CryptoError> {
        match jwk {
            Jwk::Ec(ec) => self.verifier_from_ec_jwk(ec, cose_algorithm),
            Jwk::Rsa(rsa) => self.verifier_from_rsa_jwk(rsa, cose_algorithm),
            Jwk::Pqc(pqc) => self.verifier_from_pqc_jwk(pqc, cose_algorithm),
        }
    }
}
