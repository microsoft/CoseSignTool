// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! JWK to CryptoVerifier conversion using OpenSSL.
//!
//! Implements `crypto_primitives::JwkVerifierFactory` for the OpenSSL backend.
//! Supports EC (P-256, P-384, P-521), RSA, and PQC (ML-DSA, feature-gated).

#[cfg(feature = "pqc")]
use crypto_primitives::PqcJwk;
use crypto_primitives::{CryptoError, CryptoVerifier, EcJwk, JwkVerifierFactory, RsaJwk};

use crate::evp_verifier::EvpVerifier;

/// Base64url decoder (no padding).
pub(crate) fn base64url_decode(input: &str) -> Result<Vec<u8>, CryptoError> {
    const LUT: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut lookup = [0xFFu8; 256];
    for (i, &c) in LUT.iter().enumerate() {
        lookup[c as usize] = i as u8;
    }

    let input = input.trim_end_matches('=');
    let mut out = Vec::with_capacity(input.len() * 3 / 4);
    let mut buf: u32 = 0;
    let mut bits: u32 = 0;

    for &b in input.as_bytes() {
        let val = lookup[b as usize];
        if val == 0xFF {
            return Err(CryptoError::InvalidKey(format!(
                "invalid base64url byte: 0x{:02x}",
                b
            )));
        }
        buf = (buf << 6) | val as u32;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((buf >> bits) as u8);
            buf &= (1 << bits) - 1;
        }
    }
    Ok(out)
}

/// OpenSSL implementation of JWK → CryptoVerifier conversion.
///
/// Supports:
/// - EC keys (P-256, P-384, P-521) via `verifier_from_ec_jwk()`
/// - RSA keys via `verifier_from_rsa_jwk()`
/// - PQC (ML-DSA) keys via `verifier_from_pqc_jwk()` (requires `pqc` feature)
pub struct OpenSslJwkVerifierFactory;

impl JwkVerifierFactory for OpenSslJwkVerifierFactory {
    fn verifier_from_ec_jwk(
        &self,
        jwk: &EcJwk,
        cose_algorithm: i64,
    ) -> Result<Box<dyn CryptoVerifier>, CryptoError> {
        if jwk.kty != "EC" {
            return Err(CryptoError::InvalidKey(format!(
                "expected kty=EC, got {}",
                jwk.kty
            )));
        }

        let expected_len = match jwk.crv.as_str() {
            "P-256" => 32,
            "P-384" => 48,
            "P-521" => 66,
            _ => {
                return Err(CryptoError::InvalidKey(format!(
                    "unsupported EC curve: {}",
                    jwk.crv
                )))
            }
        };

        let x = base64url_decode(&jwk.x)?;
        let y = base64url_decode(&jwk.y)?;

        if x.len() != expected_len || y.len() != expected_len {
            return Err(CryptoError::InvalidKey(format!(
                "EC coordinate length mismatch: x={} y={} expected={}",
                x.len(),
                y.len(),
                expected_len
            )));
        }

        // Build uncompressed EC point: 0x04 || x || y
        let mut uncompressed = Vec::with_capacity(1 + x.len() + y.len());
        uncompressed.push(0x04);
        uncompressed.extend_from_slice(&x);
        uncompressed.extend_from_slice(&y);

        // Convert to SPKI DER via OpenSSL
        let spki_der = crate::key_conversion::ec_point_to_spki_der(&uncompressed, &jwk.crv)?;

        // Create verifier from SPKI DER
        let verifier = EvpVerifier::from_der(&spki_der, cose_algorithm)?;
        Ok(Box::new(verifier))
    }

    fn verifier_from_rsa_jwk(
        &self,
        jwk: &RsaJwk,
        cose_algorithm: i64,
    ) -> Result<Box<dyn CryptoVerifier>, CryptoError> {
        if jwk.kty != "RSA" {
            return Err(CryptoError::InvalidKey(format!(
                "expected kty=RSA, got {}",
                jwk.kty
            )));
        }

        let n = base64url_decode(&jwk.n)?;
        let e = base64url_decode(&jwk.e)?;

        // Build RSA public key from n and e using OpenSSL
        let rsa_n = openssl::bn::BigNum::from_slice(&n)
            .map_err(|err| CryptoError::InvalidKey(format!("RSA modulus: {}", err)))?;
        let rsa_e = openssl::bn::BigNum::from_slice(&e)
            .map_err(|err| CryptoError::InvalidKey(format!("RSA exponent: {}", err)))?;

        let rsa = openssl::rsa::Rsa::from_public_components(rsa_n, rsa_e)
            .map_err(|err| CryptoError::InvalidKey(format!("RSA key: {}", err)))?;

        let pkey = openssl::pkey::PKey::from_rsa(rsa)
            .map_err(|err| CryptoError::InvalidKey(format!("PKey from RSA: {}", err)))?;

        let spki_der = pkey
            .public_key_to_der()
            .map_err(|err| CryptoError::InvalidKey(format!("SPKI DER: {}", err)))?;

        let verifier = EvpVerifier::from_der(&spki_der, cose_algorithm)?;
        Ok(Box::new(verifier))
    }

    #[cfg(feature = "pqc")]
    fn verifier_from_pqc_jwk(
        &self,
        jwk: &PqcJwk,
        cose_algorithm: i64,
    ) -> Result<Box<dyn CryptoVerifier>, CryptoError> {
        // Decode the raw public key bytes from base64url
        let pub_key_bytes = base64url_decode(&jwk.pub_key)?;

        // ML-DSA public keys are raw bytes — OpenSSL can load them via
        // EVP_PKEY_new_raw_public_key or from DER. For now, try DER first.
        let verifier = EvpVerifier::from_der(&pub_key_bytes, cose_algorithm)?;
        Ok(Box::new(verifier))
    }
}
