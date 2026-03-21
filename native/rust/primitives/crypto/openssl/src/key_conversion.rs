// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Key format conversion utilities.
//!
//! Converts between different key representations (JWK coordinates, uncompressed
//! EC points, SubjectPublicKeyInfo DER) using OpenSSL.

use crypto_primitives::CryptoError;

/// Convert an uncompressed EC public key point (0x04 || x || y) to
/// SubjectPublicKeyInfo (SPKI) DER format.
///
/// # Arguments
///
/// * `uncompressed` - The uncompressed SEC1 point (must start with 0x04)
/// * `curve_name` - The curve name: "P-256", "P-384", or "P-521"
///
/// # Returns
///
/// DER-encoded SubjectPublicKeyInfo suitable for `PKey::public_key_from_der()`.
pub fn ec_point_to_spki_der(uncompressed: &[u8], curve_name: &str) -> Result<Vec<u8>, CryptoError> {
    if uncompressed.is_empty() || uncompressed[0] != 0x04 {
        return Err(CryptoError::InvalidKey(
            "EC point must start with 0x04 (uncompressed)".into(),
        ));
    }

    let nid = match curve_name {
        "P-256" => openssl::nid::Nid::X9_62_PRIME256V1,
        "P-384" => openssl::nid::Nid::SECP384R1,
        "P-521" => openssl::nid::Nid::SECP521R1,
        _ => {
            return Err(CryptoError::InvalidKey(format!(
                "unsupported EC curve: {}",
                curve_name
            )))
        }
    };

    let group = openssl::ec::EcGroup::from_curve_name(nid)
        .map_err(|e| CryptoError::InvalidKey(format!("EC group: {}", e)))?;

    let mut ctx = openssl::bn::BigNumContext::new()
        .map_err(|e| CryptoError::InvalidKey(format!("BN context: {}", e)))?;

    let point = openssl::ec::EcPoint::from_bytes(&group, uncompressed, &mut ctx)
        .map_err(|e| CryptoError::InvalidKey(format!("EC point: {}", e)))?;

    let ec_key = openssl::ec::EcKey::from_public_key(&group, &point)
        .map_err(|e| CryptoError::InvalidKey(format!("EC key: {}", e)))?;

    let pkey = openssl::pkey::PKey::from_ec_key(ec_key)
        .map_err(|e| CryptoError::InvalidKey(format!("PKey: {}", e)))?;

    pkey.public_key_to_der()
        .map_err(|e| CryptoError::InvalidKey(format!("SPKI DER: {}", e)))
}
