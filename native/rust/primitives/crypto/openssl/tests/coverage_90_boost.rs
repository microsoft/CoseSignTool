// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Targeted coverage tests for cose_sign1_crypto_openssl to reach 90%.
//!
//! Focuses on:
//! - ECDSA DER↔fixed edge cases
//! - Unsupported algorithm error paths
//! - Streaming sign/verify contexts
//! - Provider key type detection
//! - JWK verifier factory error paths

use cose_sign1_crypto_openssl::ecdsa_format::{der_to_fixed, fixed_to_der};
use cose_sign1_crypto_openssl::{
    EvpSigner, EvpVerifier, OpenSslCryptoProvider, OpenSslJwkVerifierFactory,
};
use crypto_primitives::{
    CryptoProvider, CryptoSigner, CryptoVerifier, EcJwk, JwkVerifierFactory, RsaJwk,
};

// ============================================================================
// ECDSA format conversion edge cases
// ============================================================================

#[test]
fn der_to_fixed_too_short() {
    let result = der_to_fixed(&[0x30, 0x01], 64);
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("too short"));
}

#[test]
fn der_to_fixed_missing_sequence_tag() {
    let result = der_to_fixed(&[0x31, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01], 64);
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("SEQUENCE"));
}

#[test]
fn der_to_fixed_length_mismatch() {
    // SEQUENCE tag with length larger than actual data
    let result = der_to_fixed(&[0x30, 0xFF, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01], 64);
    assert!(result.is_err());
}

#[test]
fn der_to_fixed_missing_r_integer_tag() {
    // SEQUENCE OK but first element is not INTEGER
    let result = der_to_fixed(&[0x30, 0x06, 0x03, 0x01, 0x01, 0x02, 0x01, 0x01], 64);
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("INTEGER tag for r"));
}

#[test]
fn der_to_fixed_missing_s_integer_tag() {
    // r is valid INTEGER, but s is not
    let result = der_to_fixed(&[0x30, 0x06, 0x02, 0x01, 0x01, 0x03, 0x01, 0x01], 64);
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("INTEGER tag for s"));
}

#[test]
fn der_to_fixed_r_out_of_bounds() {
    // r length extends beyond signature
    let result = der_to_fixed(&[0x30, 0x06, 0x02, 0xFF, 0x01, 0x02, 0x01, 0x01], 64);
    assert!(result.is_err());
}

#[test]
fn fixed_to_der_odd_length() {
    let result = fixed_to_der(&[0u8; 63]);
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("even"));
}

#[test]
fn fixed_to_der_and_back_roundtrip() {
    // Create a known fixed signature and roundtrip
    let mut fixed = vec![0u8; 64];
    fixed[31] = 0x42; // r = ...42
    fixed[63] = 0x43; // s = ...43

    let der = fixed_to_der(&fixed).unwrap();
    let recovered = der_to_fixed(&der, 64).unwrap();
    assert_eq!(recovered, fixed);
}

#[test]
fn fixed_to_der_high_bit_set() {
    // Both r and s have high bit set, requiring padding
    let mut fixed = vec![0u8; 64];
    fixed[0] = 0x80; // r high bit set
    fixed[32] = 0x80; // s high bit set

    let der = fixed_to_der(&fixed).unwrap();
    assert!(der.len() > 64 + 6); // extra bytes for padding

    let recovered = der_to_fixed(&der, 64).unwrap();
    assert_eq!(recovered, fixed);
}

#[test]
fn fixed_to_der_all_zeros() {
    let fixed = vec![0u8; 64];
    let der = fixed_to_der(&fixed).unwrap();
    let recovered = der_to_fixed(&der, 64).unwrap();
    assert_eq!(recovered, fixed);
}

#[test]
fn der_to_fixed_with_leading_zero_padding() {
    // Create a DER signature with leading zero on r (positive sign)
    let der = vec![
        0x30, 0x08, // SEQUENCE, len 8
        0x02, 0x03, 0x00, 0x80, 0x01, // INTEGER r = 0x00 0x80 0x01 (padded)
        0x02, 0x01, 0x42, // INTEGER s = 0x42
    ];
    let fixed = der_to_fixed(&der, 4).unwrap();
    assert_eq!(fixed.len(), 4);
    // r should be [0x80, 0x01], s should be [0x00, 0x42]
    assert_eq!(fixed[0], 0x80);
    assert_eq!(fixed[1], 0x01);
    assert_eq!(fixed[2], 0x00);
    assert_eq!(fixed[3], 0x42);
}

#[test]
fn der_length_long_form() {
    // Test long-form DER length (> 127 bytes total)
    // Build a DER ECDSA signature with long-form length
    // This tests the parse_der_length path for multi-byte lengths

    // Create components larger than 127 bytes is impractical for real ECDSA,
    // so let's just verify the long form parsing handles the size correctly
    // via integer_to_der and fixed_to_der

    // A very large P-521 signature (66 bytes per component = 132 total)
    let mut fixed = vec![0u8; 132];
    fixed[0] = 0xFF; // max value r
    fixed[66] = 0xFF; // max value s

    let der = fixed_to_der(&fixed).unwrap();
    let recovered = der_to_fixed(&der, 132).unwrap();
    assert_eq!(recovered, fixed);
}

#[test]
fn integer_to_der_empty_input() {
    // Test via fixed_to_der with zero-length components
    // (not directly possible with fixed_to_der, but can test the internal function
    //  indirectly through a roundtrip with all-zero small signature)
    let fixed = vec![0u8; 2]; // 1 byte per component
    let der = fixed_to_der(&fixed).unwrap();
    let recovered = der_to_fixed(&der, 2).unwrap();
    assert_eq!(recovered, fixed);
}

// ============================================================================
// Unsupported algorithm error paths
// ============================================================================

#[test]
fn signer_unsupported_algorithm() {
    let ec = openssl::ec::EcKey::generate(
        &openssl::ec::EcGroup::from_curve_name(openssl::nid::Nid::X9_62_PRIME256V1).unwrap(),
    )
    .unwrap();
    let pkey = openssl::pkey::PKey::from_ec_key(ec).unwrap();
    let der = pkey.private_key_to_der().unwrap();

    // Use an unsupported algorithm ID
    let result = EvpSigner::from_der(&der, -999);
    assert!(result.is_ok()); // signer creation succeeds (algorithm is just metadata)

    let signer = result.unwrap();
    // Signing with unsupported algorithm should fail at sign time
    let sign_result = signer.sign(b"test data");
    assert!(sign_result.is_err());
}

#[test]
fn verifier_unsupported_algorithm() {
    let ec = openssl::ec::EcKey::generate(
        &openssl::ec::EcGroup::from_curve_name(openssl::nid::Nid::X9_62_PRIME256V1).unwrap(),
    )
    .unwrap();
    let pkey = openssl::pkey::PKey::from_ec_key(ec).unwrap();
    let der = pkey.public_key_to_der().unwrap();

    // Use an unsupported algorithm for the verifier
    let result = EvpVerifier::from_der(&der, -999);
    assert!(result.is_ok());

    let verifier = result.unwrap();
    let verify_result = verifier.verify(b"test", &[0u8; 64]);
    assert!(verify_result.is_err());
}

// ============================================================================
// Streaming sign/verify context
// ============================================================================

#[test]
fn streaming_sign_verify_roundtrip_ec() {
    let ec = openssl::ec::EcKey::generate(
        &openssl::ec::EcGroup::from_curve_name(openssl::nid::Nid::X9_62_PRIME256V1).unwrap(),
    )
    .unwrap();
    let pkey = openssl::pkey::PKey::from_ec_key(ec).unwrap();
    let priv_der = pkey.private_key_to_der().unwrap();
    let pub_der = pkey.public_key_to_der().unwrap();

    let signer = EvpSigner::from_der(&priv_der, -7).unwrap();
    let verifier = EvpVerifier::from_der(&pub_der, -7).unwrap();

    assert!(signer.supports_streaming());
    assert!(verifier.supports_streaming());

    // Streaming sign
    let mut ctx = signer.sign_init().unwrap();
    ctx.update(b"hello ").unwrap();
    ctx.update(b"streaming ").unwrap();
    ctx.update(b"world").unwrap();
    let sig = ctx.finalize().unwrap();

    // Streaming verify
    let mut vctx = verifier.verify_init(&sig).unwrap();
    vctx.update(b"hello ").unwrap();
    vctx.update(b"streaming ").unwrap();
    vctx.update(b"world").unwrap();
    let valid = vctx.finalize().unwrap();
    assert!(valid);
}

#[test]
fn streaming_sign_verify_ec384() {
    let ec = openssl::ec::EcKey::generate(
        &openssl::ec::EcGroup::from_curve_name(openssl::nid::Nid::SECP384R1).unwrap(),
    )
    .unwrap();
    let pkey = openssl::pkey::PKey::from_ec_key(ec).unwrap();
    let priv_der = pkey.private_key_to_der().unwrap();
    let pub_der = pkey.public_key_to_der().unwrap();

    // Explicitly pass ES384 algorithm (-35) since provider defaults EC to ES256
    let signer = EvpSigner::from_der(&priv_der, -35).unwrap();
    let verifier = EvpVerifier::from_der(&pub_der, -35).unwrap();

    let data = b"ES384 streaming test";
    let sig = signer.sign(data).unwrap();
    let valid = verifier.verify(data, &sig).unwrap();
    assert!(valid);
}

#[test]
fn ed25519_does_not_support_streaming() {
    let pkey = openssl::pkey::PKey::generate_ed25519().unwrap();
    let priv_der = pkey.private_key_to_der().unwrap();
    let pub_der = pkey.public_key_to_der().unwrap();

    let signer = EvpSigner::from_der(&priv_der, -8).unwrap();
    let verifier = EvpVerifier::from_der(&pub_der, -8).unwrap();

    assert!(!signer.supports_streaming());
    assert!(!verifier.supports_streaming());

    // key_type should return "OKP" for Ed25519
    assert_eq!(signer.key_type(), "OKP");

    // Non-streaming sign/verify still works
    let data = b"ed25519 test data";
    let sig = signer.sign(data).unwrap();
    let valid = verifier.verify(data, &sig).unwrap();
    assert!(valid);
}

// ============================================================================
// Provider key type detection
// ============================================================================

#[test]
fn provider_name() {
    let provider = OpenSslCryptoProvider;
    assert_eq!(provider.name(), "OpenSSL");
}

#[test]
fn provider_ec_key_detection() {
    let ec = openssl::ec::EcKey::generate(
        &openssl::ec::EcGroup::from_curve_name(openssl::nid::Nid::X9_62_PRIME256V1).unwrap(),
    )
    .unwrap();
    let pkey = openssl::pkey::PKey::from_ec_key(ec).unwrap();

    let provider = OpenSslCryptoProvider;
    let signer = provider
        .signer_from_der(&pkey.private_key_to_der().unwrap())
        .unwrap();
    assert_eq!(signer.algorithm(), -7); // ES256

    let verifier = provider
        .verifier_from_der(&pkey.public_key_to_der().unwrap())
        .unwrap();
    assert_eq!(verifier.algorithm(), -7);
}

#[test]
fn provider_rsa_key_detection() {
    let rsa = openssl::rsa::Rsa::generate(2048).unwrap();
    let pkey = openssl::pkey::PKey::from_rsa(rsa).unwrap();

    let provider = OpenSslCryptoProvider;
    let signer = provider
        .signer_from_der(&pkey.private_key_to_der().unwrap())
        .unwrap();
    assert_eq!(signer.algorithm(), -257); // RS256

    let verifier = provider
        .verifier_from_der(&pkey.public_key_to_der().unwrap())
        .unwrap();
    assert_eq!(verifier.algorithm(), -257);
}

#[test]
fn provider_ed25519_key_detection() {
    let pkey = openssl::pkey::PKey::generate_ed25519().unwrap();

    let provider = OpenSslCryptoProvider;
    let signer = provider
        .signer_from_der(&pkey.private_key_to_der().unwrap())
        .unwrap();
    assert_eq!(signer.algorithm(), -8); // EdDSA

    let verifier = provider
        .verifier_from_der(&pkey.public_key_to_der().unwrap())
        .unwrap();
    assert_eq!(verifier.algorithm(), -8);
}

#[test]
fn provider_invalid_key_der() {
    let provider = OpenSslCryptoProvider;
    let result = provider.signer_from_der(&[0xDE, 0xAD]);
    assert!(result.is_err());

    let result = provider.verifier_from_der(&[0xDE, 0xAD]);
    assert!(result.is_err());
}

// ============================================================================
// RSA sign/verify with PSS padding
// ============================================================================

#[test]
fn rsa_ps256_sign_verify() {
    let rsa = openssl::rsa::Rsa::generate(2048).unwrap();
    let pkey = openssl::pkey::PKey::from_rsa(rsa).unwrap();
    let priv_der = pkey.private_key_to_der().unwrap();
    let pub_der = pkey.public_key_to_der().unwrap();

    let signer = EvpSigner::from_der(&priv_der, -37).unwrap(); // PS256
    let verifier = EvpVerifier::from_der(&pub_der, -37).unwrap();

    let data = b"PSS padding test";
    let sig = signer.sign(data).unwrap();
    let valid = verifier.verify(data, &sig).unwrap();
    assert!(valid);
}

#[test]
fn rsa_ps384_sign_verify() {
    let rsa = openssl::rsa::Rsa::generate(2048).unwrap();
    let pkey = openssl::pkey::PKey::from_rsa(rsa).unwrap();
    let priv_der = pkey.private_key_to_der().unwrap();
    let pub_der = pkey.public_key_to_der().unwrap();

    let signer = EvpSigner::from_der(&priv_der, -38).unwrap(); // PS384
    let verifier = EvpVerifier::from_der(&pub_der, -38).unwrap();

    let data = b"PS384 test";
    let sig = signer.sign(data).unwrap();
    let valid = verifier.verify(data, &sig).unwrap();
    assert!(valid);
}

#[test]
fn rsa_ps512_sign_verify() {
    let rsa = openssl::rsa::Rsa::generate(2048).unwrap();
    let pkey = openssl::pkey::PKey::from_rsa(rsa).unwrap();
    let priv_der = pkey.private_key_to_der().unwrap();
    let pub_der = pkey.public_key_to_der().unwrap();

    let signer = EvpSigner::from_der(&priv_der, -39).unwrap(); // PS512
    let verifier = EvpVerifier::from_der(&pub_der, -39).unwrap();

    let data = b"PS512 test";
    let sig = signer.sign(data).unwrap();
    let valid = verifier.verify(data, &sig).unwrap();
    assert!(valid);
}

#[test]
fn rsa_streaming_sign_verify() {
    let rsa = openssl::rsa::Rsa::generate(2048).unwrap();
    let pkey = openssl::pkey::PKey::from_rsa(rsa).unwrap();
    let priv_der = pkey.private_key_to_der().unwrap();
    let pub_der = pkey.public_key_to_der().unwrap();

    let signer = EvpSigner::from_der(&priv_der, -257).unwrap(); // RS256
    let verifier = EvpVerifier::from_der(&pub_der, -257).unwrap();

    assert!(signer.supports_streaming());
    assert!(verifier.supports_streaming());

    // Streaming sign
    let mut ctx = signer.sign_init().unwrap();
    ctx.update(b"chunk1").unwrap();
    ctx.update(b"chunk2").unwrap();
    let sig = ctx.finalize().unwrap();

    // Streaming verify
    let mut vctx = verifier.verify_init(&sig).unwrap();
    vctx.update(b"chunk1").unwrap();
    vctx.update(b"chunk2").unwrap();
    let valid = vctx.finalize().unwrap();
    assert!(valid);
}

// ============================================================================
// JWK verifier factory error paths
// ============================================================================

#[test]
fn jwk_ec_wrong_kty() {
    let factory = OpenSslJwkVerifierFactory;
    let jwk = EcJwk {
        kty: "RSA".into(),
        crv: "P-256".into(),
        x: "AAAA".into(),
        y: "BBBB".into(),
        kid: None,
    };
    let result = factory.verifier_from_ec_jwk(&jwk, -7);
    assert!(result.is_err());
}

#[test]
fn jwk_ec_unsupported_curve() {
    let factory = OpenSslJwkVerifierFactory;
    let jwk = EcJwk {
        kty: "EC".into(),
        crv: "P-999".into(),
        x: "AAAA".into(),
        y: "BBBB".into(),
        kid: None,
    };
    let result = factory.verifier_from_ec_jwk(&jwk, -7);
    assert!(result.is_err());
}

#[test]
fn jwk_ec_coordinate_length_mismatch() {
    let factory = OpenSslJwkVerifierFactory;
    // x is 1 byte, should be 32 for P-256
    let jwk = EcJwk {
        kty: "EC".into(),
        crv: "P-256".into(),
        x: "AA".into(), // 1 byte decoded
        y: "AA".into(), // 1 byte decoded
        kid: None,
    };
    let result = factory.verifier_from_ec_jwk(&jwk, -7);
    assert!(result.is_err());
}

#[test]
fn jwk_rsa_wrong_kty() {
    let factory = OpenSslJwkVerifierFactory;
    let jwk = RsaJwk {
        kty: "EC".into(),
        n: "AAAA".into(),
        e: "AQAB".into(),
        kid: None,
    };
    let result = factory.verifier_from_rsa_jwk(&jwk, -257);
    assert!(result.is_err());
}

#[test]
fn jwk_ec_invalid_base64url() {
    let factory = OpenSslJwkVerifierFactory;
    let jwk = EcJwk {
        kty: "EC".into(),
        crv: "P-256".into(),
        x: "invalid!!!base64".into(),
        y: "BBBB".into(),
        kid: None,
    };
    let result = factory.verifier_from_ec_jwk(&jwk, -7);
    assert!(result.is_err());
}

// ============================================================================
// Signer key_type
// ============================================================================

#[test]
fn signer_key_type_ec() {
    let ec = openssl::ec::EcKey::generate(
        &openssl::ec::EcGroup::from_curve_name(openssl::nid::Nid::X9_62_PRIME256V1).unwrap(),
    )
    .unwrap();
    let pkey = openssl::pkey::PKey::from_ec_key(ec).unwrap();
    let signer = EvpSigner::from_der(&pkey.private_key_to_der().unwrap(), -7).unwrap();
    assert_eq!(signer.key_type(), "EC2");
    assert!(signer.key_id().is_none());
}

#[test]
fn signer_key_type_rsa() {
    let rsa = openssl::rsa::Rsa::generate(2048).unwrap();
    let pkey = openssl::pkey::PKey::from_rsa(rsa).unwrap();
    let signer = EvpSigner::from_der(&pkey.private_key_to_der().unwrap(), -257).unwrap();
    assert_eq!(signer.key_type(), "RSA");
}

// ============================================================================
// EC P-521 (ES512)
// ============================================================================

#[test]
fn ec_p521_sign_verify() {
    let ec = openssl::ec::EcKey::generate(
        &openssl::ec::EcGroup::from_curve_name(openssl::nid::Nid::SECP521R1).unwrap(),
    )
    .unwrap();
    let pkey = openssl::pkey::PKey::from_ec_key(ec).unwrap();
    let priv_der = pkey.private_key_to_der().unwrap();
    let pub_der = pkey.public_key_to_der().unwrap();

    let signer = EvpSigner::from_der(&priv_der, -36).unwrap(); // ES512
    let verifier = EvpVerifier::from_der(&pub_der, -36).unwrap();

    let data = b"P-521 test data";
    let sig = signer.sign(data).unwrap();
    assert_eq!(sig.len(), 132); // 2 * 66

    let valid = verifier.verify(data, &sig).unwrap();
    assert!(valid);
}
