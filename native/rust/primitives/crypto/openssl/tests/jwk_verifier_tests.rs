// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Tests for JWK → CryptoVerifier conversion via OpenSslJwkVerifierFactory.
//!
//! Covers:
//! - EC JWK (P-256, P-384) → verifier creation and signature verification
//! - RSA JWK → verifier creation
//! - Invalid JWK handling (wrong kty, bad coordinates, unsupported curves)
//! - Key conversion (ec_point_to_spki_der)
//! - Base64url decoding

use cose_sign1_crypto_openssl::jwk_verifier::OpenSslJwkVerifierFactory;
use cose_sign1_crypto_openssl::key_conversion::ec_point_to_spki_der;
use crypto_primitives::{CryptoVerifier, EcJwk, Jwk, JwkVerifierFactory, RsaJwk};

use base64::Engine;
use openssl::ec::{EcGroup, EcKey};
use openssl::nid::Nid;
use openssl::pkey::PKey;

fn b64url(data: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(data)
}

/// Generate a real P-256 key pair and return (private_pkey, EcJwk).
fn generate_p256_jwk() -> (PKey<openssl::pkey::Private>, EcJwk) {
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
    let ec_key = EcKey::generate(&group).unwrap();
    let pkey = PKey::from_ec_key(ec_key.clone()).unwrap();

    let mut ctx = openssl::bn::BigNumContext::new().unwrap();
    let mut x = openssl::bn::BigNum::new().unwrap();
    let mut y = openssl::bn::BigNum::new().unwrap();
    ec_key
        .public_key()
        .affine_coordinates_gfp(&group, &mut x, &mut y, &mut ctx)
        .unwrap();

    let x_bytes = x.to_vec();
    let y_bytes = y.to_vec();
    // Pad to 32 bytes for P-256
    let mut x_padded = vec![0u8; 32 - x_bytes.len()];
    x_padded.extend_from_slice(&x_bytes);
    let mut y_padded = vec![0u8; 32 - y_bytes.len()];
    y_padded.extend_from_slice(&y_bytes);

    let jwk = EcJwk {
        kty: "EC".to_string(),
        crv: "P-256".to_string(),
        x: b64url(&x_padded),
        y: b64url(&y_padded),
        kid: Some("test-p256".to_string()),
    };

    (pkey, jwk)
}

/// Generate a real P-384 key pair and return (private_pkey, EcJwk).
fn generate_p384_jwk() -> (PKey<openssl::pkey::Private>, EcJwk) {
    let group = EcGroup::from_curve_name(Nid::SECP384R1).unwrap();
    let ec_key = EcKey::generate(&group).unwrap();
    let pkey = PKey::from_ec_key(ec_key.clone()).unwrap();

    let mut ctx = openssl::bn::BigNumContext::new().unwrap();
    let mut x = openssl::bn::BigNum::new().unwrap();
    let mut y = openssl::bn::BigNum::new().unwrap();
    ec_key
        .public_key()
        .affine_coordinates_gfp(&group, &mut x, &mut y, &mut ctx)
        .unwrap();

    let x_bytes = x.to_vec();
    let y_bytes = y.to_vec();
    let mut x_padded = vec![0u8; 48 - x_bytes.len()];
    x_padded.extend_from_slice(&x_bytes);
    let mut y_padded = vec![0u8; 48 - y_bytes.len()];
    y_padded.extend_from_slice(&y_bytes);

    let jwk = EcJwk {
        kty: "EC".to_string(),
        crv: "P-384".to_string(),
        x: b64url(&x_padded),
        y: b64url(&y_padded),
        kid: Some("test-p384".to_string()),
    };

    (pkey, jwk)
}

/// Generate an RSA key pair and return (private_pkey, RsaJwk).
fn generate_rsa_jwk() -> (PKey<openssl::pkey::Private>, RsaJwk) {
    let rsa = openssl::rsa::Rsa::generate(2048).unwrap();
    let pkey = PKey::from_rsa(rsa.clone()).unwrap();

    let n = rsa.n().to_vec();
    let e = rsa.e().to_vec();

    let jwk = RsaJwk {
        kty: "RSA".to_string(),
        n: b64url(&n),
        e: b64url(&e),
        kid: Some("test-rsa".to_string()),
    };

    (pkey, jwk)
}

// ==================== EC JWK Tests ====================

#[test]
fn ec_p256_jwk_creates_verifier() {
    let factory = OpenSslJwkVerifierFactory;
    let (_pkey, jwk) = generate_p256_jwk();

    let verifier = factory.verifier_from_ec_jwk(&jwk, -7); // ES256
    assert!(
        verifier.is_ok(),
        "P-256 JWK should create verifier: {:?}",
        verifier.err()
    );
    assert_eq!(verifier.unwrap().algorithm(), -7);
}

#[test]
fn ec_p384_jwk_creates_verifier() {
    let factory = OpenSslJwkVerifierFactory;
    let (_pkey, jwk) = generate_p384_jwk();

    let verifier = factory.verifier_from_ec_jwk(&jwk, -35); // ES384
    assert!(
        verifier.is_ok(),
        "P-384 JWK should create verifier: {:?}",
        verifier.err()
    );
    assert_eq!(verifier.unwrap().algorithm(), -35);
}

#[test]
fn ec_p256_jwk_verifies_signature() {
    let factory = OpenSslJwkVerifierFactory;
    let (pkey, jwk) = generate_p256_jwk();

    // Sign some data with the private key
    let data = b"test data for ES256 signature verification";
    let mut signer =
        openssl::sign::Signer::new(openssl::hash::MessageDigest::sha256(), &pkey).unwrap();
    let der_sig = signer.sign_oneshot_to_vec(data).unwrap();
    // Convert DER → fixed r||s format (COSE uses fixed-length)
    let fixed_sig = cose_sign1_crypto_openssl::ecdsa_format::der_to_fixed(&der_sig, 64).unwrap();

    // Create verifier from JWK and verify
    let verifier = factory.verifier_from_ec_jwk(&jwk, -7).unwrap();
    let result = verifier.verify(data, &fixed_sig);
    assert!(result.is_ok());
    assert!(result.unwrap(), "Signature should verify with matching key");
}

#[test]
fn ec_p384_jwk_verifies_signature() {
    let factory = OpenSslJwkVerifierFactory;
    let (pkey, jwk) = generate_p384_jwk();

    let data = b"test data for ES384 signature verification";
    let mut signer =
        openssl::sign::Signer::new(openssl::hash::MessageDigest::sha384(), &pkey).unwrap();
    let der_sig = signer.sign_oneshot_to_vec(data).unwrap();
    let fixed_sig = cose_sign1_crypto_openssl::ecdsa_format::der_to_fixed(&der_sig, 96).unwrap();

    let verifier = factory.verifier_from_ec_jwk(&jwk, -35).unwrap();
    let result = verifier.verify(data, &fixed_sig);
    assert!(result.is_ok());
    assert!(result.unwrap(), "ES384 signature should verify");
}

#[test]
fn ec_jwk_wrong_key_rejects_signature() {
    let factory = OpenSslJwkVerifierFactory;
    let (pkey, _jwk1) = generate_p256_jwk();
    let (_pkey2, jwk2) = generate_p256_jwk(); // different key

    let data = b"signed with key 1";
    let mut signer =
        openssl::sign::Signer::new(openssl::hash::MessageDigest::sha256(), &pkey).unwrap();
    let der_sig = signer.sign_oneshot_to_vec(data).unwrap();
    let fixed_sig = cose_sign1_crypto_openssl::ecdsa_format::der_to_fixed(&der_sig, 64).unwrap();

    // Verify with DIFFERENT key should fail
    let verifier = factory.verifier_from_ec_jwk(&jwk2, -7).unwrap();
    let result = verifier.verify(data, &fixed_sig);
    assert!(result.is_ok());
    assert!(!result.unwrap(), "Wrong key should reject signature");
}

// ==================== EC JWK Error Cases ====================

#[test]
fn ec_jwk_wrong_kty_rejected() {
    let factory = OpenSslJwkVerifierFactory;
    let jwk = EcJwk {
        kty: "RSA".to_string(), // wrong type
        crv: "P-256".to_string(),
        x: b64url(&[1u8; 32]),
        y: b64url(&[2u8; 32]),
        kid: None,
    };
    assert!(factory.verifier_from_ec_jwk(&jwk, -7).is_err());
}

#[test]
fn ec_jwk_unsupported_curve_rejected() {
    let factory = OpenSslJwkVerifierFactory;
    let jwk = EcJwk {
        kty: "EC".to_string(),
        crv: "secp256k1".to_string(), // not supported
        x: b64url(&[1u8; 32]),
        y: b64url(&[2u8; 32]),
        kid: None,
    };
    assert!(factory.verifier_from_ec_jwk(&jwk, -7).is_err());
}

#[test]
fn ec_jwk_wrong_coordinate_length_rejected() {
    let factory = OpenSslJwkVerifierFactory;
    let jwk = EcJwk {
        kty: "EC".to_string(),
        crv: "P-256".to_string(),
        x: b64url(&[1u8; 16]), // too short for P-256
        y: b64url(&[2u8; 32]),
        kid: None,
    };
    assert!(factory.verifier_from_ec_jwk(&jwk, -7).is_err());
}

#[test]
fn ec_jwk_invalid_point_rejected() {
    let factory = OpenSslJwkVerifierFactory;
    // All-zeros is not a valid point on P-256
    let jwk = EcJwk {
        kty: "EC".to_string(),
        crv: "P-256".to_string(),
        x: b64url(&[0u8; 32]),
        y: b64url(&[0u8; 32]),
        kid: None,
    };
    assert!(factory.verifier_from_ec_jwk(&jwk, -7).is_err());
}

// ==================== RSA JWK Tests ====================

#[test]
fn rsa_jwk_creates_verifier() {
    let factory = OpenSslJwkVerifierFactory;
    let (_pkey, jwk) = generate_rsa_jwk();

    let verifier = factory.verifier_from_rsa_jwk(&jwk, -37); // PS256
    assert!(
        verifier.is_ok(),
        "RSA JWK should create verifier: {:?}",
        verifier.err()
    );
}

#[test]
fn rsa_jwk_wrong_kty_rejected() {
    let factory = OpenSslJwkVerifierFactory;
    let jwk = RsaJwk {
        kty: "EC".to_string(), // wrong
        n: b64url(&[1u8; 256]),
        e: b64url(&[1, 0, 1]),
        kid: None,
    };
    assert!(factory.verifier_from_rsa_jwk(&jwk, -37).is_err());
}

#[test]
fn rsa_jwk_verifies_signature() {
    let factory = OpenSslJwkVerifierFactory;
    let (pkey, jwk) = generate_rsa_jwk();

    let data = b"test data for RSA-PSS signature";
    let mut signer =
        openssl::sign::Signer::new(openssl::hash::MessageDigest::sha256(), &pkey).unwrap();
    signer
        .set_rsa_padding(openssl::rsa::Padding::PKCS1_PSS)
        .unwrap();
    signer
        .set_rsa_pss_saltlen(openssl::sign::RsaPssSaltlen::DIGEST_LENGTH)
        .unwrap();
    let sig = signer.sign_oneshot_to_vec(data).unwrap();

    let verifier = factory.verifier_from_rsa_jwk(&jwk, -37).unwrap(); // PS256
    let result = verifier.verify(data, &sig);
    assert!(result.is_ok());
    assert!(result.unwrap(), "RSA-PSS signature should verify");
}

// ==================== Jwk Enum Dispatch ====================

#[test]
fn jwk_enum_dispatches_to_ec() {
    let factory = OpenSslJwkVerifierFactory;
    let (_pkey, ec_jwk) = generate_p256_jwk();
    let jwk = Jwk::Ec(ec_jwk);

    let verifier = factory.verifier_from_jwk(&jwk, -7);
    assert!(verifier.is_ok());
}

#[test]
fn jwk_enum_dispatches_to_rsa() {
    let factory = OpenSslJwkVerifierFactory;
    let (_pkey, rsa_jwk) = generate_rsa_jwk();
    let jwk = Jwk::Rsa(rsa_jwk);

    let verifier = factory.verifier_from_jwk(&jwk, -37);
    assert!(verifier.is_ok());
}

// ==================== key_conversion tests ====================

#[test]
fn ec_point_to_spki_der_p256() {
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
    let ec_key = EcKey::generate(&group).unwrap();
    let mut ctx = openssl::bn::BigNumContext::new().unwrap();
    let point_bytes = ec_key
        .public_key()
        .to_bytes(
            &group,
            openssl::ec::PointConversionForm::UNCOMPRESSED,
            &mut ctx,
        )
        .unwrap();

    let spki = ec_point_to_spki_der(&point_bytes, "P-256");
    assert!(spki.is_ok());
    let spki = spki.unwrap();
    assert_eq!(spki[0], 0x30, "SPKI DER starts with SEQUENCE");
    assert!(spki.len() > 65);
}

#[test]
fn ec_point_to_spki_der_p384() {
    let group = EcGroup::from_curve_name(Nid::SECP384R1).unwrap();
    let ec_key = EcKey::generate(&group).unwrap();
    let mut ctx = openssl::bn::BigNumContext::new().unwrap();
    let point_bytes = ec_key
        .public_key()
        .to_bytes(
            &group,
            openssl::ec::PointConversionForm::UNCOMPRESSED,
            &mut ctx,
        )
        .unwrap();

    let spki = ec_point_to_spki_der(&point_bytes, "P-384");
    assert!(spki.is_ok());
}

#[test]
fn ec_point_to_spki_der_invalid_prefix() {
    let bad_point = vec![0x00; 65]; // missing 0x04 prefix
    assert!(ec_point_to_spki_der(&bad_point, "P-256").is_err());
}

#[test]
fn ec_point_to_spki_der_empty() {
    assert!(ec_point_to_spki_der(&[], "P-256").is_err());
}

#[test]
fn ec_point_to_spki_der_unsupported_curve() {
    let point = vec![0x04; 65];
    assert!(ec_point_to_spki_der(&point, "secp256k1").is_err());
}
