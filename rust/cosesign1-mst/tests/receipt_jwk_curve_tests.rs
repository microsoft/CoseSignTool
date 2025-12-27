// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Receipt verifier JWK curve handling tests.
//!
//! These tests are intentionally "receipt driven" (we call
//! `verify_transparent_statement_receipt`) but the assertions focus on curve
//! selection and JWK->SPKI conversion paths.

mod common;

use common::*;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use cosesign1_mst::{verify_transparent_statement_receipt, JwkEcPublicKey};

#[test]
fn receipt_verification_covers_p384_and_p521_invalid_key_material_branches() {
    let sk = p256::ecdsa::SigningKey::from_bytes(&[27u8; 32].into()).expect("sk");
    let receipt = build_receipt_es256("kid-1", "issuer.example", b"claims", &sk);

    // Valid base64, wrong sizes => triggers the curve-specific from_sec1_bytes error paths.
    let tiny = URL_SAFE_NO_PAD.encode([1u8]);
    let bad_p384 = JwkEcPublicKey {
        kty: "EC".to_string(),
        crv: "P-384".to_string(),
        x: tiny.clone(),
        y: tiny.clone(),
        kid: "kid-1".to_string(),
    };
    let res1 = verify_transparent_statement_receipt("mst", &bad_p384, &receipt, b"claims");
    assert!(!res1.is_valid);
    assert_eq!(res1.failures[0].error_code.as_deref(), Some("MST_JWK_ERROR"));

    let bad_p521 = JwkEcPublicKey {
        kty: "EC".to_string(),
        crv: "P-521".to_string(),
        x: tiny.clone(),
        y: tiny,
        kid: "kid-1".to_string(),
    };
    let res2 = verify_transparent_statement_receipt("mst", &bad_p521, &receipt, b"claims");
    assert!(!res2.is_valid);
    assert_eq!(res2.failures[0].error_code.as_deref(), Some("MST_JWK_ERROR"));
}

#[test]
fn receipt_verification_covers_p384_and_p521_jwk_conversion_success_paths() {
    // Receipt can be any well-formed ES256 receipt; we force a KID mismatch to stop early.
    let sk = p256::ecdsa::SigningKey::from_bytes(&[29u8; 32].into()).expect("sk");
    let receipt = build_receipt_es256("kid-in-receipt", "issuer.example", b"claims", &sk);

    // P-384 key -> JWK -> SPKI conversion should succeed.
    let sk384 = p384::ecdsa::SigningKey::from_bytes(&[1u8; 48].into()).expect("sk384");
    let vk384 = sk384.verifying_key();
    let p384_point = vk384.to_encoded_point(false);
    let p384_x = p384_point.x().expect("x");
    let p384_y = p384_point.y().expect("y");
    let jwk384 = JwkEcPublicKey {
        kty: "EC".to_string(),
        crv: "P-384".to_string(),
        x: URL_SAFE_NO_PAD.encode(p384_x),
        y: URL_SAFE_NO_PAD.encode(p384_y),
        kid: "different-kid".to_string(),
    };
    let res1 = verify_transparent_statement_receipt("mst", &jwk384, &receipt, b"claims");
    assert!(!res1.is_valid);
    assert_eq!(res1.failures[0].error_code.as_deref(), Some("MST_KID_MISMATCH"));

    // P-521 key -> JWK -> SPKI conversion should succeed.
    let mut rng = p521::elliptic_curve::rand_core::OsRng;
    let sk521 = p521::ecdsa::SigningKey::random(&mut rng);
    let vk521 = p521::ecdsa::VerifyingKey::from(&sk521);
    let p521_point = vk521.to_encoded_point(false);
    let p521_x = p521_point.x().expect("x");
    let p521_y = p521_point.y().expect("y");
    let jwk521 = JwkEcPublicKey {
        kty: "EC".to_string(),
        crv: "P-521".to_string(),
        x: URL_SAFE_NO_PAD.encode(p521_x),
        y: URL_SAFE_NO_PAD.encode(p521_y),
        kid: "different-kid".to_string(),
    };
    let res2 = verify_transparent_statement_receipt("mst", &jwk521, &receipt, b"claims");
    assert!(!res2.is_valid);
    assert_eq!(res2.failures[0].error_code.as_deref(), Some("MST_KID_MISMATCH"));
}
