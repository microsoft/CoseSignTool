// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Receipt-focused tests.
//!
//! These tests exercise the receipt verifier in isolation via
//! `verify_transparent_statement_receipt`.

mod common;

use common::*;
use cosesign1_mst::{verify_transparent_statement_receipt, JwkEcPublicKey};

#[test]
fn receipt_happy_path_verifies() {
    // A well-formed ES256 receipt should verify against the claims bytes.
    let sk = p256::ecdsa::SigningKey::from_bytes(&[1u8; 32].into()).expect("sk");
    let vk = sk.verifying_key();

    let kid = "kid-1";
    let issuer = "issuer.example";
    let claims = b"claims";

    let jwk = build_jwk_from_p256(kid, vk);
    let receipt = build_receipt_es256(kid, issuer, claims, &sk);

    let res = verify_transparent_statement_receipt("mst", &jwk, &receipt, claims);
    assert!(res.is_valid, "{:?}", res.failures);
}

#[test]
fn receipt_claim_digest_mismatch_fails() {
    // If the receipt commits to different claims, we should fail with the digest mismatch.
    let sk = p256::ecdsa::SigningKey::from_bytes(&[2u8; 32].into()).expect("sk");
    let vk = sk.verifying_key();

    let kid = "kid-1";
    let issuer = "issuer.example";
    let claims = b"claims";
    let receipt = build_receipt_es256(kid, issuer, claims, &sk);

    let jwk = build_jwk_from_p256(kid, vk);
    let res = verify_transparent_statement_receipt("mst", &jwk, &receipt, b"different");
    assert!(!res.is_valid);
    assert_eq!(res.failures[0].error_code.as_deref(), Some("MST_CLAIM_DIGEST_MISMATCH"));
}

#[test]
fn receipt_kid_mismatch_fails_before_signature() {
    // KID mismatch should be detected before doing expensive signature verification.
    let sk = p256::ecdsa::SigningKey::from_bytes(&[3u8; 32].into()).expect("sk");
    let vk = sk.verifying_key();

    let kid = "kid-1";
    let issuer = "issuer.example";
    let claims = b"claims";
    let receipt = build_receipt_es256(kid, issuer, claims, &sk);

    let jwk = build_jwk_from_p256("kid-other", vk);
    let res = verify_transparent_statement_receipt("mst", &jwk, &receipt, claims);
    assert!(!res.is_valid);
    assert_eq!(res.failures[0].error_code.as_deref(), Some("MST_KID_MISMATCH"));
}

#[test]
fn receipt_signature_invalid_is_reported() {
    // Corrupting the receipt signature should produce the signature-invalid error.
    let sk = p256::ecdsa::SigningKey::from_bytes(&[12u8; 32].into()).expect("sk");
    let vk = sk.verifying_key();

    let kid = "kid-1";
    let issuer = "issuer.example";
    let claims = b"claims";

    let jwk = build_jwk_from_p256(kid, vk);
    let mut receipt = build_receipt_es256(kid, issuer, claims, &sk);
    *receipt.last_mut().unwrap() ^= 0x01;

    let res = verify_transparent_statement_receipt("mst", &jwk, &receipt, claims);
    assert!(!res.is_valid);
    assert_eq!(res.failures[0].error_code.as_deref(), Some("MST_RECEIPT_SIGNATURE_INVALID"));
}

#[test]
fn receipt_verification_reports_kid_missing() {
    // If the protected header lacks the KID, we should report MST_KID_MISSING.
    let sk = p256::ecdsa::SigningKey::from_bytes(&[23u8; 32].into()).expect("sk");
    let vk = sk.verifying_key();
    let jwk = build_jwk_from_p256("kid-ignored", vk);

    let mut protected = Vec::new();
    {
        let mut enc = minicbor::Encoder::new(&mut protected);
        enc.map(3).unwrap();
        enc.i64(1).unwrap();
        enc.i64(-7).unwrap();
        enc.i64(395).unwrap();
        enc.i64(2).unwrap();
        enc.i64(15).unwrap();
        enc.map(1).unwrap();
        enc.i64(1).unwrap();
        enc.str("issuer.example").unwrap();
    }
    let inclusion_map = encode_inclusion_map_with_path(b"claims", &[]);
    let receipt = encode_receipt(&protected, &inclusion_map, b"sig");

    let res = verify_transparent_statement_receipt("mst", &jwk, &receipt, b"claims");
    assert!(!res.is_valid);
    assert_eq!(res.failures[0].error_code.as_deref(), Some("MST_KID_MISSING"));
}

#[test]
fn receipt_verification_succeeds_when_expected_kid_is_empty_string() {
    // Empty-string KIDs are used by some call-sites. The verifier treats an empty expected KID
    // as "don't check" and should still verify successfully.
    let sk = p256::ecdsa::SigningKey::from_bytes(&[28u8; 32].into()).expect("sk");
    let vk = sk.verifying_key();

    let receipt = build_receipt_es256("kid-1", "issuer.example", b"claims", &sk);

    let mut jwk = build_jwk_from_p256("", vk);
    jwk.kid = "".to_string();

    let res = verify_transparent_statement_receipt("mst", &jwk, &receipt, b"claims");
    assert!(res.is_valid, "{:?}", res.failures);
}

#[test]
fn receipt_verification_accepts_inclusion_proofs_array_wrapped_in_bstr() {
    // Exercise the path where the inclusion proofs array is wrapped in a bstr.
    let sk = p256::ecdsa::SigningKey::from_bytes(&[22u8; 32].into()).expect("sk");
    let vk = sk.verifying_key();
    let kid = "kid-1";
    let jwk = build_jwk_from_p256(kid, vk);

    let protected = encode_receipt_headers(kid, Some("issuer.example"), Some(2), true);
    let inclusion_map = encode_inclusion_map_with_path(b"claims", &[]);

    let mut wrapped = Vec::new();
    {
        let mut enc = minicbor::Encoder::new(&mut wrapped);
        enc.array(1).unwrap();
        enc.bytes(&inclusion_map).unwrap();
    }

    let mut vdp = Vec::new();
    {
        let mut enc = minicbor::Encoder::new(&mut vdp);
        enc.map(1).unwrap();
        enc.i64(-1).unwrap();
        enc.bytes(&wrapped).unwrap();
    }

    let receipt = encode_receipt_with_vdp_value(&protected, Some(&vdp), &[0u8; 64]);
    let res = verify_transparent_statement_receipt("mst", &jwk, &receipt, b"claims");
    assert!(!res.is_valid);
    assert_eq!(res.failures[0].error_code.as_deref(), Some("MST_RECEIPT_SIGNATURE_INVALID"));
}

#[test]
fn receipt_parses_proof_path_when_path_is_bstr_encoded_array() {
    // Exercise the "path is bstr" decode branch in proof parsing.
    let issuer = "issuer.example";
    let kid = "kid";
    let claims = b"claims";

    let tx_hash = sha256(b"tx");
    let evidence = "evidence";
    let data_hash = sha256(claims);

    // Path value is a bstr containing CBOR array (empty array = 0x80).
    let path_cbor = vec![0x80u8];

    let mut inclusion_map = Vec::new();
    {
        let mut enc = minicbor::Encoder::new(&mut inclusion_map);
        enc.map(2).unwrap();
        enc.i64(1).unwrap();
        enc.array(3).unwrap();
        enc.bytes(&tx_hash).unwrap();
        enc.str(evidence).unwrap();
        enc.bytes(&data_hash).unwrap();
        enc.i64(2).unwrap();
        enc.bytes(&path_cbor).unwrap();
    }

    let protected = encode_receipt_headers(kid, Some(issuer), Some(2), false);
    let receipt = encode_receipt(&protected, &inclusion_map, &[0u8; 64]);

    let sk = p256::ecdsa::SigningKey::from_bytes(&[14u8; 32].into()).expect("sk");
    let vk = sk.verifying_key();
    let jwk = build_jwk_from_p256(kid, vk);

    let res = verify_transparent_statement_receipt("mst", &jwk, &receipt, claims);
    assert!(!res.is_valid);
    assert_eq!(
        res.failures.first().and_then(|f| f.error_code.as_deref()),
        Some("MST_RECEIPT_SIGNATURE_INVALID")
    );
}

#[test]
fn receipt_reports_path_parse_error_for_invalid_path_type() {
    // Exercise the MST_PATH_PARSE_ERROR early return by making the inclusion map's
    // path value a non-array/non-bstr type.
    let issuer = "issuer.example";
    let kid = "kid";
    let claims = b"claims";

    let tx_hash = sha256(b"tx");
    let evidence = "evidence";
    let data_hash = sha256(claims);

    let mut inclusion_map = Vec::new();
    {
        let mut enc = minicbor::Encoder::new(&mut inclusion_map);
        enc.map(2).unwrap();
        enc.i64(1).unwrap();
        enc.array(3).unwrap();
        enc.bytes(&tx_hash).unwrap();
        enc.str(evidence).unwrap();
        enc.bytes(&data_hash).unwrap();
        enc.i64(2).unwrap();
        enc.i64(1).unwrap();
    }

    let protected = encode_receipt_headers(kid, Some(issuer), Some(2), false);
    let receipt = encode_receipt(&protected, &inclusion_map, &[0u8; 64]);

    let sk = p256::ecdsa::SigningKey::from_bytes(&[14u8; 32].into()).expect("sk");
    let vk = sk.verifying_key();
    let jwk = build_jwk_from_p256(kid, vk);

    let res = verify_transparent_statement_receipt("mst", &jwk, &receipt, claims);
    assert!(!res.is_valid);
    assert_eq!(
        res.failures.first().and_then(|f| f.error_code.as_deref()),
        Some("MST_PATH_PARSE_ERROR")
    );
}

#[test]
fn receipt_non_empty_path_exercises_left_and_right_accumulator_steps() {
    // Use a non-empty inclusion path with left/right steps to exercise accumulator hashing.
    let sk = p256::ecdsa::SigningKey::from_bytes(&[13u8; 32].into()).expect("sk");
    let vk = sk.verifying_key();
    let kid = "kid-1";
    let issuer = "issuer.example";
    let claims = b"claims";

    let jwk = build_jwk_from_p256(kid, vk);

    let h1 = sha256(b"p1");
    let h2 = sha256(b"p2");
    let inclusion_map = encode_inclusion_map_with_path(claims, &[(true, &h1), (false, &h2)]);

    let mut protected = Vec::new();
    {
        let mut enc = minicbor::Encoder::new(&mut protected);
        enc.map(4).unwrap();
        enc.i64(1).unwrap();
        enc.i64(-7).unwrap(); // ES256
        enc.i64(4).unwrap();
        enc.bytes(kid.as_bytes()).unwrap();
        enc.i64(395).unwrap();
        enc.i64(2).unwrap();
        enc.i64(15).unwrap();
        enc.map(1).unwrap();
        enc.i64(1).unwrap();
        enc.str(issuer).unwrap();
    }

    let receipt = encode_receipt(&protected, &inclusion_map, &[0u8; 64]);
    let res = verify_transparent_statement_receipt("mst", &jwk, &receipt, claims);
    assert!(!res.is_valid);
    assert_eq!(res.failures[0].error_code.as_deref(), Some("MST_RECEIPT_SIGNATURE_INVALID"));
}

#[test]
fn receipt_verification_reports_vds_and_vdp_errors() {
    // Exercise missing/wrong VDS and missing/wrong-type VDP handling.
    let sk = p256::ecdsa::SigningKey::from_bytes(&[18u8; 32].into()).expect("sk");
    let vk = sk.verifying_key();
    let kid = "kid-1";
    let jwk = build_jwk_from_p256(kid, vk);

    let inclusion_map = encode_inclusion_map_with_path(b"claims", &[]);

    let protected_missing_vds = encode_receipt_headers(kid, Some("issuer.example"), None, false);
    let receipt_missing_vds = encode_receipt(&protected_missing_vds, &inclusion_map, b"sig");
    let res = verify_transparent_statement_receipt("mst", &jwk, &receipt_missing_vds, b"claims");
    assert!(!res.is_valid);
    assert_eq!(res.failures[0].error_code.as_deref(), Some("MST_VDS_MISSING"));

    let protected_wrong_vds = encode_receipt_headers(kid, Some("issuer.example"), Some(3), false);
    let receipt_wrong_vds = encode_receipt(&protected_wrong_vds, &inclusion_map, b"sig");
    let res2 = verify_transparent_statement_receipt("mst", &jwk, &receipt_wrong_vds, b"claims");
    assert!(!res2.is_valid);
    assert_eq!(res2.failures[0].error_code.as_deref(), Some("MST_VDS_NOT_CCF"));

    let protected_ok = encode_receipt_headers(kid, Some("issuer.example"), Some(2), false);
    let receipt_missing_vdp = encode_receipt_with_vdp_value(&protected_ok, None, b"sig");
    let res3 = verify_transparent_statement_receipt("mst", &jwk, &receipt_missing_vdp, b"claims");
    assert!(!res3.is_valid);
    assert_eq!(res3.failures[0].error_code.as_deref(), Some("MST_VDP_MISSING"));

    let receipt_vdp_int = encode_receipt_with_vdp_header_int(&protected_ok, 123, b"sig");
    let res4 = verify_transparent_statement_receipt("mst", &jwk, &receipt_vdp_int, b"claims");
    assert!(!res4.is_valid);
    assert_eq!(res4.failures[0].error_code.as_deref(), Some("MST_VDP_PARSE_ERROR"));
}

#[test]
fn receipt_verification_handles_jwk_conversion_errors() {
    // JWK conversion failures should map to MST_JWK_ERROR.
    let sk = p256::ecdsa::SigningKey::from_bytes(&[16u8; 32].into()).expect("sk");
    let kid = "kid-1";
    let issuer = "issuer.example";
    let claims = b"claims";
    let receipt = build_receipt_es256(kid, issuer, claims, &sk);

    let bad_kty = JwkEcPublicKey {
        kty: "RSA".to_string(),
        crv: "P-256".to_string(),
        x: "AA".to_string(),
        y: "AA".to_string(),
        kid: kid.to_string(),
    };
    let res = verify_transparent_statement_receipt("mst", &bad_kty, &receipt, claims);
    assert!(!res.is_valid);
    assert_eq!(res.failures[0].error_code.as_deref(), Some("MST_JWK_ERROR"));

    let mut bad_x = build_jwk_from_p256(kid, sk.verifying_key());
    bad_x.x = "%%%".to_string();
    let res2 = verify_transparent_statement_receipt("mst", &bad_x, &receipt, claims);
    assert!(!res2.is_valid);
    assert_eq!(res2.failures[0].error_code.as_deref(), Some("MST_JWK_ERROR"));
}

#[test]
fn receipt_verification_handles_more_jwk_errors_and_curves() {
    // Cover additional base64 errors and curve selection paths.
    let sk = p256::ecdsa::SigningKey::from_bytes(&[17u8; 32].into()).expect("sk");
    let kid = "kid-1";
    let issuer = "issuer.example";
    let claims = b"claims";
    let receipt = build_receipt_es256(kid, issuer, claims, &sk);

    let mut bad_y = build_jwk_from_p256(kid, sk.verifying_key());
    bad_y.y = "%%%".to_string();
    let res = verify_transparent_statement_receipt("mst", &bad_y, &receipt, claims);
    assert!(!res.is_valid);
    assert_eq!(res.failures[0].error_code.as_deref(), Some("MST_JWK_ERROR"));

    let mut bad_p384 = build_jwk_from_p256(kid, sk.verifying_key());
    bad_p384.crv = "P-384".to_string();
    bad_p384.x = "%%%".to_string();
    let res2 = verify_transparent_statement_receipt("mst", &bad_p384, &receipt, claims);
    assert!(!res2.is_valid);
    assert_eq!(res2.failures[0].error_code.as_deref(), Some("MST_JWK_ERROR"));

    let mut bad_p521 = build_jwk_from_p256(kid, sk.verifying_key());
    bad_p521.crv = "P-521".to_string();
    bad_p521.x = "%%%".to_string();
    let res3 = verify_transparent_statement_receipt("mst", &bad_p521, &receipt, claims);
    assert!(!res3.is_valid);
    assert_eq!(res3.failures[0].error_code.as_deref(), Some("MST_JWK_ERROR"));

    let mut bad_curve = build_jwk_from_p256(kid, sk.verifying_key());
    bad_curve.crv = "P-999".to_string();
    let res4 = verify_transparent_statement_receipt("mst", &bad_curve, &receipt, claims);
    assert!(!res4.is_valid);
    assert_eq!(res4.failures[0].error_code.as_deref(), Some("MST_JWK_ERROR"));
}
