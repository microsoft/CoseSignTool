// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Extended test coverage for MST receipt verification internal parsing functions.

use cbor_primitives::CborEncoder;

use cose_sign1_crypto_openssl::jwk_verifier::OpenSslJwkVerifierFactory;
use cose_sign1_transparent_mst::validation::receipt_verify::{
    base64url_decode, find_jwk_for_kid, is_cose_sign1_tagged_18, local_jwk_to_ec_jwk, sha256,
    sha256_concat_slices, validate_receipt_alg_against_jwk, verify_mst_receipt, Jwk,
    ReceiptVerifyError, ReceiptVerifyInput,
};

/// Test that ReceiptVerifyError debug output works for all variants
#[test]
fn test_receipt_verify_error_debug_all_variants() {
    let errors = vec![
        ReceiptVerifyError::ReceiptDecode("test".to_string()),
        ReceiptVerifyError::MissingAlg,
        ReceiptVerifyError::MissingKid,
        ReceiptVerifyError::UnsupportedAlg(-100),
        ReceiptVerifyError::UnsupportedVds(5),
        ReceiptVerifyError::MissingVdp,
        ReceiptVerifyError::MissingProof,
        ReceiptVerifyError::MissingIssuer,
        ReceiptVerifyError::JwksParse("parse error".to_string()),
        ReceiptVerifyError::JwksFetch("fetch error".to_string()),
        ReceiptVerifyError::JwkNotFound("kid123".to_string()),
        ReceiptVerifyError::JwkUnsupported("unsupported".to_string()),
        ReceiptVerifyError::StatementReencode("reencode".to_string()),
        ReceiptVerifyError::SigStructureEncode("sigstruct".to_string()),
        ReceiptVerifyError::DataHashMismatch,
        ReceiptVerifyError::SignatureInvalid,
    ];

    for error in errors {
        let debug_str = format!("{:?}", error);
        assert!(!debug_str.is_empty());
    }
}

/// Test base64url_decode with various edge cases
#[test]
fn test_base64url_decode_multiple_padding_levels() {
    // Test single char padding
    let result1 = base64url_decode("YQ==").unwrap(); // "a"
    assert_eq!(result1, b"a");

    // Test double char padding
    let result2 = base64url_decode("YWI=").unwrap(); // "ab"
    assert_eq!(result2, b"ab");

    // Test no padding needed
    let result3 = base64url_decode("YWJj").unwrap(); // "abc"
    assert_eq!(result3, b"abc");
}

#[test]
fn test_base64url_decode_all_url_safe_chars() {
    // Test that URL-safe characters decode correctly
    // '-' replaces '+' and '_' replaces '/' in base64url
    let input = "-_";
    let result = base64url_decode(input).unwrap();
    // Should decode to bytes that correspond to these URL-safe chars
    assert!(!result.is_empty() || input.is_empty());
}

#[test]
fn test_base64url_decode_binary_data() {
    // Encode and decode binary data with all byte values
    let original = vec![0x00, 0xFF, 0x7F, 0x80];
    // Pre-encoded base64url representation
    let encoded = "AP9_gA";
    let decoded = base64url_decode(encoded).unwrap();
    assert_eq!(decoded, original);
}

/// Test is_cose_sign1_tagged_18 with various inputs
#[test]
fn test_is_cose_sign1_tagged_18_various_tags() {
    // Tag 17 (not 18)
    let tag17 = &[0xD1, 0x84];
    let result = is_cose_sign1_tagged_18(tag17).unwrap();
    assert!(!result);

    // Tag 19 (not 18)
    let tag19 = &[0xD3, 0x84];
    let result = is_cose_sign1_tagged_18(tag19).unwrap();
    assert!(!result);
}

#[test]
fn test_is_cose_sign1_tagged_18_map_input() {
    // CBOR map instead of tag
    let map_input = &[0xA1, 0x01, 0x02]; // {1: 2}
    let result = is_cose_sign1_tagged_18(map_input).unwrap();
    assert!(!result);
}

#[test]
fn test_is_cose_sign1_tagged_18_bstr_input() {
    // CBOR bstr instead of tag
    let bstr_input = &[0x44, 0x01, 0x02, 0x03, 0x04]; // h'01020304'
    let result = is_cose_sign1_tagged_18(bstr_input).unwrap();
    assert!(!result);
}

#[test]
fn test_is_cose_sign1_tagged_18_integer_input() {
    // CBOR integer
    let int_input = &[0x18, 0x64]; // 100
    let result = is_cose_sign1_tagged_18(int_input).unwrap();
    assert!(!result);
}

/// Test local_jwk_to_ec_jwk with P-384 curve
#[test]
fn test_local_jwk_to_ec_jwk_p384_valid() {
    let x_b64 = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEB";
    let y_b64 = "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIC";

    let jwk = Jwk {
        kty: "EC".to_string(),
        crv: Some("P-384".to_string()),
        kid: Some("test-key".to_string()),
        x: Some(x_b64.to_string()),
        y: Some(y_b64.to_string()),
    };

    let result = local_jwk_to_ec_jwk(&jwk);
    assert!(result.is_ok());
    let ec = result.unwrap();
    assert_eq!(ec.crv, "P-384");
    assert_eq!(ec.x, x_b64);
    assert_eq!(ec.y, y_b64);
    assert_eq!(ec.kid, Some("test-key".to_string()));
}

#[test]
fn test_local_jwk_to_ec_jwk_wrong_kty() {
    let jwk = Jwk {
        kty: "RSA".to_string(),
        crv: Some("P-256".to_string()),
        kid: None,
        x: Some("x".to_string()),
        y: Some("y".to_string()),
    };
    assert!(local_jwk_to_ec_jwk(&jwk).is_err());
}

#[test]
fn test_local_jwk_to_ec_jwk_missing_crv() {
    let jwk = Jwk {
        kty: "EC".to_string(),
        crv: None,
        kid: None,
        x: Some("x".to_string()),
        y: Some("y".to_string()),
    };
    assert!(local_jwk_to_ec_jwk(&jwk).is_err());
}

#[test]
fn test_local_jwk_to_ec_jwk_missing_x() {
    let jwk = Jwk {
        kty: "EC".to_string(),
        crv: Some("P-256".to_string()),
        kid: None,
        x: None,
        y: Some("y".to_string()),
    };
    assert!(local_jwk_to_ec_jwk(&jwk).is_err());
}

#[test]
fn test_local_jwk_to_ec_jwk_missing_y() {
    let jwk = Jwk {
        kty: "EC".to_string(),
        crv: Some("P-256".to_string()),
        kid: None,
        x: Some("x".to_string()),
        y: None,
    };
    assert!(local_jwk_to_ec_jwk(&jwk).is_err());
}

/// Test validate_receipt_alg_against_jwk with various curve/alg combinations
#[test]
fn test_validate_receipt_alg_against_jwk_p256_es384_mismatch() {
    let jwk = Jwk {
        kty: "EC".to_string(),
        crv: Some("P-256".to_string()),
        kid: None,
        x: None,
        y: None,
    };

    // P-256 with ES384 should fail
    let result = validate_receipt_alg_against_jwk(&jwk, -35);
    assert!(result.is_err());
}

#[test]
fn test_validate_receipt_alg_against_jwk_p384_es256_mismatch() {
    let jwk = Jwk {
        kty: "EC".to_string(),
        crv: Some("P-384".to_string()),
        kid: None,
        x: None,
        y: None,
    };

    // P-384 with ES256 should fail
    let result = validate_receipt_alg_against_jwk(&jwk, -7);
    assert!(result.is_err());
}

#[test]
fn test_validate_receipt_alg_against_jwk_unknown_curve() {
    let jwk = Jwk {
        kty: "EC".to_string(),
        crv: Some("P-521".to_string()), // Not supported
        kid: None,
        x: None,
        y: None,
    };

    let result = validate_receipt_alg_against_jwk(&jwk, -7);
    assert!(result.is_err());
    match result.unwrap_err() {
        ReceiptVerifyError::JwkUnsupported(msg) => {
            assert!(msg.contains("alg_curve_mismatch"));
        }
        _ => panic!("Wrong error type"),
    }
}

/// Test find_jwk_for_kid with multiple keys
#[test]
fn test_find_jwk_for_kid_first_key_match() {
    let jwks_json = r#"{
        "keys": [
            {
                "kty": "EC",
                "crv": "P-256",
                "kid": "first-key",
                "x": "x1",
                "y": "y1"
            },
            {
                "kty": "EC",
                "crv": "P-384",
                "kid": "second-key",
                "x": "x2",
                "y": "y2"
            }
        ]
    }"#;

    let result = find_jwk_for_kid(jwks_json, "first-key").unwrap();
    assert_eq!(result.kid, Some("first-key".to_string()));
    assert_eq!(result.crv, Some("P-256".to_string()));
}

#[test]
fn test_find_jwk_for_kid_last_key_match() {
    let jwks_json = r#"{
        "keys": [
            {
                "kty": "EC",
                "crv": "P-256",
                "kid": "first-key",
                "x": "x1",
                "y": "y1"
            },
            {
                "kty": "EC",
                "crv": "P-384",
                "kid": "last-key",
                "x": "x2",
                "y": "y2"
            }
        ]
    }"#;

    let result = find_jwk_for_kid(jwks_json, "last-key").unwrap();
    assert_eq!(result.kid, Some("last-key".to_string()));
    assert_eq!(result.crv, Some("P-384".to_string()));
}

/// Test sha256 with known test vectors
#[test]
fn test_sha256_known_vectors() {
    // Test vector: SHA-256 of "abc" = ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
    let result = sha256(b"abc");
    let expected: [u8; 32] = [
        0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22,
        0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00,
        0x15, 0xad,
    ];
    assert_eq!(result, expected);
}

#[test]
fn test_sha256_single_byte() {
    let result = sha256(&[0x00]);
    // SHA-256 of single null byte
    let expected: [u8; 32] = [
        0x6e, 0x34, 0x0b, 0x9c, 0xff, 0xb3, 0x7a, 0x98, 0x9c, 0xa5, 0x44, 0xe6, 0xbb, 0x78, 0x0a,
        0x2c, 0x78, 0x90, 0x1d, 0x3f, 0xb3, 0x37, 0x38, 0x76, 0x85, 0x11, 0xa3, 0x06, 0x17, 0xaf,
        0xa0, 0x1d,
    ];
    assert_eq!(result, expected);
}

/// Test sha256_concat_slices
#[test]
fn test_sha256_concat_slices_order_matters() {
    let a = [0x01; 32];
    let b = [0x02; 32];

    let result_ab = sha256_concat_slices(&a, &b);
    let result_ba = sha256_concat_slices(&b, &a);

    // Order should matter - different results
    assert_ne!(result_ab, result_ba);
}

#[test]
fn test_sha256_concat_slices_empty_like() {
    let zero = [0x00; 32];
    let result = sha256_concat_slices(&zero, &zero);
    // Should be deterministic
    let result2 = sha256_concat_slices(&zero, &zero);
    assert_eq!(result, result2);
}

/// Test Jwk Clone trait
#[test]
fn test_jwk_clone() {
    let jwk = Jwk {
        kty: "EC".to_string(),
        crv: Some("P-256".to_string()),
        kid: Some("test-kid".to_string()),
        x: Some("x-coord".to_string()),
        y: Some("y-coord".to_string()),
    };

    let cloned = jwk.clone();
    assert_eq!(jwk.kty, cloned.kty);
    assert_eq!(jwk.crv, cloned.crv);
    assert_eq!(jwk.kid, cloned.kid);
    assert_eq!(jwk.x, cloned.x);
    assert_eq!(jwk.y, cloned.y);
}

/// Test ReceiptVerifyInput Clone trait
#[test]
fn test_receipt_verify_input_clone() {
    let statement = b"statement";
    let receipt = b"receipt";
    let jwks = r#"{"keys":[]}"#;
    let factory = OpenSslJwkVerifierFactory;

    let input = ReceiptVerifyInput {
        statement_bytes_with_receipts: statement,
        receipt_bytes: receipt,
        offline_jwks_json: Some(jwks),
        allow_network_fetch: true,
        jwks_api_version: Some("2023-01-01"),
        client: None,
        jwk_verifier_factory: &factory,
    };

    let cloned = input.clone();
    assert_eq!(
        input.statement_bytes_with_receipts,
        cloned.statement_bytes_with_receipts
    );
    assert_eq!(input.receipt_bytes, cloned.receipt_bytes);
    assert_eq!(input.offline_jwks_json, cloned.offline_jwks_json);
    assert_eq!(input.allow_network_fetch, cloned.allow_network_fetch);
    assert_eq!(input.jwks_api_version, cloned.jwks_api_version);
}
