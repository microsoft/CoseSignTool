// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Receipt inclusion-proof parsing and error-mapping tests.
//!
//! The MST verifier is intentionally strict about CBOR shapes. These tests build
//! malformed inclusion proofs to exercise specific decoder branches.

mod common;

use common::*;
use cosesign1_mst::verify_transparent_statement_receipt;

#[test]
fn receipt_vdp_bytes_decode_errors_report_parse_error() {
    let sk = p256::ecdsa::SigningKey::from_bytes(&[7u8; 32].into()).expect("sk");
    let vk = sk.verifying_key();

    let kid = "kid-1";
    let jwk = build_jwk_from_p256(kid, vk);

    // VDP is bytes containing an indefinite-length map (unsupported).
    let vdp = vec![0xbf, 0xff];
    let protected = encode_receipt_headers(kid, Some("issuer.example"), Some(2), true);
    let receipt = encode_receipt_with_vdp_value(&protected, Some(&vdp), b"sig");
    let res = verify_transparent_statement_receipt("mst", &jwk, &receipt, b"claims");
    assert!(!res.is_valid);
    assert_eq!(res.failures[0].error_code.as_deref(), Some("MST_VDP_PARSE_ERROR"));

    // VDP is bytes containing trailing bytes.
    let mut vdp2 = Vec::new();
    {
        let mut enc = minicbor::Encoder::new(&mut vdp2);
        enc.map(1).unwrap();
        enc.str("k").unwrap();
        enc.null().unwrap();
    }
    vdp2.push(0x00);
    let receipt2 = encode_receipt_with_vdp_value(&protected, Some(&vdp2), b"sig");
    let res2 = verify_transparent_statement_receipt("mst", &jwk, &receipt2, b"claims");
    assert!(!res2.is_valid);
    assert_eq!(res2.failures[0].error_code.as_deref(), Some("MST_VDP_PARSE_ERROR"));
}

#[test]
fn receipt_decode_unsupported_cbor_type_reports_parse_error() {
    let sk = p256::ecdsa::SigningKey::from_bytes(&[11u8; 32].into()).expect("sk");
    let vk = sk.verifying_key();

    let kid = "kid-1";
    let jwk = build_jwk_from_p256(kid, vk);
    let protected = encode_receipt_headers(kid, Some("issuer.example"), Some(2), true);

    // VDP bytes containing a map with float value (unsupported in our header decoder).
    let mut vdp = Vec::new();
    {
        let mut enc = minicbor::Encoder::new(&mut vdp);
        enc.map(1).unwrap();
        enc.str("k").unwrap();
        enc.f64(1.0).unwrap();
    }
    let receipt = encode_receipt_with_vdp_value(&protected, Some(&vdp), b"sig");
    let res = verify_transparent_statement_receipt("mst", &jwk, &receipt, b"claims");
    assert!(!res.is_valid);
    assert_eq!(res.failures[0].error_code.as_deref(), Some("MST_VDP_PARSE_ERROR"));

    // VDP bytes containing an indefinite-length array (unsupported).
    let vdp2 = vec![0x9f, 0xff];
    let receipt2 = encode_receipt_with_vdp_value(&protected, Some(&vdp2), b"sig");
    let res2 = verify_transparent_statement_receipt("mst", &jwk, &receipt2, b"claims");
    assert!(!res2.is_valid);
    assert_eq!(res2.failures[0].error_code.as_deref(), Some("MST_VDP_PARSE_ERROR"));
}

#[test]
fn receipt_verification_reports_inclusion_proof_errors() {
    let sk = p256::ecdsa::SigningKey::from_bytes(&[19u8; 32].into()).expect("sk");
    let vk = sk.verifying_key();
    let kid = "kid-1";
    let jwk = build_jwk_from_p256(kid, vk);
    let protected = encode_receipt_headers(kid, Some("issuer.example"), Some(2), true);

    // Missing -1 key.
    let mut vdp_missing = Vec::new();
    {
        let mut enc = minicbor::Encoder::new(&mut vdp_missing);
        enc.map(0).unwrap();
    }
    let receipt = encode_receipt_with_vdp_value(&protected, Some(&vdp_missing), b"sig");
    let res = verify_transparent_statement_receipt("mst", &jwk, &receipt, b"claims");
    assert!(!res.is_valid);
    assert_eq!(res.failures[0].error_code.as_deref(), Some("MST_INCLUSION_MISSING"));

    // -1 value is wrong type.
    let mut vdp_wrong_type = Vec::new();
    {
        let mut enc = minicbor::Encoder::new(&mut vdp_wrong_type);
        enc.map(1).unwrap();
        enc.i64(-1).unwrap();
        enc.i64(1).unwrap();
    }
    let receipt2 = encode_receipt_with_vdp_value(&protected, Some(&vdp_wrong_type), b"sig");
    let res2 = verify_transparent_statement_receipt("mst", &jwk, &receipt2, b"claims");
    assert!(!res2.is_valid);
    assert_eq!(res2.failures[0].error_code.as_deref(), Some("MST_INCLUSION_MISSING"));

    // -1 array is empty.
    let mut vdp_empty = Vec::new();
    {
        let mut enc = minicbor::Encoder::new(&mut vdp_empty);
        enc.map(1).unwrap();
        enc.i64(-1).unwrap();
        enc.array(0).unwrap();
    }
    let receipt3 = encode_receipt_with_vdp_value(&protected, Some(&vdp_empty), b"sig");
    let res3 = verify_transparent_statement_receipt("mst", &jwk, &receipt3, b"claims");
    assert!(!res3.is_valid);
    assert_eq!(res3.failures[0].error_code.as_deref(), Some("MST_INCLUSION_MISSING"));

    // -1 array has element of wrong type.
    let mut vdp_bad_el = Vec::new();
    {
        let mut enc = minicbor::Encoder::new(&mut vdp_bad_el);
        enc.map(1).unwrap();
        enc.i64(-1).unwrap();
        enc.array(1).unwrap();
        enc.i64(1).unwrap();
    }
    let receipt4 = encode_receipt_with_vdp_value(&protected, Some(&vdp_bad_el), b"sig");
    let res4 = verify_transparent_statement_receipt("mst", &jwk, &receipt4, b"claims");
    assert!(!res4.is_valid);
    assert_eq!(res4.failures[0].error_code.as_deref(), Some("MST_INCLUSION_PARSE_ERROR"));
}

#[test]
fn receipt_verification_leaf_value_wrong_type_reports_leaf_parse_error() {
    let sk = p256::ecdsa::SigningKey::from_bytes(&[55u8; 32].into()).expect("sk");
    let vk = sk.verifying_key();
    let kid = "kid-1";
    let jwk = build_jwk_from_p256(kid, vk);
    let protected = encode_receipt_headers(kid, Some("issuer.example"), Some(2), false);

    let mut inclusion_map = Vec::new();
    {
        let mut enc = minicbor::Encoder::new(&mut inclusion_map);
        enc.map(2).unwrap();
        enc.i64(1).unwrap();
        enc.i64(123).unwrap();
        enc.i64(2).unwrap();
        enc.array(0).unwrap();
    }

    let receipt = encode_receipt(&protected, &inclusion_map, b"sig");
    let res = verify_transparent_statement_receipt("mst", &jwk, &receipt, b"claims");
    assert!(!res.is_valid);
    assert_eq!(res.failures[0].error_code.as_deref(), Some("MST_LEAF_PARSE_ERROR"));
}

#[test]
fn receipt_verification_path_element_bool_wrong_type_reports_path_parse_error() {
    let sk = p256::ecdsa::SigningKey::from_bytes(&[56u8; 32].into()).expect("sk");
    let vk = sk.verifying_key();
    let kid = "kid-1";
    let jwk = build_jwk_from_p256(kid, vk);
    let protected = encode_receipt_headers(kid, Some("issuer.example"), Some(2), false);

    let tx_hash = sha256(b"tx");
    let data_hash = sha256(b"claims");
    let mut inclusion_map = Vec::new();
    {
        let mut enc = minicbor::Encoder::new(&mut inclusion_map);
        enc.map(2).unwrap();
        enc.i64(1).unwrap();
        enc.array(3).unwrap();
        enc.bytes(&tx_hash).unwrap();
        enc.str("evidence").unwrap();
        enc.bytes(&data_hash).unwrap();
        enc.i64(2).unwrap();
        enc.array(1).unwrap();
        enc.array(2).unwrap();
        enc.i64(1).unwrap(); // should be bool
        enc.bytes(b"h").unwrap();
    }

    let receipt = encode_receipt(&protected, &inclusion_map, b"sig");
    let res = verify_transparent_statement_receipt("mst", &jwk, &receipt, b"claims");
    assert!(!res.is_valid);
    assert_eq!(res.failures[0].error_code.as_deref(), Some("MST_PATH_PARSE_ERROR"));
}

#[test]
fn receipt_verification_reports_inclusion_map_and_leaf_path_errors() {
    let sk = p256::ecdsa::SigningKey::from_bytes(&[20u8; 32].into()).expect("sk");
    let vk = sk.verifying_key();
    let kid = "kid-1";
    let jwk = build_jwk_from_p256(kid, vk);
    let protected = encode_receipt_headers(kid, Some("issuer.example"), Some(2), false);

    let mut inclusion_map = encode_inclusion_map_with_path(b"claims", &[]);
    inclusion_map.push(0x00);
    let receipt = encode_receipt(&protected, &inclusion_map, b"sig");
    let res = verify_transparent_statement_receipt("mst", &jwk, &receipt, b"claims");
    assert!(!res.is_valid);
    assert_eq!(res.failures[0].error_code.as_deref(), Some("MST_INCLUSION_PARSE_ERROR"));

    let mut not_map = Vec::new();
    {
        let mut enc = minicbor::Encoder::new(&mut not_map);
        enc.array(0).unwrap();
    }
    let receipt2 = encode_receipt(&protected, &not_map, b"sig");
    let res2 = verify_transparent_statement_receipt("mst", &jwk, &receipt2, b"claims");
    assert!(!res2.is_valid);
    assert_eq!(res2.failures[0].error_code.as_deref(), Some("MST_INCLUSION_PARSE_ERROR"));

    let mut only_path = Vec::new();
    {
        let mut enc = minicbor::Encoder::new(&mut only_path);
        enc.map(1).unwrap();
        enc.i64(2).unwrap();
        enc.array(0).unwrap();
    }
    let receipt3 = encode_receipt(&protected, &only_path, b"sig");
    let res3 = verify_transparent_statement_receipt("mst", &jwk, &receipt3, b"claims");
    assert!(!res3.is_valid);
    assert_eq!(res3.failures[0].error_code.as_deref(), Some("MST_LEAF_MISSING"));

    let tx_hash = sha256(b"tx");
    let data_hash = sha256(b"claims");
    let mut only_leaf = Vec::new();
    {
        let mut enc = minicbor::Encoder::new(&mut only_leaf);
        enc.map(1).unwrap();
        enc.i64(1).unwrap();
        enc.array(3).unwrap();
        enc.bytes(&tx_hash).unwrap();
        enc.str("evidence").unwrap();
        enc.bytes(&data_hash).unwrap();
    }
    let receipt4 = encode_receipt(&protected, &only_leaf, b"sig");
    let res4 = verify_transparent_statement_receipt("mst", &jwk, &receipt4, b"claims");
    assert!(!res4.is_valid);
    assert_eq!(res4.failures[0].error_code.as_deref(), Some("MST_PATH_MISSING"));
}

#[test]
fn receipt_verification_leaf_and_path_parse_errors_cover_decoder_branches() {
    let sk = p256::ecdsa::SigningKey::from_bytes(&[21u8; 32].into()).expect("sk");
    let vk = sk.verifying_key();
    let kid = "kid-1";
    let jwk = build_jwk_from_p256(kid, vk);
    let protected = encode_receipt_headers(kid, Some("issuer.example"), Some(2), false);

    let mut bad_leaf0 = Vec::new();
    {
        let mut enc = minicbor::Encoder::new(&mut bad_leaf0);
        enc.map(2).unwrap();
        enc.i64(1).unwrap();
        enc.array(3).unwrap();
        enc.i64(1).unwrap();
        enc.str("evidence").unwrap();
        enc.bytes(&sha256(b"claims")).unwrap();
        enc.i64(2).unwrap();
        enc.array(0).unwrap();
    }
    let receipt = encode_receipt(&protected, &bad_leaf0, b"sig");
    let res = verify_transparent_statement_receipt("mst", &jwk, &receipt, b"claims");
    assert!(!res.is_valid);
    assert_eq!(res.failures[0].error_code.as_deref(), Some("MST_LEAF_PARSE_ERROR"));

    let tx_hash = sha256(b"tx");
    let data_hash = sha256(b"claims");
    let mut bad_path = Vec::new();
    {
        let mut enc = minicbor::Encoder::new(&mut bad_path);
        enc.map(2).unwrap();
        enc.i64(1).unwrap();
        enc.array(3).unwrap();
        enc.bytes(&tx_hash).unwrap();
        enc.str("evidence").unwrap();
        enc.bytes(&data_hash).unwrap();
        enc.i64(2).unwrap();
        enc.array(1).unwrap();
        enc.i64(1).unwrap();
    }
    let receipt2 = encode_receipt(&protected, &bad_path, b"sig");
    let res2 = verify_transparent_statement_receipt("mst", &jwk, &receipt2, b"claims");
    assert!(!res2.is_valid);
    assert_eq!(res2.failures[0].error_code.as_deref(), Some("MST_PATH_PARSE_ERROR"));
}

#[test]
fn receipt_verification_leaf_parse_error_variants_cover_more_lines() {
    let sk = p256::ecdsa::SigningKey::from_bytes(&[25u8; 32].into()).expect("sk");
    let vk = sk.verifying_key();
    let kid = "kid-1";
    let jwk = build_jwk_from_p256(kid, vk);
    let protected = encode_receipt_headers(kid, Some("issuer.example"), Some(2), false);

    let tx_hash = sha256(b"tx");
    let data_hash = sha256(b"claims");

    let mut leaf_not_array = Vec::new();
    {
        let mut enc = minicbor::Encoder::new(&mut leaf_not_array);
        enc.map(0).unwrap();
    }
    let mut inclusion1 = Vec::new();
    {
        let mut enc = minicbor::Encoder::new(&mut inclusion1);
        enc.map(2).unwrap();
        enc.i64(1).unwrap();
        enc.bytes(&leaf_not_array).unwrap();
        enc.i64(2).unwrap();
        enc.array(0).unwrap();
    }
    let receipt1 = encode_receipt(&protected, &inclusion1, b"sig");
    let res1 = verify_transparent_statement_receipt("mst", &jwk, &receipt1, b"claims");
    assert_eq!(res1.failures[0].error_code.as_deref(), Some("MST_LEAF_PARSE_ERROR"));

    let mut inclusion2 = Vec::new();
    {
        let mut enc = minicbor::Encoder::new(&mut inclusion2);
        enc.map(2).unwrap();
        enc.i64(1).unwrap();
        enc.array(2).unwrap();
        enc.bytes(&tx_hash).unwrap();
        enc.str("evidence").unwrap();
        enc.i64(2).unwrap();
        enc.array(0).unwrap();
    }
    let receipt2 = encode_receipt(&protected, &inclusion2, b"sig");
    let res2 = verify_transparent_statement_receipt("mst", &jwk, &receipt2, b"claims");
    assert_eq!(res2.failures[0].error_code.as_deref(), Some("MST_LEAF_PARSE_ERROR"));

    let mut inclusion3 = Vec::new();
    {
        let mut enc = minicbor::Encoder::new(&mut inclusion3);
        enc.map(2).unwrap();
        enc.i64(1).unwrap();
        enc.array(3).unwrap();
        enc.bytes(&tx_hash).unwrap();
        enc.i64(123).unwrap();
        enc.bytes(&data_hash).unwrap();
        enc.i64(2).unwrap();
        enc.array(0).unwrap();
    }
    let receipt3 = encode_receipt(&protected, &inclusion3, b"sig");
    let res3 = verify_transparent_statement_receipt("mst", &jwk, &receipt3, b"claims");
    assert_eq!(res3.failures[0].error_code.as_deref(), Some("MST_LEAF_PARSE_ERROR"));

    let mut inclusion4 = Vec::new();
    {
        let mut enc = minicbor::Encoder::new(&mut inclusion4);
        enc.map(2).unwrap();
        enc.i64(1).unwrap();
        enc.array(3).unwrap();
        enc.bytes(&tx_hash).unwrap();
        enc.str("evidence").unwrap();
        enc.str("not-bytes").unwrap();
        enc.i64(2).unwrap();
        enc.array(0).unwrap();
    }
    let receipt4 = encode_receipt(&protected, &inclusion4, b"sig");
    let res4 = verify_transparent_statement_receipt("mst", &jwk, &receipt4, b"claims");
    assert_eq!(res4.failures[0].error_code.as_deref(), Some("MST_LEAF_PARSE_ERROR"));
}

#[test]
fn receipt_verification_path_parse_error_variants_cover_more_lines() {
    let sk = p256::ecdsa::SigningKey::from_bytes(&[26u8; 32].into()).expect("sk");
    let vk = sk.verifying_key();
    let kid = "kid-1";
    let jwk = build_jwk_from_p256(kid, vk);
    let protected = encode_receipt_headers(kid, Some("issuer.example"), Some(2), false);

    let tx_hash = sha256(b"tx");
    let data_hash = sha256(b"claims");

    let mut bad_path_len = Vec::new();
    {
        let mut enc = minicbor::Encoder::new(&mut bad_path_len);
        enc.array(1).unwrap();
        enc.array(1).unwrap();
        enc.bool(true).unwrap();
    }
    let mut inclusion1 = Vec::new();
    {
        let mut enc = minicbor::Encoder::new(&mut inclusion1);
        enc.map(2).unwrap();
        enc.i64(1).unwrap();
        enc.array(3).unwrap();
        enc.bytes(&tx_hash).unwrap();
        enc.str("evidence").unwrap();
        enc.bytes(&data_hash).unwrap();
        enc.i64(2).unwrap();
        enc.bytes(&bad_path_len).unwrap();
    }
    let receipt1 = encode_receipt(&protected, &inclusion1, b"sig");
    let res1 = verify_transparent_statement_receipt("mst", &jwk, &receipt1, b"claims");
    assert_eq!(res1.failures[0].error_code.as_deref(), Some("MST_PATH_PARSE_ERROR"));

    let mut bad_path_bool = Vec::new();
    {
        let mut enc = minicbor::Encoder::new(&mut bad_path_bool);
        enc.array(1).unwrap();
        enc.array(2).unwrap();
        enc.i64(1).unwrap();
        enc.bytes(&sha256(b"h")).unwrap();
    }
    let mut inclusion2 = Vec::new();
    {
        let mut enc = minicbor::Encoder::new(&mut inclusion2);
        enc.map(2).unwrap();
        enc.i64(1).unwrap();
        enc.array(3).unwrap();
        enc.bytes(&tx_hash).unwrap();
        enc.str("evidence").unwrap();
        enc.bytes(&data_hash).unwrap();
        enc.i64(2).unwrap();
        enc.bytes(&bad_path_bool).unwrap();
    }
    let receipt2 = encode_receipt(&protected, &inclusion2, b"sig");
    let res2 = verify_transparent_statement_receipt("mst", &jwk, &receipt2, b"claims");
    assert_eq!(res2.failures[0].error_code.as_deref(), Some("MST_PATH_PARSE_ERROR"));

    let mut bad_path_hash = Vec::new();
    {
        let mut enc = minicbor::Encoder::new(&mut bad_path_hash);
        enc.array(1).unwrap();
        enc.array(2).unwrap();
        enc.bool(true).unwrap();
        enc.str("not-bytes").unwrap();
    }
    let mut inclusion3 = Vec::new();
    {
        let mut enc = minicbor::Encoder::new(&mut inclusion3);
        enc.map(2).unwrap();
        enc.i64(1).unwrap();
        enc.array(3).unwrap();
        enc.bytes(&tx_hash).unwrap();
        enc.str("evidence").unwrap();
        enc.bytes(&data_hash).unwrap();
        enc.i64(2).unwrap();
        enc.bytes(&bad_path_hash).unwrap();
    }
    let receipt3 = encode_receipt(&protected, &inclusion3, b"sig");
    let res3 = verify_transparent_statement_receipt("mst", &jwk, &receipt3, b"claims");
    assert_eq!(res3.failures[0].error_code.as_deref(), Some("MST_PATH_PARSE_ERROR"));
}
