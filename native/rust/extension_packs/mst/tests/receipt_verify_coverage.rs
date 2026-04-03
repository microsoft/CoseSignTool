// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Test coverage for MST receipt verification functionality.

use cose_sign1_crypto_openssl::jwk_verifier::OpenSslJwkVerifierFactory;
use cose_sign1_transparent_mst::validation::receipt_verify::{
    verify_mst_receipt, ReceiptVerifyError, ReceiptVerifyInput, ReceiptVerifyOutput,
};

#[test]
fn test_verify_mst_receipt_invalid_cbor() {
    let factory = OpenSslJwkVerifierFactory;
    let input = ReceiptVerifyInput {
        statement_bytes_with_receipts: &[],
        receipt_bytes: &[0xFF, 0xFF], // Invalid CBOR
        offline_jwks_json: None,
        allow_network_fetch: false,
        jwks_api_version: None,
        client: None,
        jwk_verifier_factory: &factory,
    };

    let result = verify_mst_receipt(input);
    assert!(result.is_err());
    match result {
        Err(ReceiptVerifyError::ReceiptDecode(_)) => {
            // Expected error type
        }
        _ => panic!("Expected ReceiptDecode error, got: {:?}", result),
    }
}

#[test]
fn test_verify_mst_receipt_empty_bytes() {
    let factory = OpenSslJwkVerifierFactory;
    let input = ReceiptVerifyInput {
        statement_bytes_with_receipts: &[],
        receipt_bytes: &[], // Empty bytes
        offline_jwks_json: None,
        allow_network_fetch: false,
        jwks_api_version: None,
        client: None,
        jwk_verifier_factory: &factory,
    };

    let result = verify_mst_receipt(input);
    assert!(result.is_err());
    match result {
        Err(ReceiptVerifyError::ReceiptDecode(_)) => {
            // Expected error type
        }
        _ => panic!("Expected ReceiptDecode error, got: {:?}", result),
    }
}

#[test]
fn test_receipt_verify_error_display_receipt_decode() {
    let error = ReceiptVerifyError::ReceiptDecode("invalid format".to_string());
    let display = format!("{}", error);
    assert_eq!(display, "receipt_decode_failed: invalid format");
}

#[test]
fn test_receipt_verify_error_display_missing_alg() {
    let error = ReceiptVerifyError::MissingAlg;
    let display = format!("{}", error);
    assert_eq!(display, "receipt_missing_alg");
}

#[test]
fn test_receipt_verify_error_display_missing_kid() {
    let error = ReceiptVerifyError::MissingKid;
    let display = format!("{}", error);
    assert_eq!(display, "receipt_missing_kid");
}

#[test]
fn test_receipt_verify_error_display_unsupported_alg() {
    let error = ReceiptVerifyError::UnsupportedAlg(-999);
    let display = format!("{}", error);
    assert_eq!(display, "unsupported_alg: -999");
}

#[test]
fn test_receipt_verify_error_display_unsupported_vds() {
    let error = ReceiptVerifyError::UnsupportedVds(5);
    let display = format!("{}", error);
    assert_eq!(display, "unsupported_vds: 5");
}

#[test]
fn test_receipt_verify_error_display_missing_vdp() {
    let error = ReceiptVerifyError::MissingVdp;
    let display = format!("{}", error);
    assert_eq!(display, "missing_vdp");
}

#[test]
fn test_receipt_verify_error_display_missing_proof() {
    let error = ReceiptVerifyError::MissingProof;
    let display = format!("{}", error);
    assert_eq!(display, "missing_proof");
}

#[test]
fn test_receipt_verify_error_display_missing_issuer() {
    let error = ReceiptVerifyError::MissingIssuer;
    let display = format!("{}", error);
    assert_eq!(display, "issuer_missing");
}

#[test]
fn test_receipt_verify_error_display_jwks_parse() {
    let error = ReceiptVerifyError::JwksParse("malformed json".to_string());
    let display = format!("{}", error);
    assert_eq!(display, "jwks_parse_failed: malformed json");
}

#[test]
fn test_receipt_verify_error_display_jwks_fetch() {
    let error = ReceiptVerifyError::JwksFetch("network error".to_string());
    let display = format!("{}", error);
    assert_eq!(display, "jwks_fetch_failed: network error");
}

#[test]
fn test_receipt_verify_error_display_jwk_not_found() {
    let error = ReceiptVerifyError::JwkNotFound("key123".to_string());
    let display = format!("{}", error);
    assert_eq!(display, "jwk_not_found_for_kid: key123");
}

#[test]
fn test_receipt_verify_error_display_jwk_unsupported() {
    let error = ReceiptVerifyError::JwkUnsupported("unsupported curve".to_string());
    let display = format!("{}", error);
    assert_eq!(display, "jwk_unsupported: unsupported curve");
}

#[test]
fn test_receipt_verify_error_display_statement_reencode() {
    let error = ReceiptVerifyError::StatementReencode("encoding failed".to_string());
    let display = format!("{}", error);
    assert_eq!(display, "statement_reencode_failed: encoding failed");
}

#[test]
fn test_receipt_verify_error_display_sig_structure_encode() {
    let error = ReceiptVerifyError::SigStructureEncode("structure error".to_string());
    let display = format!("{}", error);
    assert_eq!(display, "sig_structure_encode_failed: structure error");
}

#[test]
fn test_receipt_verify_error_display_data_hash_mismatch() {
    let error = ReceiptVerifyError::DataHashMismatch;
    let display = format!("{}", error);
    assert_eq!(display, "data_hash_mismatch");
}

#[test]
fn test_receipt_verify_error_display_signature_invalid() {
    let error = ReceiptVerifyError::SignatureInvalid;
    let display = format!("{}", error);
    assert_eq!(display, "signature_invalid");
}

#[test]
fn test_receipt_verify_error_is_error() {
    let error = ReceiptVerifyError::MissingAlg;
    // Test that it implements std::error::Error
    let _: &dyn std::error::Error = &error;
}

#[test]
fn test_receipt_verify_input_construction() {
    let statement_bytes = b"test_statement";
    let receipt_bytes = b"test_receipt";
    let jwks_json = r#"{"keys": []}"#;
    let factory = OpenSslJwkVerifierFactory;

    let input = ReceiptVerifyInput {
        statement_bytes_with_receipts: statement_bytes,
        receipt_bytes: receipt_bytes,
        offline_jwks_json: Some(jwks_json),
        allow_network_fetch: true,
        jwks_api_version: Some("2023-01-01"),
        client: None,
        jwk_verifier_factory: &factory,
    };

    // Just verify the struct can be constructed and accessed
    assert_eq!(input.statement_bytes_with_receipts, statement_bytes);
    assert_eq!(input.receipt_bytes, receipt_bytes);
    assert_eq!(input.offline_jwks_json, Some(jwks_json));
    assert_eq!(input.allow_network_fetch, true);
    assert_eq!(input.jwks_api_version, Some("2023-01-01"));
}

#[test]
fn test_receipt_verify_output_construction() {
    let output = ReceiptVerifyOutput {
        trusted: true,
        details: Some("verification successful".to_string()),
        issuer: "example.com".to_string(),
        kid: "key123".to_string(),
        statement_sha256: [0u8; 32],
    };

    assert_eq!(output.trusted, true);
    assert_eq!(output.details, Some("verification successful".to_string()));
    assert_eq!(output.issuer, "example.com");
    assert_eq!(output.kid, "key123");
    assert_eq!(output.statement_sha256, [0u8; 32]);
}

// Test base64url decode functionality indirectly by testing invalid receipt formats
#[test]
fn test_verify_mst_receipt_malformed_cbor_map() {
    // Create a minimal valid CBOR that will pass initial parsing but fail later
    let mut cbor_bytes = Vec::new();

    // CBOR array with 4 elements (COSE_Sign1 format)
    cbor_bytes.push(0x84); // array(4)
    cbor_bytes.push(0x40); // empty bstr (protected headers)
    cbor_bytes.push(0xA0); // empty map (unprotected headers)
    cbor_bytes.push(0xF6); // null (payload)
    cbor_bytes.push(0x40); // empty bstr (signature)

    let factory = OpenSslJwkVerifierFactory;
    let input = ReceiptVerifyInput {
        statement_bytes_with_receipts: &cbor_bytes,
        receipt_bytes: &cbor_bytes,
        offline_jwks_json: None,
        allow_network_fetch: false,
        jwks_api_version: None,
        client: None,
        jwk_verifier_factory: &factory,
    };

    let result = verify_mst_receipt(input);
    // This will fail due to missing required headers, which exercises error paths
    assert!(result.is_err());
}
