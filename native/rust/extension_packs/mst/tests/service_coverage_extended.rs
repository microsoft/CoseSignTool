// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Extended test coverage for MST transparency provider service.rs paths.

use cbor_primitives::CborEncoder;
use cose_sign1_transparent_mst::signing::{
    MstTransparencyClient, MstTransparencyClientOptions, MstTransparencyProvider,
};
use cose_sign1_signing::transparency::TransparencyProvider;
use url::Url;

/// Create a valid COSE_Sign1 message with proper structure.
fn create_valid_cose_sign1(payload: &[u8]) -> Vec<u8> {
    let mut enc = cose_sign1_primitives::provider::encoder();
    enc.encode_array(4).unwrap();
    // Empty protected headers
    enc.encode_bstr(&[0xA0]).unwrap(); // empty map
    // Empty unprotected headers
    enc.encode_map(0).unwrap();
    // Payload
    enc.encode_bstr(payload).unwrap();
    // Signature
    enc.encode_bstr(&[0u8; 64]).unwrap();
    enc.into_bytes()
}

/// Create a COSE_Sign1 message with receipts header (394).
fn create_cose_sign1_with_receipts_header(
    payload: &[u8],
    receipt_bytes: &[u8],
) -> Vec<u8> {
    let mut enc = cose_sign1_primitives::provider::encoder();
    enc.encode_array(4).unwrap();
    // Empty protected headers
    enc.encode_bstr(&[0xA0]).unwrap();
    // Unprotected headers with receipts
    {
        enc.encode_map(1).unwrap();
        enc.encode_i64(394).unwrap(); // receipts header label
        enc.encode_array(1).unwrap(); // array with one receipt
        enc.encode_bstr(receipt_bytes).unwrap();
    }
    // Payload
    enc.encode_bstr(payload).unwrap();
    // Signature
    enc.encode_bstr(&[0u8; 64]).unwrap();
    enc.into_bytes()
}

#[test]
fn test_verify_transparency_proof_no_receipts() {
    let endpoint = Url::parse("https://example.com").unwrap();
    let options = MstTransparencyClientOptions::default();
    let client = MstTransparencyClient::new(endpoint, options);
    let provider = MstTransparencyProvider::new(client);

    // Create a valid COSE_Sign1 without receipts header
    let cose_bytes = create_valid_cose_sign1(b"test payload");

    let result = provider.verify_transparency_proof(&cose_bytes);
    assert!(result.is_ok());
    let validation_result = result.unwrap();
    assert!(!validation_result.is_valid);
    assert!(
        validation_result
            .errors
            .iter()
            .any(|e| e.contains("No MST receipts"))
    );
}

#[test]
fn test_verify_transparency_proof_invalid_receipt_bytes() {
    let endpoint = Url::parse("https://example.com").unwrap();
    let options = MstTransparencyClientOptions::default();
    let client = MstTransparencyClient::new(endpoint, options);
    let provider = MstTransparencyProvider::new(client);

    // Create COSE_Sign1 with invalid receipt bytes
    let invalid_receipt = vec![0xFF, 0xFF]; // Invalid CBOR
    let cose_bytes = create_cose_sign1_with_receipts_header(b"test payload", &invalid_receipt);

    let result = provider.verify_transparency_proof(&cose_bytes);
    assert!(result.is_ok());
    let validation_result = result.unwrap();
    // Should return failure since receipt is invalid
    assert!(!validation_result.is_valid);
    assert!(
        validation_result
            .errors
            .iter()
            .any(|e| e.contains("No valid MST receipts"))
    );
}

#[test]
fn test_verify_transparency_proof_empty_receipts_array() {
    let endpoint = Url::parse("https://example.com").unwrap();
    let options = MstTransparencyClientOptions::default();
    let client = MstTransparencyClient::new(endpoint, options);
    let provider = MstTransparencyProvider::new(client);

    // Create COSE_Sign1 with empty receipts array
    let mut enc = cose_sign1_primitives::provider::encoder();
    enc.encode_array(4).unwrap();
    enc.encode_bstr(&[0xA0]).unwrap();
    // Unprotected headers with empty receipts array
    {
        enc.encode_map(1).unwrap();
        enc.encode_i64(394).unwrap();
        enc.encode_array(0).unwrap(); // Empty array
    }
    enc.encode_bstr(b"payload").unwrap();
    enc.encode_bstr(&[0u8; 64]).unwrap();
    let cose_bytes = enc.into_bytes();

    let result = provider.verify_transparency_proof(&cose_bytes);
    assert!(result.is_ok());
    let validation_result = result.unwrap();
    assert!(!validation_result.is_valid);
}

#[test]
fn test_verify_transparency_proof_malformed_receipt_structure() {
    let endpoint = Url::parse("https://example.com").unwrap();
    let options = MstTransparencyClientOptions::default();
    let client = MstTransparencyClient::new(endpoint, options);
    let provider = MstTransparencyProvider::new(client);

    // Create a minimally valid COSE_Sign1 structure that will parse but fail receipt verification
    let mut receipt_enc = cose_sign1_primitives::provider::encoder();
    receipt_enc.encode_array(4).unwrap();
    receipt_enc.encode_bstr(&[]).unwrap(); // empty protected
    receipt_enc.encode_map(0).unwrap(); // empty unprotected
    receipt_enc.encode_null().unwrap(); // null payload
    receipt_enc.encode_bstr(&[]).unwrap(); // empty signature
    let receipt_bytes = receipt_enc.into_bytes();

    let cose_bytes = create_cose_sign1_with_receipts_header(b"test payload", &receipt_bytes);

    let result = provider.verify_transparency_proof(&cose_bytes);
    assert!(result.is_ok());
    let validation_result = result.unwrap();
    // Should fail because the receipt doesn't have the required MST headers
    assert!(!validation_result.is_valid);
}

#[test]
fn test_provider_name_constant() {
    let endpoint = Url::parse("https://example.com").unwrap();
    let options = MstTransparencyClientOptions::default();
    let client = MstTransparencyClient::new(endpoint, options);
    let provider = MstTransparencyProvider::new(client);

    // Verify provider name is constant
    let name1 = provider.provider_name();
    let name2 = provider.provider_name();
    assert_eq!(name1, name2);
    assert_eq!(name1, "Microsoft Signing Transparency");
}

#[test]
fn test_verify_transparency_proof_with_multiple_receipts() {
    let endpoint = Url::parse("https://example.com").unwrap();
    let options = MstTransparencyClientOptions::default();
    let client = MstTransparencyClient::new(endpoint, options);
    let provider = MstTransparencyProvider::new(client);

    // Create COSE_Sign1 with multiple receipt bytes
    let mut enc = cose_sign1_primitives::provider::encoder();
    enc.encode_array(4).unwrap();
    enc.encode_bstr(&[0xA0]).unwrap();
    // Unprotected headers with multiple receipts
    {
        enc.encode_map(1).unwrap();
        enc.encode_i64(394).unwrap();
        enc.encode_array(3).unwrap(); // Array with three receipts
        enc.encode_bstr(&[0xFF]).unwrap(); // Invalid receipt 1
        enc.encode_bstr(&[0xFE]).unwrap(); // Invalid receipt 2
        enc.encode_bstr(&[0xFD]).unwrap(); // Invalid receipt 3
    }
    enc.encode_bstr(b"payload").unwrap();
    enc.encode_bstr(&[0u8; 64]).unwrap();
    let cose_bytes = enc.into_bytes();

    let result = provider.verify_transparency_proof(&cose_bytes);
    assert!(result.is_ok());
    let validation_result = result.unwrap();
    // All receipts are invalid so it should fail
    assert!(!validation_result.is_valid);
}

#[test]
fn test_verify_transparency_proof_result_contains_provider_name() {
    let endpoint = Url::parse("https://example.com").unwrap();
    let options = MstTransparencyClientOptions::default();
    let client = MstTransparencyClient::new(endpoint, options);
    let provider = MstTransparencyProvider::new(client);

    let cose_bytes = create_valid_cose_sign1(b"test payload");

    let result = provider.verify_transparency_proof(&cose_bytes);
    assert!(result.is_ok());
    let validation_result = result.unwrap();
    assert_eq!(validation_result.provider_name, "Microsoft Signing Transparency");
}
