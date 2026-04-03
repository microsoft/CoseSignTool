// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Test coverage for MST receipt verification error paths via public API.

use cbor_primitives::CborEncoder;
use cose_sign1_crypto_openssl::jwk_verifier::OpenSslJwkVerifierFactory;
use cose_sign1_transparent_mst::validation::receipt_verify::{
    verify_mst_receipt, ReceiptVerifyError, ReceiptVerifyInput,
};

#[test]
fn test_verify_receipt_wrong_vds() {
    // Create a receipt with wrong VDS value
    let mut enc = cose_sign1_primitives::provider::encoder();
    enc.encode_array(4).unwrap();

    // Protected headers with wrong VDS
    {
        let mut prot_enc = cose_sign1_primitives::provider::encoder();
        prot_enc.encode_map(4).unwrap();
        prot_enc.encode_i64(1).unwrap(); // alg
        prot_enc.encode_i64(-7).unwrap(); // ES256
        prot_enc.encode_i64(4).unwrap(); // kid
        prot_enc.encode_bstr(b"test-key").unwrap();
        prot_enc.encode_i64(395).unwrap(); // VDS label
        prot_enc.encode_i64(999).unwrap(); // Wrong VDS value (should be 2)
        prot_enc.encode_i64(15).unwrap(); // CWT claims
        {
            let mut cwt_enc = cose_sign1_primitives::provider::encoder();
            cwt_enc.encode_map(1).unwrap();
            cwt_enc.encode_i64(1).unwrap(); // issuer label
            cwt_enc.encode_tstr("example.com").unwrap();
            prot_enc.encode_raw(&cwt_enc.into_bytes()).unwrap();
        }
        enc.encode_bstr(&prot_enc.into_bytes()).unwrap();
    }

    enc.encode_map(0).unwrap(); // empty unprotected
    enc.encode_bstr(b"payload").unwrap();
    enc.encode_bstr(&[0u8; 64]).unwrap(); // signature

    let receipt_bytes = enc.into_bytes();

    let factory = OpenSslJwkVerifierFactory;
    let input = ReceiptVerifyInput {
        statement_bytes_with_receipts: &[],
        receipt_bytes: &receipt_bytes,
        offline_jwks_json: None,
        allow_network_fetch: false,
        jwks_api_version: None,
        client: None,
        jwk_verifier_factory: &factory,
    };

    let result = verify_mst_receipt(input);
    assert!(result.is_err());
    match result {
        Err(ReceiptVerifyError::UnsupportedVds(999)) => {}
        _ => panic!("Expected UnsupportedVds(999), got: {:?}", result),
    }
}

#[test]
fn test_verify_receipt_unsupported_alg() {
    // Create receipt with unsupported algorithm
    let mut enc = cose_sign1_primitives::provider::encoder();
    enc.encode_array(4).unwrap();

    // Protected headers with unsupported algorithm
    {
        let mut prot_enc = cose_sign1_primitives::provider::encoder();
        prot_enc.encode_map(4).unwrap();
        prot_enc.encode_i64(1).unwrap(); // alg
        prot_enc.encode_i64(-999).unwrap(); // Unsupported algorithm
        prot_enc.encode_i64(4).unwrap(); // kid
        prot_enc.encode_bstr(b"test-key").unwrap();
        prot_enc.encode_i64(395).unwrap(); // VDS
        prot_enc.encode_i64(2).unwrap(); // Correct VDS value
        prot_enc.encode_i64(15).unwrap(); // CWT claims
        {
            let mut cwt_enc = cose_sign1_primitives::provider::encoder();
            cwt_enc.encode_map(1).unwrap();
            cwt_enc.encode_i64(1).unwrap();
            cwt_enc.encode_tstr("example.com").unwrap();
            prot_enc.encode_raw(&cwt_enc.into_bytes()).unwrap();
        }
        enc.encode_bstr(&prot_enc.into_bytes()).unwrap();
    }

    enc.encode_map(0).unwrap();
    enc.encode_bstr(b"payload").unwrap();
    enc.encode_bstr(&[0u8; 64]).unwrap();

    let receipt_bytes = enc.into_bytes();

    let factory = OpenSslJwkVerifierFactory;
    let input = ReceiptVerifyInput {
        statement_bytes_with_receipts: &[],
        receipt_bytes: &receipt_bytes,
        offline_jwks_json: None,
        allow_network_fetch: false,
        jwks_api_version: None,
        client: None,
        jwk_verifier_factory: &factory,
    };

    let result = verify_mst_receipt(input);
    assert!(result.is_err());
    match result {
        Err(ReceiptVerifyError::UnsupportedAlg(-999)) => {}
        _ => panic!("Expected UnsupportedAlg(-999), got: {:?}", result),
    }
}

#[test]
fn test_verify_receipt_missing_alg() {
    // Create receipt without algorithm header
    let mut enc = cose_sign1_primitives::provider::encoder();
    enc.encode_array(4).unwrap();
    enc.encode_bstr(&[]).unwrap(); // empty protected headers
    enc.encode_map(0).unwrap(); // empty unprotected headers
    enc.encode_bstr(b"payload").unwrap();
    enc.encode_bstr(&[0u8; 64]).unwrap();

    let receipt_bytes = enc.into_bytes();

    let factory = OpenSslJwkVerifierFactory;
    let input = ReceiptVerifyInput {
        statement_bytes_with_receipts: &[],
        receipt_bytes: &receipt_bytes,
        offline_jwks_json: None,
        allow_network_fetch: false,
        jwks_api_version: None,
        client: None,
        jwk_verifier_factory: &factory,
    };

    let result = verify_mst_receipt(input);
    assert!(result.is_err());
    match result {
        Err(ReceiptVerifyError::MissingAlg) => {}
        _ => panic!("Expected MissingAlg, got: {:?}", result),
    }
}

#[test]
fn test_verify_receipt_missing_kid() {
    // Create receipt without kid header
    let mut enc = cose_sign1_primitives::provider::encoder();
    enc.encode_array(4).unwrap();

    // Protected headers with alg but no kid
    {
        let mut prot_enc = cose_sign1_primitives::provider::encoder();
        prot_enc.encode_map(1).unwrap();
        prot_enc.encode_i64(1).unwrap(); // alg
        prot_enc.encode_i64(-7).unwrap(); // ES256
        enc.encode_bstr(&prot_enc.into_bytes()).unwrap();
    }

    enc.encode_map(0).unwrap(); // empty unprotected
    enc.encode_bstr(b"payload").unwrap();
    enc.encode_bstr(&[0u8; 64]).unwrap();

    let receipt_bytes = enc.into_bytes();

    let factory = OpenSslJwkVerifierFactory;
    let input = ReceiptVerifyInput {
        statement_bytes_with_receipts: &[],
        receipt_bytes: &receipt_bytes,
        offline_jwks_json: None,
        allow_network_fetch: false,
        jwks_api_version: None,
        client: None,
        jwk_verifier_factory: &factory,
    };

    let result = verify_mst_receipt(input);
    assert!(result.is_err());
    match result {
        Err(ReceiptVerifyError::MissingKid) => {}
        _ => panic!("Expected MissingKid, got: {:?}", result),
    }
}

#[test]
fn test_verify_receipt_missing_issuer() {
    // Create receipt without issuer in CWT claims
    let mut enc = cose_sign1_primitives::provider::encoder();
    enc.encode_array(4).unwrap();

    // Protected headers without CWT claims
    {
        let mut prot_enc = cose_sign1_primitives::provider::encoder();
        prot_enc.encode_map(3).unwrap();
        prot_enc.encode_i64(1).unwrap(); // alg
        prot_enc.encode_i64(-7).unwrap();
        prot_enc.encode_i64(4).unwrap(); // kid
        prot_enc.encode_bstr(b"test-key").unwrap();
        prot_enc.encode_i64(395).unwrap(); // VDS
        prot_enc.encode_i64(2).unwrap();
        enc.encode_bstr(&prot_enc.into_bytes()).unwrap();
    }

    enc.encode_map(0).unwrap();
    enc.encode_bstr(b"payload").unwrap();
    enc.encode_bstr(&[0u8; 64]).unwrap();

    let receipt_bytes = enc.into_bytes();

    let factory = OpenSslJwkVerifierFactory;
    let input = ReceiptVerifyInput {
        statement_bytes_with_receipts: &[],
        receipt_bytes: &receipt_bytes,
        offline_jwks_json: None,
        allow_network_fetch: false,
        jwks_api_version: None,
        client: None,
        jwk_verifier_factory: &factory,
    };

    let result = verify_mst_receipt(input);
    assert!(result.is_err());
    match result {
        Err(ReceiptVerifyError::MissingIssuer) => {}
        _ => panic!("Expected MissingIssuer, got: {:?}", result),
    }
}

#[test]
fn test_verify_receipt_missing_vds() {
    // Create receipt without VDS header
    let mut enc = cose_sign1_primitives::provider::encoder();
    enc.encode_array(4).unwrap();

    // Protected headers without VDS
    {
        let mut prot_enc = cose_sign1_primitives::provider::encoder();
        prot_enc.encode_map(3).unwrap();
        prot_enc.encode_i64(1).unwrap(); // alg
        prot_enc.encode_i64(-7).unwrap();
        prot_enc.encode_i64(4).unwrap(); // kid
        prot_enc.encode_bstr(b"test-key").unwrap();
        prot_enc.encode_i64(15).unwrap(); // CWT claims
        {
            let mut cwt_enc = cose_sign1_primitives::provider::encoder();
            cwt_enc.encode_map(1).unwrap();
            cwt_enc.encode_i64(1).unwrap();
            cwt_enc.encode_tstr("example.com").unwrap();
            prot_enc.encode_raw(&cwt_enc.into_bytes()).unwrap();
        }
        enc.encode_bstr(&prot_enc.into_bytes()).unwrap();
    }

    enc.encode_map(0).unwrap();
    enc.encode_bstr(b"payload").unwrap();
    enc.encode_bstr(&[0u8; 64]).unwrap();

    let receipt_bytes = enc.into_bytes();

    let factory = OpenSslJwkVerifierFactory;
    let input = ReceiptVerifyInput {
        statement_bytes_with_receipts: &[],
        receipt_bytes: &receipt_bytes,
        offline_jwks_json: None,
        allow_network_fetch: false,
        jwks_api_version: None,
        client: None,
        jwk_verifier_factory: &factory,
    };

    let result = verify_mst_receipt(input);
    assert!(result.is_err());
    match result {
        Err(ReceiptVerifyError::UnsupportedVds(-1)) => {} // Default value when missing
        _ => panic!("Expected UnsupportedVds(-1), got: {:?}", result),
    }
}

#[test]
fn test_verify_receipt_invalid_cbor() {
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
        Err(ReceiptVerifyError::ReceiptDecode(_)) => {}
        _ => panic!("Expected ReceiptDecode error, got: {:?}", result),
    }
}

#[test]
fn test_verify_receipt_empty_bytes() {
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
        Err(ReceiptVerifyError::ReceiptDecode(_)) => {}
        _ => panic!("Expected ReceiptDecode error, got: {:?}", result),
    }
}

#[test]
fn test_verify_receipt_no_offline_jwks_no_network() {
    // Create a valid receipt structure that will get to key resolution
    let mut enc = cose_sign1_primitives::provider::encoder();
    enc.encode_array(4).unwrap();

    // Complete protected headers
    {
        let mut prot_enc = cose_sign1_primitives::provider::encoder();
        prot_enc.encode_map(4).unwrap();
        prot_enc.encode_i64(1).unwrap(); // alg
        prot_enc.encode_i64(-7).unwrap(); // ES256
        prot_enc.encode_i64(4).unwrap(); // kid
        prot_enc.encode_bstr(b"test-key").unwrap();
        prot_enc.encode_i64(395).unwrap(); // VDS
        prot_enc.encode_i64(2).unwrap();
        prot_enc.encode_i64(15).unwrap(); // CWT claims
        {
            let mut cwt_enc = cose_sign1_primitives::provider::encoder();
            cwt_enc.encode_map(1).unwrap();
            cwt_enc.encode_i64(1).unwrap();
            cwt_enc.encode_tstr("example.com").unwrap();
            prot_enc.encode_raw(&cwt_enc.into_bytes()).unwrap();
        }
        enc.encode_bstr(&prot_enc.into_bytes()).unwrap();
    }

    enc.encode_map(0).unwrap(); // empty unprotected
    enc.encode_bstr(b"payload").unwrap();
    enc.encode_bstr(&[0u8; 64]).unwrap();

    let receipt_bytes = enc.into_bytes();

    let factory = OpenSslJwkVerifierFactory;
    let input = ReceiptVerifyInput {
        statement_bytes_with_receipts: &[],
        receipt_bytes: &receipt_bytes,
        offline_jwks_json: None,    // no offline JWKS
        allow_network_fetch: false, // no network fetch
        jwks_api_version: None,
        client: None,
        jwk_verifier_factory: &factory,
    };

    let result = verify_mst_receipt(input);
    assert!(result.is_err());
    match result {
        Err(ReceiptVerifyError::JwksParse(msg)) => {
            assert!(msg.contains("MissingOfflineJwks"));
        }
        _ => panic!("Expected JwksParse error, got: {:?}", result),
    }
}

#[test]
fn test_verify_receipt_jwk_not_found() {
    // Create a receipt that will make it to key resolution
    let mut enc = cose_sign1_primitives::provider::encoder();
    enc.encode_array(4).unwrap();

    {
        let mut prot_enc = cose_sign1_primitives::provider::encoder();
        prot_enc.encode_map(4).unwrap();
        prot_enc.encode_i64(1).unwrap(); // alg
        prot_enc.encode_i64(-7).unwrap(); // ES256
        prot_enc.encode_i64(4).unwrap(); // kid
        prot_enc.encode_bstr(b"missing-key").unwrap(); // Key that won't be found
        prot_enc.encode_i64(395).unwrap(); // VDS
        prot_enc.encode_i64(2).unwrap();
        prot_enc.encode_i64(15).unwrap(); // CWT claims
        {
            let mut cwt_enc = cose_sign1_primitives::provider::encoder();
            cwt_enc.encode_map(1).unwrap();
            cwt_enc.encode_i64(1).unwrap();
            cwt_enc.encode_tstr("example.com").unwrap();
            prot_enc.encode_raw(&cwt_enc.into_bytes()).unwrap();
        }
        enc.encode_bstr(&prot_enc.into_bytes()).unwrap();
    }

    enc.encode_map(0).unwrap();
    enc.encode_bstr(b"payload").unwrap();
    enc.encode_bstr(&[0u8; 64]).unwrap();

    let receipt_bytes = enc.into_bytes();

    // JWKS with different key
    let jwks_json = r#"{
        "keys": [
            {
                "kty": "EC",
                "crv": "P-256",
                "kid": "different-key",
                "x": "test",
                "y": "test"
            }
        ]
    }"#;

    let factory = OpenSslJwkVerifierFactory;
    let input = ReceiptVerifyInput {
        statement_bytes_with_receipts: &[],
        receipt_bytes: &receipt_bytes,
        offline_jwks_json: Some(jwks_json),
        allow_network_fetch: false, // no network fallback
        jwks_api_version: None,
        client: None,
        jwk_verifier_factory: &factory,
    };

    let result = verify_mst_receipt(input);
    assert!(result.is_err());
    // Should fail due to key not found + no network fallback
    match result {
        Err(ReceiptVerifyError::JwksParse(msg)) => {
            assert!(msg.contains("MissingOfflineJwks"));
        }
        _ => panic!("Expected JwksParse error, got: {:?}", result),
    }
}

// Integration tests that exercise helper functions indirectly

#[test]
fn test_verify_receipt_invalid_statement_bytes() {
    // Test the reencode path with invalid statement bytes in the input
    let mut enc = cose_sign1_primitives::provider::encoder();
    enc.encode_array(4).unwrap();

    {
        let mut prot_enc = cose_sign1_primitives::provider::encoder();
        prot_enc.encode_map(4).unwrap();
        prot_enc.encode_i64(1).unwrap(); // alg
        prot_enc.encode_i64(-7).unwrap(); // ES256
        prot_enc.encode_i64(4).unwrap(); // kid
        prot_enc.encode_bstr(b"test-key").unwrap();
        prot_enc.encode_i64(395).unwrap(); // VDS
        prot_enc.encode_i64(2).unwrap();
        prot_enc.encode_i64(15).unwrap(); // CWT claims
        {
            let mut cwt_enc = cose_sign1_primitives::provider::encoder();
            cwt_enc.encode_map(1).unwrap();
            cwt_enc.encode_i64(1).unwrap();
            cwt_enc.encode_tstr("example.com").unwrap();
            prot_enc.encode_raw(&cwt_enc.into_bytes()).unwrap();
        }
        enc.encode_bstr(&prot_enc.into_bytes()).unwrap();
    }

    enc.encode_map(0).unwrap();
    enc.encode_bstr(b"payload").unwrap();
    enc.encode_bstr(&[0u8; 64]).unwrap();

    let receipt_bytes = enc.into_bytes();

    // Provide invalid statement bytes that will fail the reencode step
    let invalid_statement = vec![0xFF, 0xFF]; // Invalid CBOR

    let factory = OpenSslJwkVerifierFactory;
    let input = ReceiptVerifyInput {
        statement_bytes_with_receipts: &invalid_statement,
        receipt_bytes: &receipt_bytes,
        offline_jwks_json: Some(r#"{"keys":[]}"#),
        allow_network_fetch: false,
        jwks_api_version: None,
        client: None,
        jwk_verifier_factory: &factory,
    };

    let result = verify_mst_receipt(input);
    assert!(result.is_err());
    // This should trigger the StatementReencode error path
}

#[test]
fn test_verify_receipt_es384_algorithm() {
    // Test ES384 algorithm path
    let mut enc = cose_sign1_primitives::provider::encoder();
    enc.encode_array(4).unwrap();

    {
        let mut prot_enc = cose_sign1_primitives::provider::encoder();
        prot_enc.encode_map(4).unwrap();
        prot_enc.encode_i64(1).unwrap(); // alg
        prot_enc.encode_i64(-35).unwrap(); // ES384 instead of ES256
        prot_enc.encode_i64(4).unwrap(); // kid
        prot_enc.encode_bstr(b"test-key").unwrap();
        prot_enc.encode_i64(395).unwrap(); // VDS
        prot_enc.encode_i64(2).unwrap();
        prot_enc.encode_i64(15).unwrap(); // CWT claims
        {
            let mut cwt_enc = cose_sign1_primitives::provider::encoder();
            cwt_enc.encode_map(1).unwrap();
            cwt_enc.encode_i64(1).unwrap();
            cwt_enc.encode_tstr("example.com").unwrap();
            prot_enc.encode_raw(&cwt_enc.into_bytes()).unwrap();
        }
        enc.encode_bstr(&prot_enc.into_bytes()).unwrap();
    }

    enc.encode_map(0).unwrap();
    enc.encode_bstr(b"payload").unwrap();
    enc.encode_bstr(&[0u8; 64]).unwrap();

    let receipt_bytes = enc.into_bytes();

    let factory = OpenSslJwkVerifierFactory;
    let input = ReceiptVerifyInput {
        statement_bytes_with_receipts: &[],
        receipt_bytes: &receipt_bytes,
        offline_jwks_json: Some(r#"{"keys":[]}"#),
        allow_network_fetch: false,
        jwks_api_version: None,
        client: None,
        jwk_verifier_factory: &factory,
    };

    let result = verify_mst_receipt(input);
    assert!(result.is_err());
    // This exercises the ES384 path in validate_cose_alg_supported
}

#[test]
fn test_verify_receipt_with_vdp_header() {
    // Test VDP header parsing path
    let mut enc = cose_sign1_primitives::provider::encoder();
    enc.encode_array(4).unwrap();

    {
        let mut prot_enc = cose_sign1_primitives::provider::encoder();
        prot_enc.encode_map(4).unwrap();
        prot_enc.encode_i64(1).unwrap(); // alg
        prot_enc.encode_i64(-7).unwrap(); // ES256
        prot_enc.encode_i64(4).unwrap(); // kid
        prot_enc.encode_bstr(b"test-key").unwrap();
        prot_enc.encode_i64(395).unwrap(); // VDS
        prot_enc.encode_i64(2).unwrap();
        prot_enc.encode_i64(15).unwrap(); // CWT claims
        {
            let mut cwt_enc = cose_sign1_primitives::provider::encoder();
            cwt_enc.encode_map(1).unwrap();
            cwt_enc.encode_i64(1).unwrap();
            cwt_enc.encode_tstr("example.com").unwrap();
            prot_enc.encode_raw(&cwt_enc.into_bytes()).unwrap();
        }
        enc.encode_bstr(&prot_enc.into_bytes()).unwrap();
    }

    // Add VDP header (unprotected header label 396)
    {
        let mut unprot_enc = cose_sign1_primitives::provider::encoder();
        unprot_enc.encode_map(1).unwrap();
        unprot_enc.encode_i64(396).unwrap(); // VDP header label
                                             // Create array of proof blobs
        {
            let mut vdp_enc = cose_sign1_primitives::provider::encoder();
            vdp_enc.encode_array(1).unwrap(); // Array with one proof blob
            vdp_enc.encode_bstr(&[0x01, 0x02, 0x03, 0x04]).unwrap(); // Dummy proof blob
            unprot_enc.encode_raw(&vdp_enc.into_bytes()).unwrap();
        }
        enc.encode_raw(&unprot_enc.into_bytes()).unwrap();
    }

    enc.encode_bstr(b"payload").unwrap();
    enc.encode_bstr(&[0u8; 64]).unwrap();

    let receipt_bytes = enc.into_bytes();

    let factory = OpenSslJwkVerifierFactory;
    let input = ReceiptVerifyInput {
        statement_bytes_with_receipts: &[],
        receipt_bytes: &receipt_bytes,
        offline_jwks_json: Some(r#"{"keys":[]}"#),
        allow_network_fetch: false,
        jwks_api_version: None,
        client: None,
        jwk_verifier_factory: &factory,
    };

    let result = verify_mst_receipt(input);
    assert!(result.is_err());
    // This exercises extract_proof_blobs and related parsing paths
}

#[test]
fn test_verify_receipt_missing_cwt_issuer() {
    // Test get_cwt_issuer_host path with missing issuer
    let mut enc = cose_sign1_primitives::provider::encoder();
    enc.encode_array(4).unwrap();

    {
        let mut prot_enc = cose_sign1_primitives::provider::encoder();
        prot_enc.encode_map(3).unwrap();
        prot_enc.encode_i64(1).unwrap(); // alg
        prot_enc.encode_i64(-7).unwrap(); // ES256
        prot_enc.encode_i64(4).unwrap(); // kid
        prot_enc.encode_bstr(b"test-key").unwrap();
        prot_enc.encode_i64(395).unwrap(); // VDS
        prot_enc.encode_i64(2).unwrap();
        // CWT claims without issuer
        prot_enc.encode_i64(15).unwrap(); // CWT claims
        {
            let mut cwt_enc = cose_sign1_primitives::provider::encoder();
            cwt_enc.encode_map(1).unwrap();
            cwt_enc.encode_i64(2).unwrap(); // some other claim (not issuer)
            cwt_enc.encode_tstr("other-value").unwrap();
            prot_enc.encode_raw(&cwt_enc.into_bytes()).unwrap();
        }
        enc.encode_bstr(&prot_enc.into_bytes()).unwrap();
    }

    enc.encode_map(0).unwrap();
    enc.encode_bstr(b"payload").unwrap();
    enc.encode_bstr(&[0u8; 64]).unwrap();

    let receipt_bytes = enc.into_bytes();

    let factory = OpenSslJwkVerifierFactory;
    let input = ReceiptVerifyInput {
        statement_bytes_with_receipts: &[],
        receipt_bytes: &receipt_bytes,
        offline_jwks_json: Some(r#"{"keys":[]}"#),
        allow_network_fetch: false,
        jwks_api_version: None,
        client: None,
        jwk_verifier_factory: &factory,
    };

    let result = verify_mst_receipt(input);
    assert!(result.is_err());
    match result {
        Err(ReceiptVerifyError::MissingIssuer) => {}
        _ => panic!("Expected MissingIssuer error, got: {:?}", result),
    }
}
