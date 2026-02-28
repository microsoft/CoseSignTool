// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Tests for CertificateHeaderContributor.

use cbor_primitives::CborDecoder;
use cose_sign1_primitives::{CoseHeaderMap, CoseHeaderLabel, CoseHeaderValue};
use cose_sign1_signing::{HeaderContributor, HeaderContributorContext, HeaderMergeStrategy, SigningContext};

use cose_sign1_certificates::signing::certificate_header_contributor::CertificateHeaderContributor;
use cose_sign1_certificates::error::CertificateError;

fn create_mock_cert() -> Vec<u8> {
    // Simple mock DER certificate
    vec![
        0x30, 0x82, 0x01, 0x23, // SEQUENCE
        0x30, 0x82, 0x01, 0x00, // tbsCertificate SEQUENCE  
        0x01, 0x02, 0x03, 0x04, 0x05, // Mock certificate content
    ]
}

fn create_mock_chain() -> Vec<Vec<u8>> {
    vec![
        create_mock_cert(), // Leaf cert (must match signing cert)
        vec![0x30, 0x11, 0x22, 0x33, 0x44], // Intermediate cert
        vec![0x30, 0x55, 0x66, 0x77, 0x88], // Root cert
    ]
}

#[test]
fn test_new_with_matching_chain() {
    let cert = create_mock_cert();
    let chain = create_mock_chain();
    let chain_refs: Vec<&[u8]> = chain.iter().map(|c| c.as_slice()).collect();

    let result = CertificateHeaderContributor::new(&cert, &chain_refs);
    assert!(result.is_ok());
}

#[test]
fn test_new_with_empty_chain() {
    let cert = create_mock_cert();
    
    let result = CertificateHeaderContributor::new(&cert, &[]);
    assert!(result.is_ok());
}

#[test]
fn test_new_with_mismatched_chain() {
    let cert = create_mock_cert();
    let different_cert = vec![0x30, 0x99, 0xAA, 0xBB];
    let chain = vec![different_cert, vec![0x30, 0x11, 0x22]];
    let chain_refs: Vec<&[u8]> = chain.iter().map(|c| c.as_slice()).collect();

    let result = CertificateHeaderContributor::new(&cert, &chain_refs);
    assert!(result.is_err());
    match result {
        Err(CertificateError::InvalidCertificate(msg)) => {
            assert!(msg.contains("First chain certificate does not match signing certificate"));
        }
        _ => panic!("Expected InvalidCertificate error"),
    }
}

#[test]
fn test_x5t_label_constant() {
    assert_eq!(CertificateHeaderContributor::X5T_LABEL, 34);
}

#[test]
fn test_x5chain_label_constant() {
    assert_eq!(CertificateHeaderContributor::X5CHAIN_LABEL, 33);
}

#[test]
fn test_merge_strategy() {
    let cert = create_mock_cert();
    let contributor = CertificateHeaderContributor::new(&cert, &[]).unwrap();
    
    assert!(matches!(contributor.merge_strategy(), HeaderMergeStrategy::Replace));
}

#[test]
fn test_contribute_protected_headers() {
    let cert = create_mock_cert();
    let chain = create_mock_chain();
    let chain_refs: Vec<&[u8]> = chain.iter().map(|c| c.as_slice()).collect();
    
    let contributor = CertificateHeaderContributor::new(&cert, &chain_refs).unwrap();
    let mut headers = CoseHeaderMap::new();
    
    // Mock context (we don't use it in the contributor)
    let context = create_mock_context();
    
    contributor.contribute_protected_headers(&mut headers, &context);
    
    // Check that x5t and x5chain headers were added
    assert!(headers.get(&CoseHeaderLabel::Int(CertificateHeaderContributor::X5T_LABEL)).is_some());
    assert!(headers.get(&CoseHeaderLabel::Int(CertificateHeaderContributor::X5CHAIN_LABEL)).is_some());
    
    // Verify the headers contain raw CBOR data
    let x5t_value = headers.get(&CoseHeaderLabel::Int(CertificateHeaderContributor::X5T_LABEL)).unwrap();
    let x5chain_value = headers.get(&CoseHeaderLabel::Int(CertificateHeaderContributor::X5CHAIN_LABEL)).unwrap();
    
    match (x5t_value, x5chain_value) {
        (CoseHeaderValue::Raw(x5t_bytes), CoseHeaderValue::Raw(x5chain_bytes)) => {
            assert!(!x5t_bytes.is_empty());
            assert!(!x5chain_bytes.is_empty());
            
            // x5t should be CBOR array [alg_id, thumbprint]
            assert!(x5t_bytes.len() > 2); // At least array header + some content
            
            // x5chain should be CBOR array of bstr
            assert!(x5chain_bytes.len() > 2); // At least array header + some content
        }
        _ => panic!("Expected Raw header values"),
    }
}

#[test]
fn test_contribute_unprotected_headers_no_op() {
    let cert = create_mock_cert();
    let contributor = CertificateHeaderContributor::new(&cert, &[]).unwrap();
    let mut headers = CoseHeaderMap::new();
    
    let context = create_mock_context();
    
    contributor.contribute_unprotected_headers(&mut headers, &context);
    
    // Should be a no-op
    assert!(headers.is_empty());
}

#[test] 
fn test_build_x5t_sha256_thumbprint() {
    let cert = create_mock_cert();
    let contributor = CertificateHeaderContributor::new(&cert, &[]).unwrap();
    
    let mut headers = CoseHeaderMap::new();
    let context = create_mock_context();
    
    contributor.contribute_protected_headers(&mut headers, &context);
    
    let x5t_value = headers.get(&CoseHeaderLabel::Int(CertificateHeaderContributor::X5T_LABEL)).unwrap();
    
    if let CoseHeaderValue::Raw(x5t_bytes) = x5t_value {
        // Decode the CBOR to verify structure: [alg_id, thumbprint]
        let mut decoder = cose_sign1_primitives::provider::decoder(x5t_bytes);
        let array_len = decoder.decode_array_len().expect("Should be a CBOR array");
        assert_eq!(array_len, Some(2));
        
        let alg_id = decoder.decode_i64().expect("Should be algorithm ID");
        assert_eq!(alg_id, -16); // SHA-256 algorithm
        
        let thumbprint = decoder.decode_bstr().expect("Should be thumbprint bytes");
        assert_eq!(thumbprint.len(), 32); // SHA-256 produces 32 bytes
    } else {
        panic!("Expected Raw header value for x5t");
    }
}

#[test]
fn test_build_x5chain_cbor_array() {
    let cert = create_mock_cert();
    let chain = create_mock_chain();
    let chain_refs: Vec<&[u8]> = chain.iter().map(|c| c.as_slice()).collect();
    
    let contributor = CertificateHeaderContributor::new(&cert, &chain_refs).unwrap();
    
    let mut headers = CoseHeaderMap::new();
    let context = create_mock_context();
    
    contributor.contribute_protected_headers(&mut headers, &context);
    
    let x5chain_value = headers.get(&CoseHeaderLabel::Int(CertificateHeaderContributor::X5CHAIN_LABEL)).unwrap();
    
    if let CoseHeaderValue::Raw(x5chain_bytes) = x5chain_value {
        // Decode the CBOR to verify structure: array of bstr
        let mut decoder = cose_sign1_primitives::provider::decoder(x5chain_bytes);
        let array_len = decoder.decode_array_len().expect("Should be a CBOR array");
        assert_eq!(array_len, Some(chain.len()));
        
        for (i, expected_cert) in chain.iter().enumerate() {
            let cert_bytes = decoder.decode_bstr().expect(&format!("Should be cert {} bytes", i));
            assert_eq!(cert_bytes, expected_cert);
        }
    } else {
        panic!("Expected Raw header value for x5chain");
    }
}

#[test]
fn test_empty_chain_x5chain_header() {
    let cert = create_mock_cert();
    let contributor = CertificateHeaderContributor::new(&cert, &[]).unwrap();
    
    let mut headers = CoseHeaderMap::new();
    let context = create_mock_context();
    
    contributor.contribute_protected_headers(&mut headers, &context);
    
    let x5chain_value = headers.get(&CoseHeaderLabel::Int(CertificateHeaderContributor::X5CHAIN_LABEL)).unwrap();
    
    if let CoseHeaderValue::Raw(x5chain_bytes) = x5chain_value {
        // Should be empty CBOR array
        let mut decoder = cose_sign1_primitives::provider::decoder(x5chain_bytes);
        let array_len = decoder.decode_array_len().expect("Should be a CBOR array");
        assert_eq!(array_len, Some(0));
    } else {
        panic!("Expected Raw header value for x5chain");
    }
}

#[test]
fn test_x5t_different_certs_different_thumbprints() {
    let cert1 = create_mock_cert();
    let cert2 = vec![0x30, 0x99, 0xAA, 0xBB, 0xCC]; // Different cert
    
    let contributor1 = CertificateHeaderContributor::new(&cert1, &[]).unwrap();
    let contributor2 = CertificateHeaderContributor::new(&cert2, &[]).unwrap();
    
    let mut headers1 = CoseHeaderMap::new();
    let mut headers2 = CoseHeaderMap::new();
    let context = create_mock_context();
    
    contributor1.contribute_protected_headers(&mut headers1, &context);
    contributor2.contribute_protected_headers(&mut headers2, &context);
    
    let x5t_value1 = headers1.get(&CoseHeaderLabel::Int(CertificateHeaderContributor::X5T_LABEL)).unwrap();
    let x5t_value2 = headers2.get(&CoseHeaderLabel::Int(CertificateHeaderContributor::X5CHAIN_LABEL)).unwrap();
    
    // Different certificates should produce different x5t values
    assert_ne!(x5t_value1, x5t_value2);
}

#[test]
fn test_single_cert_chain() {
    let cert = create_mock_cert();
    let chain = vec![cert.clone()]; // Single cert chain
    let chain_refs: Vec<&[u8]> = chain.iter().map(|c| c.as_slice()).collect();
    
    let contributor = CertificateHeaderContributor::new(&cert, &chain_refs).unwrap();
    
    let mut headers = CoseHeaderMap::new();
    let context = create_mock_context();
    
    contributor.contribute_protected_headers(&mut headers, &context);
    
    // Should succeed and create valid headers
    assert!(headers.get(&CoseHeaderLabel::Int(CertificateHeaderContributor::X5T_LABEL)).is_some());
    assert!(headers.get(&CoseHeaderLabel::Int(CertificateHeaderContributor::X5CHAIN_LABEL)).is_some());
}

// Helper function to create a mock HeaderContributorContext
fn create_mock_context() -> HeaderContributorContext<'static> {
    use crypto_primitives::{CryptoSigner, CryptoError};
    
    struct MockSigner;
    impl CryptoSigner for MockSigner {
        fn sign(&self, _data: &[u8]) -> Result<Vec<u8>, CryptoError> {
            Ok(vec![1, 2, 3, 4])
        }
        fn algorithm(&self) -> i64 { -7 }
        fn key_id(&self) -> Option<&[u8]> { None }
        fn key_type(&self) -> &str { "EC" }
    }
    
    // Leak to get 'static lifetime for test purposes
    let signing_context: &'static SigningContext = Box::leak(Box::new(SigningContext::from_bytes(vec![])));
    let signer: &'static (dyn CryptoSigner + 'static) = Box::leak(Box::new(MockSigner));
    
    HeaderContributorContext::new(signing_context, signer)
}