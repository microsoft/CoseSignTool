// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Comprehensive tests for CertificateHeaderContributor.

use cose_sign1_certificates::error::CertificateError;
use cose_sign1_certificates::signing::certificate_header_contributor::CertificateHeaderContributor;
use cose_sign1_primitives::{CoseHeaderLabel, CoseHeaderMap, CoseHeaderValue};
use cose_sign1_signing::{
    HeaderContributor, HeaderContributorContext, HeaderMergeStrategy, SigningContext,
};
use crypto_primitives::{CryptoError, CryptoSigner};
use rcgen::{CertificateParams, KeyPair, PKCS_ECDSA_P256_SHA256};

fn generate_test_cert() -> Vec<u8> {
    let params = CertificateParams::new(vec!["test.example.com".to_string()]).unwrap();
    let key_pair = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
    let cert = params.self_signed(&key_pair).unwrap();
    cert.der().to_vec()
}

fn create_test_context() -> HeaderContributorContext<'static> {
    struct MockSigner;
    impl CryptoSigner for MockSigner {
        fn sign(&self, _data: &[u8]) -> Result<Vec<u8>, CryptoError> {
            Ok(vec![1, 2, 3, 4])
        }
        fn algorithm(&self) -> i64 {
            -7
        }
        fn key_id(&self) -> Option<&[u8]> {
            None
        }
        fn key_type(&self) -> &str {
            "EC"
        }
    }

    let signing_context: &'static SigningContext =
        Box::leak(Box::new(SigningContext::from_bytes(vec![])));
    let signer: &'static (dyn CryptoSigner + 'static) = Box::leak(Box::new(MockSigner));

    HeaderContributorContext::new(signing_context, signer)
}

#[test]
fn test_new_with_matching_chain() {
    let cert = generate_test_cert();
    let chain = vec![cert.as_slice()];

    let result = CertificateHeaderContributor::new(&cert, &chain);
    assert!(result.is_ok(), "Should succeed with matching chain");
}

#[test]
fn test_new_with_empty_chain() {
    let cert = generate_test_cert();
    let chain: Vec<&[u8]> = vec![];

    let result = CertificateHeaderContributor::new(&cert, &chain);
    assert!(result.is_ok(), "Should succeed with empty chain");
}

#[test]
fn test_new_with_mismatched_chain_error() {
    let cert1 = generate_test_cert();
    let cert2 = generate_test_cert();
    let chain = vec![cert2.as_slice()];

    let result = CertificateHeaderContributor::new(&cert1, &chain);
    assert!(result.is_err(), "Should fail with mismatched chain");

    match result {
        Err(CertificateError::InvalidCertificate(msg)) => {
            assert!(
                msg.contains("First chain certificate does not match"),
                "error message did not contain expected substring (len={})",
                msg.len()
            );
        }
        _ => panic!("Expected InvalidCertificate error"),
    }
}

#[test]
fn test_new_with_multi_cert_chain() {
    let leaf = generate_test_cert();
    let intermediate = generate_test_cert();
    let root = generate_test_cert();

    let chain = vec![leaf.as_slice(), intermediate.as_slice(), root.as_slice()];

    let result = CertificateHeaderContributor::new(&leaf, &chain);
    assert!(result.is_ok(), "Should succeed with multi-cert chain");
}

#[test]
fn test_merge_strategy() {
    let cert = generate_test_cert();
    let chain = vec![cert.as_slice()];
    let contributor = CertificateHeaderContributor::new(&cert, &chain).unwrap();

    assert!(matches!(
        contributor.merge_strategy(),
        HeaderMergeStrategy::Replace
    ));
}

#[test]
fn test_contribute_protected_headers() {
    let cert = generate_test_cert();
    let chain = vec![cert.as_slice()];
    let contributor = CertificateHeaderContributor::new(&cert, &chain).unwrap();

    let mut headers = CoseHeaderMap::new();
    let context = create_test_context();

    contributor.contribute_protected_headers(&mut headers, &context);

    // Verify x5t header is present
    let x5t_label = CoseHeaderLabel::Int(CertificateHeaderContributor::X5T_LABEL);
    assert!(
        headers.get(&x5t_label).is_some(),
        "x5t header should be present"
    );

    // Verify x5chain header is present
    let x5chain_label = CoseHeaderLabel::Int(CertificateHeaderContributor::X5CHAIN_LABEL);
    assert!(
        headers.get(&x5chain_label).is_some(),
        "x5chain header should be present"
    );
}

#[test]
fn test_contribute_unprotected_headers_is_noop() {
    let cert = generate_test_cert();
    let chain = vec![cert.as_slice()];
    let contributor = CertificateHeaderContributor::new(&cert, &chain).unwrap();

    let mut headers = CoseHeaderMap::new();
    let context = create_test_context();

    contributor.contribute_unprotected_headers(&mut headers, &context);

    // Should not add any headers
    assert!(
        headers.is_empty(),
        "Unprotected headers should remain empty"
    );
}

#[test]
fn test_x5t_header_is_raw_cbor() {
    let cert = generate_test_cert();
    let chain = vec![cert.as_slice()];
    let contributor = CertificateHeaderContributor::new(&cert, &chain).unwrap();

    let mut headers = CoseHeaderMap::new();
    let context = create_test_context();
    contributor.contribute_protected_headers(&mut headers, &context);

    let x5t_label = CoseHeaderLabel::Int(CertificateHeaderContributor::X5T_LABEL);
    let x5t_value = headers.get(&x5t_label).unwrap();

    // Verify it's a Raw CBOR value
    match x5t_value {
        CoseHeaderValue::Raw(bytes) => {
            assert!(!bytes.is_empty(), "x5t should have non-empty bytes");
        }
        _ => panic!("x5t should be CoseHeaderValue::Raw"),
    }
}

#[test]
fn test_x5chain_header_is_raw_cbor() {
    let cert = generate_test_cert();
    let chain = vec![cert.as_slice()];
    let contributor = CertificateHeaderContributor::new(&cert, &chain).unwrap();

    let mut headers = CoseHeaderMap::new();
    let context = create_test_context();
    contributor.contribute_protected_headers(&mut headers, &context);

    let x5chain_label = CoseHeaderLabel::Int(CertificateHeaderContributor::X5CHAIN_LABEL);
    let x5chain_value = headers.get(&x5chain_label).unwrap();

    // Verify it's a Raw CBOR value
    match x5chain_value {
        CoseHeaderValue::Raw(bytes) => {
            assert!(!bytes.is_empty(), "x5chain should have non-empty bytes");
        }
        _ => panic!("x5chain should be CoseHeaderValue::Raw"),
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
fn test_new_with_single_cert_chain() {
    let cert = generate_test_cert();
    let chain = vec![cert.as_slice()];

    let result = CertificateHeaderContributor::new(&cert, &chain);
    assert!(result.is_ok());

    let contributor = result.unwrap();
    let mut headers = CoseHeaderMap::new();
    let context = create_test_context();
    contributor.contribute_protected_headers(&mut headers, &context);

    assert_eq!(headers.len(), 2, "Should have x5t and x5chain headers");
}

#[test]
fn test_new_with_two_cert_chain() {
    let leaf = generate_test_cert();
    let root = generate_test_cert();
    let chain = vec![leaf.as_slice(), root.as_slice()];

    let result = CertificateHeaderContributor::new(&leaf, &chain);
    assert!(result.is_ok());
}

#[test]
fn test_contribute_headers_idempotent() {
    let cert = generate_test_cert();
    let chain = vec![cert.as_slice()];
    let contributor = CertificateHeaderContributor::new(&cert, &chain).unwrap();

    let mut headers1 = CoseHeaderMap::new();
    let context = create_test_context();
    contributor.contribute_protected_headers(&mut headers1, &context);

    let mut headers2 = CoseHeaderMap::new();
    contributor.contribute_protected_headers(&mut headers2, &context);

    // Both should have the same number of headers
    assert_eq!(headers1.len(), headers2.len());
}

#[test]
fn test_contribute_headers_with_existing_headers() {
    let cert = generate_test_cert();
    let chain = vec![cert.as_slice()];
    let contributor = CertificateHeaderContributor::new(&cert, &chain).unwrap();

    let mut headers = CoseHeaderMap::new();
    // Add a pre-existing header
    headers.insert(CoseHeaderLabel::Int(1), CoseHeaderValue::Int(-7));

    let context = create_test_context();
    contributor.contribute_protected_headers(&mut headers, &context);

    // Should have 3 headers total (1 existing + 2 new)
    assert_eq!(
        headers.len(),
        3,
        "Should have existing header plus x5t and x5chain"
    );
}

#[test]
fn test_x5t_different_for_different_certs() {
    let cert1 = generate_test_cert();
    let cert2 = generate_test_cert();

    let contributor1 = CertificateHeaderContributor::new(&cert1, &[cert1.as_slice()]).unwrap();
    let contributor2 = CertificateHeaderContributor::new(&cert2, &[cert2.as_slice()]).unwrap();

    let mut headers1 = CoseHeaderMap::new();
    let mut headers2 = CoseHeaderMap::new();
    let context = create_test_context();

    contributor1.contribute_protected_headers(&mut headers1, &context);
    contributor2.contribute_protected_headers(&mut headers2, &context);

    let x5t_label = CoseHeaderLabel::Int(CertificateHeaderContributor::X5T_LABEL);
    let x5t1 = headers1.get(&x5t_label).unwrap();
    let x5t2 = headers2.get(&x5t_label).unwrap();

    // x5t should be different for different certificates
    assert_ne!(x5t1, x5t2, "Different certs should have different x5t");
}

#[test]
fn test_x5t_consistent_for_same_cert() {
    let cert = generate_test_cert();

    let contributor1 = CertificateHeaderContributor::new(&cert, &[cert.as_slice()]).unwrap();
    let contributor2 = CertificateHeaderContributor::new(&cert, &[cert.as_slice()]).unwrap();

    let mut headers1 = CoseHeaderMap::new();
    let mut headers2 = CoseHeaderMap::new();
    let context = create_test_context();

    contributor1.contribute_protected_headers(&mut headers1, &context);
    contributor2.contribute_protected_headers(&mut headers2, &context);

    let x5t_label = CoseHeaderLabel::Int(CertificateHeaderContributor::X5T_LABEL);
    let x5t1 = headers1.get(&x5t_label).unwrap();
    let x5t2 = headers2.get(&x5t_label).unwrap();

    // Same cert should produce same x5t
    assert_eq!(x5t1, x5t2, "Same cert should have identical x5t");
}

#[test]
fn test_empty_chain_produces_empty_x5chain() {
    let cert = generate_test_cert();
    let chain: Vec<&[u8]> = vec![];

    let contributor = CertificateHeaderContributor::new(&cert, &chain).unwrap();
    let mut headers = CoseHeaderMap::new();
    let context = create_test_context();

    contributor.contribute_protected_headers(&mut headers, &context);

    let x5chain_label = CoseHeaderLabel::Int(CertificateHeaderContributor::X5CHAIN_LABEL);
    let x5chain_value = headers.get(&x5chain_label).unwrap();

    match x5chain_value {
        CoseHeaderValue::Raw(bytes) => {
            assert!(
                !bytes.is_empty(),
                "x5chain CBOR should not be empty even for empty chain"
            );
        }
        _ => panic!("Expected Raw value"),
    }
}

#[test]
fn test_chain_with_three_certs() {
    let leaf = generate_test_cert();
    let intermediate = generate_test_cert();
    let root = generate_test_cert();

    let chain = vec![leaf.as_slice(), intermediate.as_slice(), root.as_slice()];

    let contributor = CertificateHeaderContributor::new(&leaf, &chain).unwrap();
    let mut headers = CoseHeaderMap::new();
    let context = create_test_context();

    contributor.contribute_protected_headers(&mut headers, &context);

    assert_eq!(headers.len(), 2);
}
