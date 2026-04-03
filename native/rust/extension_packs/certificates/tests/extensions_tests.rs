// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use cose_sign1_certificates::extensions::{
    extract_x5chain, extract_x5t, verify_x5t_matches_chain, X5CHAIN_LABEL, X5T_LABEL,
};
use cose_sign1_certificates::thumbprint::{CoseX509Thumbprint, ThumbprintAlgorithm};
use cose_sign1_primitives::{CoseHeaderLabel, CoseHeaderMap, CoseHeaderValue};

fn test_cert_der() -> Vec<u8> {
    b"test certificate data".to_vec()
}

fn test_cert2_der() -> Vec<u8> {
    b"another certificate".to_vec()
}

#[test]
fn test_extract_x5chain_empty() {
    // provider not needed  using singleton
    let headers = CoseHeaderMap::new();

    let result = extract_x5chain(&headers).unwrap();
    assert!(result.is_empty());
}

#[test]
fn test_extract_x5chain_single_cert() {
    // provider not needed  using singleton
    let mut headers = CoseHeaderMap::new();

    let cert = test_cert_der();
    headers.insert(
        CoseHeaderLabel::Int(X5CHAIN_LABEL),
        CoseHeaderValue::Bytes(cert.clone().into()),
    );

    let result = extract_x5chain(&headers).unwrap();
    assert_eq!(result.len(), 1);
    assert_eq!(result[0].as_bytes(), cert.as_slice());
}

#[test]
fn test_extract_x5chain_multiple_certs() {
    let mut headers = CoseHeaderMap::new();

    let cert1 = test_cert_der();
    let cert2 = test_cert2_der();

    headers.insert(
        CoseHeaderLabel::Int(X5CHAIN_LABEL),
        CoseHeaderValue::Array(vec![
            CoseHeaderValue::Bytes(cert1.clone().into()),
            CoseHeaderValue::Bytes(cert2.clone().into()),
        ]),
    );

    let result = extract_x5chain(&headers).unwrap();
    assert_eq!(result.len(), 2);
    assert_eq!(result[0].as_bytes(), cert1.as_slice());
    assert_eq!(result[1].as_bytes(), cert2.as_slice());
}

#[test]
fn test_extract_x5t_not_present() {
    // provider not needed  using singleton
    let headers = CoseHeaderMap::new();

    let result = extract_x5t(&headers).unwrap();
    assert!(result.is_none());
}

#[test]
fn test_extract_x5t_present() {
    // provider not needed  using singleton
    let mut headers = CoseHeaderMap::new();

    let cert = test_cert_der();
    let thumbprint = CoseX509Thumbprint::new(&cert, ThumbprintAlgorithm::Sha256);
    let thumbprint_bytes = thumbprint.serialize().unwrap();

    headers.insert(
        CoseHeaderLabel::Int(X5T_LABEL),
        CoseHeaderValue::Raw(thumbprint_bytes.into()),
    );

    let result = extract_x5t(&headers).unwrap();
    assert!(result.is_some());

    let extracted = result.unwrap();
    assert_eq!(extracted.hash_id, -16);
    assert_eq!(extracted.thumbprint, thumbprint.thumbprint);
}

#[test]
fn test_verify_x5t_matches_chain_both_missing() {
    // provider not needed  using singleton
    let headers = CoseHeaderMap::new();

    let result = verify_x5t_matches_chain(&headers).unwrap();
    assert!(!result);
}

#[test]
fn test_verify_x5t_matches_chain_x5t_missing() {
    // provider not needed  using singleton
    let mut headers = CoseHeaderMap::new();

    headers.insert(
        CoseHeaderLabel::Int(X5CHAIN_LABEL),
        CoseHeaderValue::Bytes(test_cert_der().into()),
    );

    let result = verify_x5t_matches_chain(&headers).unwrap();
    assert!(!result);
}

#[test]
fn test_verify_x5t_matches_chain_x5chain_missing() {
    // provider not needed  using singleton
    let mut headers = CoseHeaderMap::new();

    let cert = test_cert_der();
    let thumbprint = CoseX509Thumbprint::new(&cert, ThumbprintAlgorithm::Sha256);
    let thumbprint_bytes = thumbprint.serialize().unwrap();

    headers.insert(
        CoseHeaderLabel::Int(X5T_LABEL),
        CoseHeaderValue::Raw(thumbprint_bytes.into()),
    );

    let result = verify_x5t_matches_chain(&headers).unwrap();
    assert!(!result);
}

#[test]
fn test_verify_x5t_matches_chain_matching() {
    // provider not needed  using singleton
    let mut headers = CoseHeaderMap::new();

    let cert = test_cert_der();
    let thumbprint = CoseX509Thumbprint::new(&cert, ThumbprintAlgorithm::Sha256);
    let thumbprint_bytes = thumbprint.serialize().unwrap();

    headers.insert(
        CoseHeaderLabel::Int(X5T_LABEL),
        CoseHeaderValue::Raw(thumbprint_bytes.into()),
    );
    headers.insert(
        CoseHeaderLabel::Int(X5CHAIN_LABEL),
        CoseHeaderValue::Bytes(cert.into()),
    );

    let result = verify_x5t_matches_chain(&headers).unwrap();
    assert!(result);
}

#[test]
fn test_verify_x5t_matches_chain_not_matching() {
    // provider not needed  using singleton
    let mut headers = CoseHeaderMap::new();

    let cert1 = test_cert_der();
    let cert2 = test_cert2_der();

    // Create thumbprint for cert1
    let thumbprint = CoseX509Thumbprint::new(&cert1, ThumbprintAlgorithm::Sha256);
    let thumbprint_bytes = thumbprint.serialize().unwrap();

    // But put cert2 in the chain
    headers.insert(
        CoseHeaderLabel::Int(X5T_LABEL),
        CoseHeaderValue::Raw(thumbprint_bytes.into()),
    );
    headers.insert(
        CoseHeaderLabel::Int(X5CHAIN_LABEL),
        CoseHeaderValue::Bytes(cert2.into()),
    );

    let result = verify_x5t_matches_chain(&headers).unwrap();
    assert!(!result);
}
