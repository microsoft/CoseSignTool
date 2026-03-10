// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use cose_sign1_certificates::{
    chain_builder::{CertificateChainBuilder, ExplicitCertificateChainBuilder},
};

#[test]
fn test_explicit_chain_builder_new() {
    let cert1 = vec![1, 2, 3];
    let cert2 = vec![4, 5, 6];
    let certs = vec![cert1.clone(), cert2.clone()];

    let builder = ExplicitCertificateChainBuilder::new(certs.clone());
    // The constructor should succeed - we can't access the private field directly,
    // but we can test the functionality through the public interface
    let result = builder.build_chain(&[7, 8, 9]).unwrap();
    assert_eq!(result, certs);
}

#[test]
fn test_explicit_chain_builder_build_chain() {
    let cert1 = vec![1, 2, 3];
    let cert2 = vec![4, 5, 6];
    let certs = vec![cert1.clone(), cert2.clone()];

    let builder = ExplicitCertificateChainBuilder::new(certs.clone());
    let result = builder.build_chain(&[7, 8, 9]).unwrap();
    assert_eq!(result, certs);
}

#[test]
fn test_explicit_chain_builder_empty_chain() {
    let builder = ExplicitCertificateChainBuilder::new(vec![]);
    let result = builder.build_chain(&[1, 2, 3]).unwrap();
    assert_eq!(result, Vec::<Vec<u8>>::new());
}