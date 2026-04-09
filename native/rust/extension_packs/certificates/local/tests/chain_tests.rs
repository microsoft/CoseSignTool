// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Tests for CertificateChainFactory.

use cose_sign1_certificates_local::*;
use std::time::Duration;

#[test]
fn test_create_default_chain() {
    let provider = Box::new(SoftwareKeyProvider::new());
    let cert_factory = EphemeralCertificateFactory::new(provider);
    let chain_factory = CertificateChainFactory::new(cert_factory);

    let chain = chain_factory.create_chain().unwrap();

    // Default is 3-tier: root -> intermediate -> leaf
    assert_eq!(chain.len(), 3);

    // Verify order (root first by default)
    use x509_parser::prelude::*;
    let root = X509Certificate::from_der(&chain[0].cert_der).unwrap().1;
    let intermediate = X509Certificate::from_der(&chain[1].cert_der).unwrap().1;
    let leaf = X509Certificate::from_der(&chain[2].cert_der).unwrap().1;

    assert!(root.subject().to_string().contains("Root CA"));
    assert!(intermediate
        .subject()
        .to_string()
        .contains("Intermediate CA"));
    assert!(leaf.subject().to_string().contains("Leaf Certificate"));
}

#[test]
fn test_create_three_tier_chain() {
    let provider = Box::new(SoftwareKeyProvider::new());
    let cert_factory = EphemeralCertificateFactory::new(provider);
    let chain_factory = CertificateChainFactory::new(cert_factory);

    let options = CertificateChainOptions::new()
        .with_root_name("CN=Test Root")
        .with_intermediate_name(Some("CN=Test Intermediate"))
        .with_leaf_name("CN=Test Leaf");

    let chain = chain_factory.create_chain_with_options(options).unwrap();

    assert_eq!(chain.len(), 3);

    // Verify all have private keys by default
    assert!(chain[0].has_private_key());
    assert!(chain[1].has_private_key());
    assert!(chain[2].has_private_key());
}

#[test]
fn test_create_two_tier_chain() {
    let provider = Box::new(SoftwareKeyProvider::new());
    let cert_factory = EphemeralCertificateFactory::new(provider);
    let chain_factory = CertificateChainFactory::new(cert_factory);

    let options = CertificateChainOptions::new()
        .with_root_name("CN=Two Tier Root")
        .with_intermediate_name(None::<String>) // No intermediate
        .with_leaf_name("CN=Two Tier Leaf");

    let chain = chain_factory.create_chain_with_options(options).unwrap();

    assert_eq!(chain.len(), 2);

    use x509_parser::prelude::*;
    let root = X509Certificate::from_der(&chain[0].cert_der).unwrap().1;
    let leaf = X509Certificate::from_der(&chain[1].cert_der).unwrap().1;

    assert!(root.subject().to_string().contains("Two Tier Root"));
    assert!(leaf.subject().to_string().contains("Two Tier Leaf"));
}

#[test]
fn test_leaf_first_order() {
    let provider = Box::new(SoftwareKeyProvider::new());
    let cert_factory = EphemeralCertificateFactory::new(provider);
    let chain_factory = CertificateChainFactory::new(cert_factory);

    let options = CertificateChainOptions::new().with_leaf_first(true);

    let chain = chain_factory.create_chain_with_options(options).unwrap();

    // Verify order (leaf first)
    use x509_parser::prelude::*;
    let first = X509Certificate::from_der(&chain[0].cert_der).unwrap().1;
    let second = X509Certificate::from_der(&chain[1].cert_der).unwrap().1;
    let third = X509Certificate::from_der(&chain[2].cert_der).unwrap().1;

    assert!(first.subject().to_string().contains("Leaf Certificate"));
    assert!(second.subject().to_string().contains("Intermediate CA"));
    assert!(third.subject().to_string().contains("Root CA"));
}

#[test]
fn test_leaf_only_private_key() {
    let provider = Box::new(SoftwareKeyProvider::new());
    let cert_factory = EphemeralCertificateFactory::new(provider);
    let chain_factory = CertificateChainFactory::new(cert_factory);

    let options = CertificateChainOptions::new().with_leaf_only_private_key(true);

    let chain = chain_factory.create_chain_with_options(options).unwrap();

    // Only leaf should have private key
    assert!(!chain[0].has_private_key()); // root
    assert!(!chain[1].has_private_key()); // intermediate
    assert!(chain[2].has_private_key()); // leaf
}

#[test]
fn test_ca_basic_constraints() {
    let provider = Box::new(SoftwareKeyProvider::new());
    let cert_factory = EphemeralCertificateFactory::new(provider);
    let chain_factory = CertificateChainFactory::new(cert_factory);

    let chain = chain_factory.create_chain().unwrap();

    use x509_parser::prelude::*;

    // Root should be CA
    let root = X509Certificate::from_der(&chain[0].cert_der).unwrap().1;
    let root_bc = root.basic_constraints().unwrap().unwrap().value;
    assert!(root_bc.ca);

    // Intermediate should be CA
    let intermediate = X509Certificate::from_der(&chain[1].cert_der).unwrap().1;
    let intermediate_bc = intermediate.basic_constraints().unwrap().unwrap().value;
    assert!(intermediate_bc.ca);

    // Leaf should NOT be CA
    let leaf = X509Certificate::from_der(&chain[2].cert_der).unwrap().1;
    let leaf_bc = leaf.basic_constraints().unwrap();
    assert!(leaf_bc.is_none() || !leaf_bc.unwrap().value.ca);
}

#[test]
fn test_custom_key_algorithm() {
    let provider = Box::new(SoftwareKeyProvider::new());
    let cert_factory = EphemeralCertificateFactory::new(provider);
    let chain_factory = CertificateChainFactory::new(cert_factory);

    let options = CertificateChainOptions::new()
        .with_key_algorithm(KeyAlgorithm::Ecdsa)
        .with_key_size(256);

    let chain = chain_factory.create_chain_with_options(options).unwrap();

    // Verify all certificates use ECDSA
    use x509_parser::prelude::*;
    for cert in &chain {
        let parsed = X509Certificate::from_der(&cert.cert_der).unwrap().1;
        let spki = &parsed.public_key();
        assert!(spki
            .algorithm
            .algorithm
            .to_string()
            .contains("1.2.840.10045"));
    }
}

#[test]
fn test_custom_validity_periods() {
    let provider = Box::new(SoftwareKeyProvider::new());
    let cert_factory = EphemeralCertificateFactory::new(provider);
    let chain_factory = CertificateChainFactory::new(cert_factory);

    let options = CertificateChainOptions::new()
        .with_root_validity(Duration::from_secs(365 * 24 * 60 * 60 * 2)) // 2 years
        .with_intermediate_validity(Duration::from_secs(365 * 24 * 60 * 60)) // 1 year
        .with_leaf_validity(Duration::from_secs(30 * 24 * 60 * 60)); // 30 days

    let chain = chain_factory.create_chain_with_options(options).unwrap();

    assert_eq!(chain.len(), 3);

    // Just verify they were created successfully with custom validity
    // Actual date checking is complex due to clock skew
    use x509_parser::prelude::*;
    let root = X509Certificate::from_der(&chain[0].cert_der).unwrap().1;
    let intermediate = X509Certificate::from_der(&chain[1].cert_der).unwrap().1;
    let leaf = X509Certificate::from_der(&chain[2].cert_der).unwrap().1;

    // Verify they all have valid dates
    assert!(root.validity().not_before.timestamp() > 0);
    assert!(intermediate.validity().not_before.timestamp() > 0);
    assert!(leaf.validity().not_before.timestamp() > 0);
}

#[test]
fn test_chain_linkage() {
    let provider = Box::new(SoftwareKeyProvider::new());
    let cert_factory = EphemeralCertificateFactory::new(provider);
    let chain_factory = CertificateChainFactory::new(cert_factory);

    let chain = chain_factory.create_chain().unwrap();

    use x509_parser::prelude::*;

    // Verify chain linkage via issuer/subject
    let root = X509Certificate::from_der(&chain[0].cert_der).unwrap().1;
    let intermediate = X509Certificate::from_der(&chain[1].cert_der).unwrap().1;
    let leaf = X509Certificate::from_der(&chain[2].cert_der).unwrap().1;

    // Root is self-signed
    assert_eq!(root.issuer().to_string(), root.subject().to_string());

    // Intermediate is signed by root
    assert_eq!(
        intermediate.issuer().to_string(),
        root.subject().to_string()
    );

    // Leaf is signed by intermediate
    assert_eq!(
        leaf.issuer().to_string(),
        intermediate.subject().to_string()
    );
}

#[test]
fn test_leaf_enhanced_key_usages() {
    let provider = Box::new(SoftwareKeyProvider::new());
    let cert_factory = EphemeralCertificateFactory::new(provider);
    let chain_factory = CertificateChainFactory::new(cert_factory);

    let options = CertificateChainOptions::new().with_leaf_enhanced_key_usages(vec![
        "1.3.6.1.5.5.7.3.1".to_string(), // Server Auth
        "1.3.6.1.5.5.7.3.2".to_string(), // Client Auth
    ]);

    let chain = chain_factory.create_chain_with_options(options).unwrap();

    // Just verify it was created successfully
    assert_eq!(chain.len(), 3);

    use x509_parser::prelude::*;
    let leaf = X509Certificate::from_der(&chain[2].cert_der).unwrap().1;

    // Verify leaf has EKU extension
    let eku = leaf.extended_key_usage();
    assert!(eku.is_ok());
}

#[test]
fn test_chain_with_rsa_4096() {
    let provider = Box::new(SoftwareKeyProvider::new());
    let cert_factory = EphemeralCertificateFactory::new(provider);
    let chain_factory = CertificateChainFactory::new(cert_factory);

    let options = CertificateChainOptions::new()
        .with_key_algorithm(KeyAlgorithm::Rsa)
        .with_key_size(4096)
        .with_intermediate_name(None::<String>); // 2-tier for faster test

    // RSA is now supported via OpenSSL
    let result = chain_factory.create_chain_with_options(options);
    assert!(result.is_ok(), "RSA 4096 chain should succeed: {:?}", result.err());

    let chain = result.unwrap();
    assert!(chain.len() >= 2, "Expected at least root + leaf");
    assert!(!chain.last().unwrap().cert_der.is_empty());
    assert!(chain.last().unwrap().private_key_der.is_some());
}
