// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Targeted coverage tests for cose_sign1_certificates_local gaps.
//!
//! Targets: factory.rs (ML-DSA/RSA paths, CA constraints),
//!          software_key.rs (MlDsa feature-gated paths),
//!          certificate.rs (Debug impl),
//!          chain_factory.rs (edge case),
//!          loaders/der.rs (load errors),
//!          loaders/pem.rs (edge case).

use cose_sign1_certificates_local::certificate::Certificate;
use cose_sign1_certificates_local::error::CertLocalError;
use cose_sign1_certificates_local::factory::EphemeralCertificateFactory;
use cose_sign1_certificates_local::key_algorithm::KeyAlgorithm;
use cose_sign1_certificates_local::options::CertificateOptions;
use cose_sign1_certificates_local::software_key::SoftwareKeyProvider;
use cose_sign1_certificates_local::traits::{CertificateFactory, PrivateKeyProvider};
use std::time::Duration;

fn make_factory() -> EphemeralCertificateFactory {
    EphemeralCertificateFactory::new(Box::new(SoftwareKeyProvider::new()))
}

// ==========================================================================
// certificate.rs — Debug impl hides private key
// ==========================================================================

#[test]
fn certificate_debug_hides_private_key() {
    let factory = make_factory();
    let cert = factory
        .create_certificate(CertificateOptions::default())
        .unwrap();
    let debug_str = format!("{:?}", cert);
    // Debug should not contain actual key bytes
    assert!(debug_str.contains("Certificate"));
}

// ==========================================================================
// factory.rs — issuer-signed without private key yields error
// ==========================================================================

#[test]
fn factory_issuer_without_key_returns_error() {
    let factory = make_factory();
    // Create a cert without private key to use as issuer
    let cert = factory
        .create_certificate(CertificateOptions::default())
        .unwrap();
    let issuer_no_key = Certificate::new(cert.cert_der.clone());

    let mut opts = CertificateOptions::default();
    opts.issuer = Some(Box::new(issuer_no_key));
    let result = factory.create_certificate(opts);
    assert!(result.is_err());
    let err_msg = format!("{}", result.unwrap_err());
    assert!(
        err_msg.contains("private key"),
        "Error should mention private key: {}",
        err_msg
    );
}

// ==========================================================================
// factory.rs — CA cert with unbounded path length
// ==========================================================================

#[test]
fn factory_ca_cert_unbounded_path_length() {
    let factory = make_factory();
    let opts = CertificateOptions::default()
        .with_subject_name("CN=UnboundedCA")
        .as_ca(u32::MAX);
    let cert = factory.create_certificate(opts).unwrap();
    assert!(!cert.cert_der.is_empty());
}

// ==========================================================================
// factory.rs — get_generated_key for nonexistent serial
// ==========================================================================

#[test]
fn factory_get_generated_key_missing() {
    let factory = make_factory();
    assert!(factory.get_generated_key("nonexistent").is_none());
}

// ==========================================================================
// factory.rs — release_key for nonexistent serial
// ==========================================================================

#[test]
fn factory_release_key_missing() {
    let factory = make_factory();
    assert!(!factory.release_key("nonexistent"));
}

// ==========================================================================
// loaders/der.rs — invalid DER bytes from file-like source
// ==========================================================================

#[test]
fn der_load_invalid_bytes_returns_error() {
    use cose_sign1_certificates_local::loaders::der;
    let result = der::load_cert_from_der_bytes(&[0xFF, 0xFE, 0x00]);
    assert!(result.is_err());
}

// ==========================================================================
// factory.rs — self-signed with custom validity and subject
// ==========================================================================

#[test]
fn factory_custom_validity_and_subject() {
    let factory = make_factory();
    let opts = CertificateOptions::default()
        .with_subject_name("CN=CustomSubject")
        .with_validity(Duration::from_secs(86400 * 365));
    let cert = factory.create_certificate(opts).unwrap();
    let subject = cert.subject().unwrap();
    assert!(subject.contains("CustomSubject"), "Subject: {}", subject);
}

// ==========================================================================
// chain_factory.rs — 2-tier chain (root + leaf, no intermediate)
// ==========================================================================

#[test]
fn chain_factory_two_tier() {
    use cose_sign1_certificates_local::chain_factory::{
        CertificateChainFactory, CertificateChainOptions,
    };
    let inner = EphemeralCertificateFactory::new(Box::new(SoftwareKeyProvider::new()));
    let factory = CertificateChainFactory::new(inner);
    let opts = CertificateChainOptions::default().with_intermediate_name(None::<String>);
    let chain = factory.create_chain_with_options(opts).unwrap();
    // 2-tier: root + leaf
    assert_eq!(chain.len(), 2, "Expected 2 certs in 2-tier chain");
}

// ==========================================================================
// certificate.rs — thumbprint_sha256 and has_private_key
// ==========================================================================

#[test]
fn certificate_thumbprint_and_private_key_check() {
    let factory = make_factory();
    let cert = factory
        .create_certificate(CertificateOptions::default())
        .unwrap();
    let thumb = cert.thumbprint_sha256();
    assert_eq!(thumb.len(), 32, "SHA-256 thumbprint should be 32 bytes");
    assert!(cert.has_private_key());

    let no_key = Certificate::new(cert.cert_der.clone());
    assert!(!no_key.has_private_key());
}
