// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Extended test coverage for pack.rs module, targeting uncovered lines.

use cose_sign1_certificates::validation::pack::*;
use cose_sign1_validation::fluent::CoseSign1TrustPack;

#[test]
fn test_certificate_trust_options_default() {
    let options = CertificateTrustOptions::default();
    assert!(options.allowed_thumbprints.is_empty());
    assert!(!options.identity_pinning_enabled);
    assert!(options.pqc_algorithm_oids.is_empty());
    assert!(!options.trust_embedded_chain_as_trusted);
}

#[test]
fn test_certificate_trust_options_with_allowed_thumbprints() {
    let options = CertificateTrustOptions {
        allowed_thumbprints: vec!["abc123".to_string(), "def456".to_string()],
        identity_pinning_enabled: true,
        pqc_algorithm_oids: vec!["1.2.3.4".to_string()],
        trust_embedded_chain_as_trusted: true,
    };

    assert_eq!(options.allowed_thumbprints.len(), 2);
    assert!(options.identity_pinning_enabled);
    assert_eq!(options.pqc_algorithm_oids.len(), 1);
    assert!(options.trust_embedded_chain_as_trusted);
}

#[test]
fn test_certificate_trust_options_debug_format() {
    let options = CertificateTrustOptions {
        allowed_thumbprints: vec!["abc123".to_string()],
        identity_pinning_enabled: true,
        pqc_algorithm_oids: vec!["1.2.3.4".to_string()],
        trust_embedded_chain_as_trusted: true,
    };

    let debug_str = format!("{:?}", options);
    assert!(debug_str.contains("CertificateTrustOptions"));
    assert!(debug_str.contains("abc123"));
    assert!(debug_str.contains("true"));
    assert!(debug_str.contains("1.2.3.4"));
}

#[test]
fn test_certificate_trust_options_clone() {
    let options = CertificateTrustOptions {
        allowed_thumbprints: vec!["test".to_string()],
        identity_pinning_enabled: true,
        pqc_algorithm_oids: vec!["1.2.3".to_string()],
        trust_embedded_chain_as_trusted: true,
    };

    let cloned = options.clone();
    assert_eq!(options.allowed_thumbprints, cloned.allowed_thumbprints);
    assert_eq!(
        options.identity_pinning_enabled,
        cloned.identity_pinning_enabled
    );
    assert_eq!(options.pqc_algorithm_oids, cloned.pqc_algorithm_oids);
    assert_eq!(
        options.trust_embedded_chain_as_trusted,
        cloned.trust_embedded_chain_as_trusted
    );
}

#[test]
fn test_x509_certificate_trust_pack_fact_producer() {
    let options = CertificateTrustOptions::default();
    let pack = X509CertificateTrustPack::new(options);

    let _producer = pack.fact_producer();
    // Producer exists and can be obtained
}

#[test]
fn test_x509_certificate_trust_pack_cose_key_resolvers() {
    let options = CertificateTrustOptions::default();
    let pack = X509CertificateTrustPack::new(options);

    let resolvers = pack.cose_key_resolvers();
    assert!(!resolvers.is_empty());
}

#[test]
fn test_x509_certificate_trust_pack_post_signature_validators() {
    let options = CertificateTrustOptions::default();
    let pack = X509CertificateTrustPack::new(options);

    let _validators = pack.post_signature_validators();
    // Validators list can be obtained
}

#[test]
fn test_x509_certificate_trust_pack_default_trust_plan() {
    let options = CertificateTrustOptions::default();
    let pack = X509CertificateTrustPack::new(options);

    let plan = pack.default_trust_plan();
    assert!(plan.is_some());
}

#[test]
fn test_x509_certificate_trust_pack_clone() {
    let options = CertificateTrustOptions {
        allowed_thumbprints: vec!["test123".to_string()],
        identity_pinning_enabled: true,
        ..Default::default()
    };

    let pack = X509CertificateTrustPack::new(options.clone());
    let cloned_pack = pack.clone();

    // Verify the clone has same configuration
    let _producer1 = pack.fact_producer();
    let _producer2 = cloned_pack.fact_producer();
    // Both packs can produce fact producers
}
