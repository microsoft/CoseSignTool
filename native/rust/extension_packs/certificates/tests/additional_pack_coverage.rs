// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Additional coverage tests for certificate trust pack functionality

use cose_sign1_certificates::validation::pack::{
    CertificateTrustOptions, X509CertificateTrustPack,
};
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
fn test_certificate_trust_options_clone() {
    let options = CertificateTrustOptions {
        allowed_thumbprints: vec!["test_thumbprint".to_string()],
        identity_pinning_enabled: true,
        pqc_algorithm_oids: vec!["1.2.3.4".to_string()],
        trust_embedded_chain_as_trusted: true,
    };

    let cloned = options.clone();
    assert_eq!(cloned.allowed_thumbprints, options.allowed_thumbprints);
    assert_eq!(
        cloned.identity_pinning_enabled,
        options.identity_pinning_enabled
    );
    assert_eq!(cloned.pqc_algorithm_oids, options.pqc_algorithm_oids);
    assert_eq!(
        cloned.trust_embedded_chain_as_trusted,
        options.trust_embedded_chain_as_trusted
    );
}

#[test]
fn test_certificate_trust_options_debug() {
    let options = CertificateTrustOptions::default();
    let debug_str = format!("{:?}", options);
    assert!(debug_str.contains("CertificateTrustOptions"));
    assert!(debug_str.contains("allowed_thumbprints"));
    assert!(debug_str.contains("identity_pinning_enabled"));
}

#[test]
fn test_trust_pack_with_identity_pinning_enabled() {
    let options = CertificateTrustOptions {
        identity_pinning_enabled: true,
        allowed_thumbprints: vec!["ABC123".to_string(), "DEF456".to_string()],
        ..Default::default()
    };

    let pack = X509CertificateTrustPack::new(options);
    assert_eq!(pack.name(), "X509CertificateTrustPack");

    // Test that pack name is stable across instances
    let pack2 = X509CertificateTrustPack::new(CertificateTrustOptions::default());
    assert_eq!(pack.name(), pack2.name());
}

#[test]
fn test_trust_pack_with_pqc_algorithms() {
    let options = CertificateTrustOptions {
        pqc_algorithm_oids: vec![
            "1.3.6.1.4.1.2.267.12.4.4".to_string(), // ML-DSA-65
            "1.3.6.1.4.1.2.267.12.6.5".to_string(), // ML-KEM-768
        ],
        ..Default::default()
    };

    let pack = X509CertificateTrustPack::new(options);

    // Basic checks that pack was created successfully
    assert_eq!(pack.name(), "X509CertificateTrustPack");
    let fact_producer = pack.fact_producer();
    assert!(!fact_producer.provides().is_empty());
}

#[test]
fn test_trust_pack_with_embedded_chain_trust() {
    let mut options = CertificateTrustOptions::default();
    options.trust_embedded_chain_as_trusted = true;

    let pack = X509CertificateTrustPack::new(options);
    assert_eq!(pack.name(), "X509CertificateTrustPack");

    // Verify that resolvers are provided
    let resolvers = pack.cose_key_resolvers();
    assert!(!resolvers.is_empty());
}

#[test]
fn test_trust_pack_post_signature_validators() {
    let options = CertificateTrustOptions::default();
    let pack = X509CertificateTrustPack::new(options);

    let validators = pack.post_signature_validators();
    // Default implementation returns empty (no post-signature validators for certificates pack)
    assert!(validators.is_empty());
}

#[test]
fn test_trust_pack_default_plan_availability() {
    let options = CertificateTrustOptions::default();
    let pack = X509CertificateTrustPack::new(options);

    // Check that default plan is available
    let default_plan = pack.default_trust_plan();
    assert!(default_plan.is_some());
}

#[test]
fn test_trust_pack_fact_producer_keys_non_empty() {
    let options = CertificateTrustOptions::default();
    let pack = X509CertificateTrustPack::new(options);

    let fact_producer = pack.fact_producer();
    let fact_keys = fact_producer.provides();

    // Should produce various certificate-related facts
    assert!(!fact_keys.is_empty());
}

#[test]
fn test_trust_pack_with_complex_options() {
    let options = CertificateTrustOptions {
        allowed_thumbprints: vec!["ABCD1234".to_string()],
        identity_pinning_enabled: true,
        pqc_algorithm_oids: vec!["1.3.6.1.4.1.2.267.12.4.4".to_string()],
        trust_embedded_chain_as_trusted: true,
    };

    let pack = X509CertificateTrustPack::new(options);

    // Verify all components are available
    assert_eq!(pack.name(), "X509CertificateTrustPack");
    assert!(!pack.fact_producer().provides().is_empty());
    assert!(!pack.cose_key_resolvers().is_empty());
    assert!(pack.post_signature_validators().is_empty()); // Default empty
    assert!(pack.default_trust_plan().is_some());
}

#[test]
fn test_trust_embedded_chain_constructor() {
    let pack = X509CertificateTrustPack::trust_embedded_chain_as_trusted();
    assert_eq!(pack.name(), "X509CertificateTrustPack");

    // Verify that resolvers and validators are available
    let resolvers = pack.cose_key_resolvers();
    assert!(!resolvers.is_empty());

    let validators = pack.post_signature_validators();
    assert!(validators.is_empty()); // Default implementation is empty
}

#[test]
fn test_certificate_trust_options_with_case_insensitive_thumbprints() {
    let mut options = CertificateTrustOptions::default();
    options.allowed_thumbprints.push("abcd1234".to_string());
    options.allowed_thumbprints.push("EFGH5678".to_string());
    options
        .allowed_thumbprints
        .push(" 12 34 56 78 ".to_string()); // with spaces

    let pack = X509CertificateTrustPack::new(options);
    assert_eq!(pack.name(), "X509CertificateTrustPack");
}
