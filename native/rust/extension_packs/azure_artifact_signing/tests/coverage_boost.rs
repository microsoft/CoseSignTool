// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Targeted coverage tests for cose_sign1_azure_artifact_signing.
//!
//! Covers uncovered lines in:
//! - signing/did_x509_helper.rs: L27, L29-31, L64, L67-76, L99, L105-110
//! - validation/mod.rs: L27, L31, L35, L37, L40, L42-43

use std::sync::Arc;

use cose_sign1_azure_artifact_signing::signing::did_x509_helper::build_did_x509_from_ats_chain;
use cose_sign1_azure_artifact_signing::validation::facts::{
    AasComplianceFact, AasSigningServiceIdentifiedFact,
};
use cose_sign1_azure_artifact_signing::validation::{
    AasFactProducer, AzureArtifactSigningTrustPack,
};
use cose_sign1_validation::fluent::CoseSign1TrustPack;
use cose_sign1_validation_primitives::facts::{TrustFactEngine, TrustFactProducer};
use cose_sign1_validation_primitives::subject::TrustSubject;

use cose_sign1_certificates_local::{
    CertificateFactory, CertificateOptions, EphemeralCertificateFactory, SoftwareKeyProvider,
};

// ============================================================================
// Certificate generation helpers
// ============================================================================

/// Generate a certificate with code signing EKU.
fn gen_cert_code_signing() -> Vec<u8> {
    let factory = EphemeralCertificateFactory::new(Box::new(SoftwareKeyProvider::new()));
    factory
        .create_certificate(
            CertificateOptions::new()
                .with_subject_name("CN=AAS Coverage Test Cert")
                .with_enhanced_key_usages(vec!["1.3.6.1.5.5.7.3.3".to_string()]),
        )
        .unwrap()
        .cert_der
}

/// Generate a certificate with multiple EKUs including code signing.
fn gen_cert_multi_eku() -> Vec<u8> {
    let factory = EphemeralCertificateFactory::new(Box::new(SoftwareKeyProvider::new()));
    factory
        .create_certificate(
            CertificateOptions::new()
                .with_subject_name("CN=AAS Multi-EKU Test Cert")
                .with_enhanced_key_usages(vec![
                    "1.3.6.1.5.5.7.3.3".to_string(),
                    "1.3.6.1.5.5.7.3.1".to_string(),
                    "1.3.6.1.5.5.7.3.2".to_string(),
                ]),
        )
        .unwrap()
        .cert_der
}

/// Generate a certificate with no EKU.
fn gen_cert_no_eku() -> Vec<u8> {
    let factory = EphemeralCertificateFactory::new(Box::new(SoftwareKeyProvider::new()));
    factory
        .create_certificate(
            CertificateOptions::new()
                .with_subject_name("CN=AAS No-EKU Test Cert")
                .with_enhanced_key_usages(vec![]),
        )
        .unwrap()
        .cert_der
}

// ============================================================================
// did_x509_helper.rs coverage
// Targets: L27 (microsoft_eku branch), L29-31 (DidX509Builder::build_from_chain),
//          L64 (microsoft_ekus.is_empty()), L67-76 (max_by selection),
//          L99 (eku_part extraction), L105-110 (last_segment_value)
// ============================================================================

#[test]
fn test_build_did_x509_from_ats_chain_code_signing() {
    // Exercises the main success path: builds DID from a cert with code signing EKU
    // Covers L27-36 fallback path (no Microsoft EKU → generic build)
    let cert_der = gen_cert_code_signing();
    let chain: Vec<&[u8]> = vec![cert_der.as_slice()];

    let result = build_did_x509_from_ats_chain(&chain);
    assert!(result.is_ok(), "should succeed: {:?}", result.err());
    let did = result.unwrap();
    assert!(did.starts_with("did:x509:0:"));
    assert!(did.contains("::eku:"));
}

#[test]
fn test_build_did_x509_from_ats_chain_multi_eku() {
    // Multiple EKUs: exercises the find_deepest_greatest_microsoft_eku filter logic
    // Covers L57-64 (microsoft_ekus filtering)
    let cert_der = gen_cert_multi_eku();
    let chain: Vec<&[u8]> = vec![cert_der.as_slice()];

    let result = build_did_x509_from_ats_chain(&chain);
    assert!(result.is_ok(), "should succeed: {:?}", result.err());
    let did = result.unwrap();
    assert!(did.starts_with("did:x509:"));
}

#[test]
fn test_build_did_x509_from_ats_chain_no_eku_fallback() {
    // No EKU → exercises the fallback path at L33-36
    // Also covers L64 (microsoft_ekus.is_empty() returns true)
    let cert_der = gen_cert_no_eku();
    let chain: Vec<&[u8]> = vec![cert_der.as_slice()];

    let result = build_did_x509_from_ats_chain(&chain);
    // Without any EKU, the generic builder may also fail
    match result {
        Ok(did) => assert!(did.starts_with("did:x509:")),
        Err(e) => assert!(e.to_string().contains("DID:x509")),
    }
}

#[test]
fn test_build_did_x509_from_ats_chain_empty() {
    // Empty chain exercises the early return at L48-49
    let empty: Vec<&[u8]> = vec![];
    let result = build_did_x509_from_ats_chain(&empty);
    assert!(result.is_err());
}

#[test]
fn test_build_did_x509_from_ats_chain_invalid_der() {
    // Invalid DER exercises error mapping at L31 and L35
    let garbage = vec![0xDE, 0xAD, 0xBE, 0xEF];
    let chain: Vec<&[u8]> = vec![garbage.as_slice()];

    let result = build_did_x509_from_ats_chain(&chain);
    assert!(result.is_err());
    let err_msg = result.unwrap_err().to_string();
    assert!(
        err_msg.contains("DID:x509") || err_msg.contains("AAS"),
        "error should mention DID:x509: got '{}'",
        err_msg
    );
}

#[test]
fn test_build_did_x509_from_ats_chain_two_cert_chain() {
    // Two certificates: leaf + CA, exercises the chain path
    let leaf = gen_cert_code_signing();
    let ca = gen_cert_code_signing();
    let chain: Vec<&[u8]> = vec![leaf.as_slice(), ca.as_slice()];

    let result = build_did_x509_from_ats_chain(&chain);
    assert!(
        result.is_ok(),
        "two-cert chain should succeed: {:?}",
        result.err()
    );
    let did = result.unwrap();
    assert!(did.starts_with("did:x509:0:"));
}

// ============================================================================
// validation/mod.rs coverage
// Targets: L27 (AasFactProducer::produce ctx.observe AasSigningServiceIdentifiedFact),
//          L31-35 (AasSigningServiceIdentifiedFact fields),
//          L37 (ctx.observe AasComplianceFact), L40, L42-43 (AasComplianceFact fields)
// ============================================================================

#[test]
fn test_ats_fact_producer_name_and_provides() {
    // Cover the AasFactProducer trait methods
    let producer = AasFactProducer;
    assert_eq!(producer.name(), "azure_artifact_signing");
    // provides() now returns the registered fact keys
    assert!(!producer.provides().is_empty());
    assert_eq!(producer.provides().len(), 2);
}

#[test]
fn test_ats_trust_pack_methods() {
    let trust_pack = AzureArtifactSigningTrustPack::new();
    assert_eq!(trust_pack.name(), "azure_artifact_signing");

    let fp = trust_pack.fact_producer();
    assert_eq!(fp.name(), "azure_artifact_signing");

    let resolvers = trust_pack.cose_key_resolvers();
    assert!(resolvers.is_empty());

    let validators = trust_pack.post_signature_validators();
    assert!(validators.is_empty());

    let plan = trust_pack.default_trust_plan();
    assert!(plan.is_none());
}

// ============================================================================
// Facts property access coverage
// ============================================================================

#[test]
fn test_ats_signing_service_identified_fact_properties() {
    use cose_sign1_validation_primitives::fact_properties::FactProperties;

    let fact = AasSigningServiceIdentifiedFact {
        is_ats_issued: true,
        issuer_cn: Some("CN=Microsoft".to_string()),
        eku_oids: vec!["1.3.6.1.4.1.311.76.59.1.1".to_string()],
    };

    assert!(matches!(
        fact.get_property("is_ats_issued"),
        Some(cose_sign1_validation_primitives::fact_properties::FactValue::Bool(true))
    ));
    assert!(fact.get_property("issuer_cn").is_some());
    assert!(fact.get_property("nonexistent").is_none());
}

#[test]
fn test_ats_compliance_fact_properties() {
    use cose_sign1_validation_primitives::fact_properties::FactProperties;

    let fact = AasComplianceFact {
        fips_level: "level3".to_string(),
        scitt_compliant: true,
    };

    assert!(fact.get_property("fips_level").is_some());
    assert!(matches!(
        fact.get_property("scitt_compliant"),
        Some(cose_sign1_validation_primitives::fact_properties::FactValue::Bool(true))
    ));
    assert!(fact.get_property("nonexistent").is_none());
}
