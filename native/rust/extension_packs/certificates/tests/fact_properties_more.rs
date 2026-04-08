// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use cose_sign1_certificates::validation::facts::{
    fields, X509ChainElementIdentityFact, X509ChainElementValidityFact, X509ChainTrustedFact,
    X509PublicKeyAlgorithmFact, X509SigningCertificateIdentityFact,
};
use cose_sign1_validation_primitives::fact_properties::{FactProperties, FactValue};
use std::sync::Arc;

// ---------------------------------------------------------------------------
// X509ChainTrustedFact – status_summary None branch
// ---------------------------------------------------------------------------

#[test]
fn chain_trusted_status_summary_none_returns_none() {
    let fact = X509ChainTrustedFact {
        chain_built: true,
        is_trusted: true,
        status_flags: 0,
        status_summary: None,
        element_count: 1,
    };

    assert_eq!(
        fact.get_property(fields::x509_chain_trusted::STATUS_SUMMARY),
        None
    );
}

// ---------------------------------------------------------------------------
// X509PublicKeyAlgorithmFact – algorithm_name Some / None branches
// ---------------------------------------------------------------------------

#[test]
fn public_key_algorithm_name_some_returns_value() {
    let fact = X509PublicKeyAlgorithmFact {
        certificate_thumbprint: Arc::from("abc"),
        algorithm_oid: Arc::from("1.2.840.113549.1.1.11"),
        algorithm_name: Some(Arc::from("RSA-SHA256")),
        is_pqc: false,
    };

    assert!(matches!(
        fact.get_property(fields::x509_public_key_algorithm::ALGORITHM_NAME),
        Some(FactValue::Str(s)) if s.as_ref() == "RSA-SHA256"
    ));
}

#[test]
fn public_key_algorithm_name_none_returns_none() {
    let fact = X509PublicKeyAlgorithmFact {
        certificate_thumbprint: Arc::from("abc"),
        algorithm_oid: Arc::from("1.2.3"),
        algorithm_name: None,
        is_pqc: false,
    };

    assert_eq!(
        fact.get_property(fields::x509_public_key_algorithm::ALGORITHM_NAME),
        None
    );
}

// ---------------------------------------------------------------------------
// Unknown / empty property names return None for every fact type
// ---------------------------------------------------------------------------

#[test]
fn signing_cert_identity_unknown_property_returns_none() {
    let fact = X509SigningCertificateIdentityFact {
        certificate_thumbprint: Arc::from("t"),
        subject: Arc::from("s"),
        issuer: Arc::from("i"),
        serial_number: Arc::from("sn"),
        not_before_unix_seconds: 0,
        not_after_unix_seconds: 0,
    };

    assert_eq!(fact.get_property("nonexistent"), None);
    assert_eq!(fact.get_property(""), None);
    assert_eq!(fact.get_property("Subject"), None); // case-sensitive
}

#[test]
fn chain_element_identity_unknown_property_returns_none() {
    let fact = X509ChainElementIdentityFact {
        index: 0,
        certificate_thumbprint: Arc::from("t"),
        subject: Arc::from("s"),
        issuer: Arc::from("i"),
    };

    assert_eq!(fact.get_property("nonexistent"), None);
    assert_eq!(fact.get_property(""), None);
}

#[test]
fn chain_element_validity_unknown_property_returns_none() {
    let fact = X509ChainElementValidityFact {
        index: 0,
        not_before_unix_seconds: 0,
        not_after_unix_seconds: 0,
    };

    assert_eq!(fact.get_property("nonexistent"), None);
    assert_eq!(fact.get_property(""), None);
}

#[test]
fn chain_trusted_unknown_property_returns_none() {
    let fact = X509ChainTrustedFact {
        chain_built: false,
        is_trusted: false,
        status_flags: 0,
        status_summary: Some(Arc::from("summary")),
        element_count: 0,
    };

    assert_eq!(fact.get_property("nonexistent"), None);
    assert_eq!(fact.get_property(""), None);
}

#[test]
fn public_key_algorithm_unknown_property_returns_none() {
    let fact = X509PublicKeyAlgorithmFact {
        certificate_thumbprint: Arc::from("t"),
        algorithm_oid: Arc::from("1.2.3"),
        algorithm_name: Some(Arc::from("name")),
        is_pqc: false,
    };

    assert_eq!(fact.get_property("nonexistent"), None);
    assert_eq!(fact.get_property(""), None);
}

// ---------------------------------------------------------------------------
// X509ChainElementIdentityFact – all valid property branches
// ---------------------------------------------------------------------------

#[test]
fn chain_element_identity_all_valid_properties() {
    let fact = X509ChainElementIdentityFact {
        index: 7,
        certificate_thumbprint: Arc::from("thumb123"),
        subject: Arc::from("CN=Test"),
        issuer: Arc::from("CN=Issuer"),
    };

    assert_eq!(
        fact.get_property(fields::x509_chain_element_identity::INDEX),
        Some(FactValue::Usize(7))
    );
    assert!(matches!(
        fact.get_property(fields::x509_chain_element_identity::CERTIFICATE_THUMBPRINT),
        Some(FactValue::Str(s)) if s.as_ref() == "thumb123"
    ));
    assert!(matches!(
        fact.get_property(fields::x509_chain_element_identity::SUBJECT),
        Some(FactValue::Str(s)) if s.as_ref() == "CN=Test"
    ));
    assert!(matches!(
        fact.get_property(fields::x509_chain_element_identity::ISSUER),
        Some(FactValue::Str(s)) if s.as_ref() == "CN=Issuer"
    ));
}

// ---------------------------------------------------------------------------
// X509ChainElementValidityFact – all valid property branches
// ---------------------------------------------------------------------------

#[test]
fn chain_element_validity_all_valid_properties() {
    let fact = X509ChainElementValidityFact {
        index: 2,
        not_before_unix_seconds: 1_700_000_000,
        not_after_unix_seconds: 1_800_000_000,
    };

    assert_eq!(
        fact.get_property(fields::x509_chain_element_validity::INDEX),
        Some(FactValue::Usize(2))
    );
    assert_eq!(
        fact.get_property(fields::x509_chain_element_validity::NOT_BEFORE_UNIX_SECONDS),
        Some(FactValue::I64(1_700_000_000))
    );
    assert_eq!(
        fact.get_property(fields::x509_chain_element_validity::NOT_AFTER_UNIX_SECONDS),
        Some(FactValue::I64(1_800_000_000))
    );
}

// ---------------------------------------------------------------------------
// X509ChainTrustedFact – all valid property branches
// ---------------------------------------------------------------------------

#[test]
fn chain_trusted_all_valid_properties_with_summary() {
    let fact = X509ChainTrustedFact {
        chain_built: false,
        is_trusted: true,
        status_flags: 42,
        status_summary: Some(Arc::from("all good")),
        element_count: 5,
    };

    assert_eq!(
        fact.get_property(fields::x509_chain_trusted::CHAIN_BUILT),
        Some(FactValue::Bool(false))
    );
    assert_eq!(
        fact.get_property(fields::x509_chain_trusted::IS_TRUSTED),
        Some(FactValue::Bool(true))
    );
    assert_eq!(
        fact.get_property(fields::x509_chain_trusted::STATUS_FLAGS),
        Some(FactValue::U32(42))
    );
    assert_eq!(
        fact.get_property(fields::x509_chain_trusted::ELEMENT_COUNT),
        Some(FactValue::Usize(5))
    );
    assert!(matches!(
        fact.get_property(fields::x509_chain_trusted::STATUS_SUMMARY),
        Some(FactValue::Str(s)) if s.as_ref() == "all good"
    ));
}

// ---------------------------------------------------------------------------
// X509PublicKeyAlgorithmFact – all valid property branches
// ---------------------------------------------------------------------------

#[test]
fn public_key_algorithm_all_valid_properties() {
    let fact = X509PublicKeyAlgorithmFact {
        certificate_thumbprint: Arc::from("tp"),
        algorithm_oid: Arc::from("1.3.6.1.4.1.2.267.7.6.5"),
        algorithm_name: Some(Arc::from("ML-DSA-65")),
        is_pqc: true,
    };

    assert!(matches!(
        fact.get_property(fields::x509_public_key_algorithm::CERTIFICATE_THUMBPRINT),
        Some(FactValue::Str(s)) if s.as_ref() == "tp"
    ));
    assert!(matches!(
        fact.get_property(fields::x509_public_key_algorithm::ALGORITHM_OID),
        Some(FactValue::Str(s)) if s.as_ref() == "1.3.6.1.4.1.2.267.7.6.5"
    ));
    assert!(matches!(
        fact.get_property(fields::x509_public_key_algorithm::ALGORITHM_NAME),
        Some(FactValue::Str(s)) if s.as_ref() == "ML-DSA-65"
    ));
    assert_eq!(
        fact.get_property(fields::x509_public_key_algorithm::IS_PQC),
        Some(FactValue::Bool(true))
    );
}
