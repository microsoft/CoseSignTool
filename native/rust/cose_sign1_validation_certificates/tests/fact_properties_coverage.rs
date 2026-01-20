// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use cose_sign1_validation_certificates::facts::{
    fields, X509ChainElementIdentityFact, X509ChainElementValidityFact, X509ChainTrustedFact,
    X509PublicKeyAlgorithmFact, X509SigningCertificateIdentityFact,
};
use cose_sign1_validation_trust::fact_properties::{FactProperties, FactValue};

#[test]
fn certificate_fact_properties_expose_expected_fields() {
    let signing = X509SigningCertificateIdentityFact {
        certificate_thumbprint: "thumb".to_string(),
        subject: "subj".to_string(),
        issuer: "iss".to_string(),
        serial_number: "serial".to_string(),
        not_before_unix_seconds: 1,
        not_after_unix_seconds: 2,
    };

    assert!(matches!(
        signing.get_property(fields::x509_signing_certificate_identity::CERTIFICATE_THUMBPRINT),
        Some(FactValue::Str(s)) if s.as_ref() == "thumb"
    ));
    assert!(matches!(
        signing.get_property(fields::x509_signing_certificate_identity::SUBJECT),
        Some(FactValue::Str(s)) if s.as_ref() == "subj"
    ));
    assert!(matches!(
        signing.get_property(fields::x509_signing_certificate_identity::ISSUER),
        Some(FactValue::Str(s)) if s.as_ref() == "iss"
    ));
    assert!(matches!(
        signing.get_property(fields::x509_signing_certificate_identity::SERIAL_NUMBER),
        Some(FactValue::Str(s)) if s.as_ref() == "serial"
    ));
    assert_eq!(
        signing.get_property(fields::x509_signing_certificate_identity::NOT_BEFORE_UNIX_SECONDS),
        Some(FactValue::I64(1))
    );
    assert_eq!(
        signing.get_property(fields::x509_signing_certificate_identity::NOT_AFTER_UNIX_SECONDS),
        Some(FactValue::I64(2))
    );
    assert_eq!(signing.get_property("unknown"), None);

    let chain_id = X509ChainElementIdentityFact {
        index: 3,
        certificate_thumbprint: "t".to_string(),
        subject: "s".to_string(),
        issuer: "i".to_string(),
    };

    assert_eq!(
        chain_id.get_property(fields::x509_chain_element_identity::INDEX),
        Some(FactValue::Usize(3))
    );
    assert!(matches!(
        chain_id.get_property(fields::x509_chain_element_identity::CERTIFICATE_THUMBPRINT),
        Some(FactValue::Str(s)) if s.as_ref() == "t"
    ));

    let validity = X509ChainElementValidityFact {
        index: 4,
        not_before_unix_seconds: 10,
        not_after_unix_seconds: 11,
    };

    assert_eq!(
        validity.get_property(fields::x509_chain_element_validity::INDEX),
        Some(FactValue::Usize(4))
    );

    let trusted = X509ChainTrustedFact {
        chain_built: true,
        is_trusted: false,
        status_flags: 123,
        status_summary: Some("ok".to_string()),
        element_count: 2,
    };

    assert_eq!(
        trusted.get_property(fields::x509_chain_trusted::CHAIN_BUILT),
        Some(FactValue::Bool(true))
    );
    assert_eq!(
        trusted.get_property(fields::x509_chain_trusted::IS_TRUSTED),
        Some(FactValue::Bool(false))
    );
    assert_eq!(
        trusted.get_property(fields::x509_chain_trusted::STATUS_FLAGS),
        Some(FactValue::U32(123))
    );
    assert_eq!(
        trusted.get_property(fields::x509_chain_trusted::ELEMENT_COUNT),
        Some(FactValue::Usize(2))
    );
    assert!(matches!(
        trusted.get_property(fields::x509_chain_trusted::STATUS_SUMMARY),
        Some(FactValue::Str(s)) if s.as_ref() == "ok"
    ));

    let alg = X509PublicKeyAlgorithmFact {
        certificate_thumbprint: "t".to_string(),
        algorithm_oid: "1.2.3".to_string(),
        algorithm_name: None,
        is_pqc: true,
    };

    assert!(matches!(
        alg.get_property(fields::x509_public_key_algorithm::CERTIFICATE_THUMBPRINT),
        Some(FactValue::Str(s)) if s.as_ref() == "t"
    ));
    assert!(matches!(
        alg.get_property(fields::x509_public_key_algorithm::ALGORITHM_OID),
        Some(FactValue::Str(s)) if s.as_ref() == "1.2.3"
    ));
    assert_eq!(
        alg.get_property(fields::x509_public_key_algorithm::IS_PQC),
        Some(FactValue::Bool(true))
    );
}
