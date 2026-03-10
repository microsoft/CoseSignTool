// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Expanded test coverage for the Azure Trusted Signing crate.
//!
//! Focuses on testable pure logic: error Display/Debug, options construction,
//! fact property access, trust pack trait implementation, and ATS fact producer.

use std::borrow::Cow;
use std::sync::Arc;

use cose_sign1_azure_trusted_signing::error::AtsError;
use cose_sign1_azure_trusted_signing::options::AzureTrustedSigningOptions;
use cose_sign1_azure_trusted_signing::validation::facts::{
    AtsComplianceFact, AtsSigningServiceIdentifiedFact,
};
use cose_sign1_validation_primitives::fact_properties::{FactProperties, FactValue};

// ============================================================================
// Error Display and Debug coverage for all variants
// ============================================================================

#[test]
fn error_display_certificate_fetch_failed() {
    let e = AtsError::CertificateFetchFailed("timeout after 30s".to_string());
    let msg = format!("{}", e);
    assert!(msg.contains("ATS certificate fetch failed"));
    assert!(msg.contains("timeout after 30s"));
}

#[test]
fn error_display_signing_failed() {
    let e = AtsError::SigningFailed("HSM unavailable".to_string());
    let msg = format!("{}", e);
    assert!(msg.contains("ATS signing failed"));
    assert!(msg.contains("HSM unavailable"));
}

#[test]
fn error_display_invalid_configuration() {
    let e = AtsError::InvalidConfiguration("endpoint is empty".to_string());
    let msg = format!("{}", e);
    assert!(msg.contains("ATS invalid configuration"));
    assert!(msg.contains("endpoint is empty"));
}

#[test]
fn error_display_did_x509_error() {
    let e = AtsError::DidX509Error("chain too short".to_string());
    let msg = format!("{}", e);
    assert!(msg.contains("ATS DID:x509 error"));
    assert!(msg.contains("chain too short"));
}

#[test]
fn error_debug_all_variants() {
    let variants: Vec<AtsError> = vec![
        AtsError::CertificateFetchFailed("msg1".into()),
        AtsError::SigningFailed("msg2".into()),
        AtsError::InvalidConfiguration("msg3".into()),
        AtsError::DidX509Error("msg4".into()),
    ];
    for e in &variants {
        let debug = format!("{:?}", e);
        assert!(!debug.is_empty());
    }
}

#[test]
fn error_implements_std_error() {
    let e = AtsError::SigningFailed("test".to_string());
    let std_err: &dyn std::error::Error = &e;
    assert!(!std_err.to_string().is_empty());
    assert!(std_err.source().is_none());
}

#[test]
fn error_display_empty_message() {
    let e = AtsError::CertificateFetchFailed(String::new());
    let msg = format!("{}", e);
    assert!(msg.contains("ATS certificate fetch failed: "));
}

#[test]
fn error_display_unicode_message() {
    let e = AtsError::SigningFailed("签名失败 🔐".to_string());
    let msg = format!("{}", e);
    assert!(msg.contains("签名失败"));
}

// ============================================================================
// Options struct construction, Clone, Debug
// ============================================================================

#[test]
fn options_construction_and_field_access() {
    let opts = AzureTrustedSigningOptions {
        endpoint: "https://eus.codesigning.azure.net".to_string(),
        account_name: "my-account".to_string(),
        certificate_profile_name: "my-profile".to_string(),
    };
    assert_eq!(opts.endpoint, "https://eus.codesigning.azure.net");
    assert_eq!(opts.account_name, "my-account");
    assert_eq!(opts.certificate_profile_name, "my-profile");
}

#[test]
fn options_clone() {
    let opts = AzureTrustedSigningOptions {
        endpoint: "https://wus.codesigning.azure.net".to_string(),
        account_name: "acct".to_string(),
        certificate_profile_name: "profile".to_string(),
    };
    let cloned = opts.clone();
    assert_eq!(cloned.endpoint, opts.endpoint);
    assert_eq!(cloned.account_name, opts.account_name);
    assert_eq!(cloned.certificate_profile_name, opts.certificate_profile_name);
}

#[test]
fn options_debug() {
    let opts = AzureTrustedSigningOptions {
        endpoint: "https://eus.codesigning.azure.net".to_string(),
        account_name: "acct".to_string(),
        certificate_profile_name: "prof".to_string(),
    };
    let debug = format!("{:?}", opts);
    assert!(debug.contains("AzureTrustedSigningOptions"));
    assert!(debug.contains("eus.codesigning.azure.net"));
}

#[test]
fn options_empty_fields() {
    let opts = AzureTrustedSigningOptions {
        endpoint: String::new(),
        account_name: String::new(),
        certificate_profile_name: String::new(),
    };
    assert!(opts.endpoint.is_empty());
    assert!(opts.account_name.is_empty());
    assert!(opts.certificate_profile_name.is_empty());
}

// ============================================================================
// AtsSigningServiceIdentifiedFact
// ============================================================================

#[test]
fn ats_identified_fact_is_ats_issued_true() {
    let fact = AtsSigningServiceIdentifiedFact {
        is_ats_issued: true,
        issuer_cn: Some("Microsoft Code Signing PCA 2010".to_string()),
        eku_oids: vec!["1.3.6.1.5.5.7.3.3".to_string()],
    };
    match fact.get_property("is_ats_issued") {
        Some(FactValue::Bool(v)) => assert!(v),
        _ => panic!("expected Bool(true)"),
    }
}

#[test]
fn ats_identified_fact_is_ats_issued_false() {
    let fact = AtsSigningServiceIdentifiedFact {
        is_ats_issued: false,
        issuer_cn: None,
        eku_oids: Vec::new(),
    };
    match fact.get_property("is_ats_issued") {
        Some(FactValue::Bool(v)) => assert!(!v),
        _ => panic!("expected Bool(false)"),
    }
}

#[test]
fn ats_identified_fact_issuer_cn_some() {
    let fact = AtsSigningServiceIdentifiedFact {
        is_ats_issued: true,
        issuer_cn: Some("Test Issuer CN".to_string()),
        eku_oids: Vec::new(),
    };
    match fact.get_property("issuer_cn") {
        Some(FactValue::Str(Cow::Borrowed(s))) => assert_eq!(s, "Test Issuer CN"),
        _ => panic!("expected Str with issuer_cn"),
    }
}

#[test]
fn ats_identified_fact_issuer_cn_none() {
    let fact = AtsSigningServiceIdentifiedFact {
        is_ats_issued: false,
        issuer_cn: None,
        eku_oids: Vec::new(),
    };
    assert!(fact.get_property("issuer_cn").is_none());
}

#[test]
fn ats_identified_fact_unknown_property() {
    let fact = AtsSigningServiceIdentifiedFact {
        is_ats_issued: false,
        issuer_cn: None,
        eku_oids: Vec::new(),
    };
    assert!(fact.get_property("nonexistent").is_none());
    assert!(fact.get_property("eku_oids").is_none());
    assert!(fact.get_property("").is_none());
}

#[test]
fn ats_identified_fact_debug() {
    let fact = AtsSigningServiceIdentifiedFact {
        is_ats_issued: true,
        issuer_cn: Some("CN".to_string()),
        eku_oids: vec!["1.2.3".to_string(), "4.5.6".to_string()],
    };
    let debug = format!("{:?}", fact);
    assert!(debug.contains("AtsSigningServiceIdentifiedFact"));
}

#[test]
fn ats_identified_fact_clone() {
    let fact = AtsSigningServiceIdentifiedFact {
        is_ats_issued: true,
        issuer_cn: Some("CN".to_string()),
        eku_oids: vec!["1.2.3".to_string()],
    };
    let cloned = fact.clone();
    assert_eq!(cloned.is_ats_issued, fact.is_ats_issued);
    assert_eq!(cloned.issuer_cn, fact.issuer_cn);
    assert_eq!(cloned.eku_oids, fact.eku_oids);
}

// ============================================================================
// AtsComplianceFact
// ============================================================================

#[test]
fn ats_compliance_fact_fips_level() {
    let fact = AtsComplianceFact {
        fips_level: "FIPS 140-2 Level 3".to_string(),
        scitt_compliant: true,
    };
    match fact.get_property("fips_level") {
        Some(FactValue::Str(Cow::Borrowed(s))) => assert_eq!(s, "FIPS 140-2 Level 3"),
        _ => panic!("expected Str"),
    }
}

#[test]
fn ats_compliance_fact_scitt_compliant_true() {
    let fact = AtsComplianceFact {
        fips_level: "unknown".to_string(),
        scitt_compliant: true,
    };
    match fact.get_property("scitt_compliant") {
        Some(FactValue::Bool(v)) => assert!(v),
        _ => panic!("expected Bool(true)"),
    }
}

#[test]
fn ats_compliance_fact_scitt_compliant_false() {
    let fact = AtsComplianceFact {
        fips_level: "none".to_string(),
        scitt_compliant: false,
    };
    match fact.get_property("scitt_compliant") {
        Some(FactValue::Bool(v)) => assert!(!v),
        _ => panic!("expected Bool(false)"),
    }
}

#[test]
fn ats_compliance_fact_unknown_property() {
    let fact = AtsComplianceFact {
        fips_level: "L3".to_string(),
        scitt_compliant: true,
    };
    assert!(fact.get_property("unknown_field").is_none());
    assert!(fact.get_property("").is_none());
    assert!(fact.get_property("fips").is_none());
}

#[test]
fn ats_compliance_fact_debug() {
    let fact = AtsComplianceFact {
        fips_level: "L2".to_string(),
        scitt_compliant: false,
    };
    let debug = format!("{:?}", fact);
    assert!(debug.contains("AtsComplianceFact"));
    assert!(debug.contains("L2"));
}

#[test]
fn ats_compliance_fact_clone() {
    let fact = AtsComplianceFact {
        fips_level: "L3".to_string(),
        scitt_compliant: true,
    };
    let cloned = fact.clone();
    assert_eq!(cloned.fips_level, fact.fips_level);
    assert_eq!(cloned.scitt_compliant, fact.scitt_compliant);
}

#[test]
fn ats_compliance_fact_empty_fips_level() {
    let fact = AtsComplianceFact {
        fips_level: String::new(),
        scitt_compliant: false,
    };
    match fact.get_property("fips_level") {
        Some(FactValue::Str(Cow::Borrowed(s))) => assert_eq!(s, ""),
        _ => panic!("expected empty Str"),
    }
}

// ============================================================================
// AtsFactProducer and AzureTrustedSigningTrustPack
// ============================================================================

#[test]
fn ats_trust_pack_name() {
    use cose_sign1_validation::fluent::CoseSign1TrustPack;
    let pack = cose_sign1_azure_trusted_signing::validation::AzureTrustedSigningTrustPack::new();
    assert_eq!(pack.name(), "azure_trusted_signing");
}

#[test]
fn ats_trust_pack_no_default_plan() {
    use cose_sign1_validation::fluent::CoseSign1TrustPack;
    let pack = cose_sign1_azure_trusted_signing::validation::AzureTrustedSigningTrustPack::new();
    assert!(pack.default_trust_plan().is_none());
}

#[test]
fn ats_trust_pack_no_key_resolvers() {
    use cose_sign1_validation::fluent::CoseSign1TrustPack;
    let pack = cose_sign1_azure_trusted_signing::validation::AzureTrustedSigningTrustPack::new();
    assert!(pack.cose_key_resolvers().is_empty());
}

#[test]
fn ats_trust_pack_no_post_signature_validators() {
    use cose_sign1_validation::fluent::CoseSign1TrustPack;
    let pack = cose_sign1_azure_trusted_signing::validation::AzureTrustedSigningTrustPack::new();
    assert!(pack.post_signature_validators().is_empty());
}

#[test]
fn ats_trust_pack_fact_producer_name() {
    use cose_sign1_validation::fluent::CoseSign1TrustPack;
    use cose_sign1_validation_primitives::facts::TrustFactProducer;
    let pack = cose_sign1_azure_trusted_signing::validation::AzureTrustedSigningTrustPack::new();
    let producer = pack.fact_producer();
    assert_eq!(producer.name(), "azure_trusted_signing");
}

#[test]
fn ats_fact_producer_provides_empty() {
    use cose_sign1_validation_primitives::facts::TrustFactProducer;
    let producer = cose_sign1_azure_trusted_signing::validation::AtsFactProducer;
    assert!(producer.provides().is_empty());
}

#[test]
fn ats_fact_producer_name() {
    use cose_sign1_validation_primitives::facts::TrustFactProducer;
    let producer = cose_sign1_azure_trusted_signing::validation::AtsFactProducer;
    assert_eq!(producer.name(), "azure_trusted_signing");
}

// ============================================================================
// Multiple fact combinations
// ============================================================================

#[test]
fn identified_fact_many_eku_oids() {
    let fact = AtsSigningServiceIdentifiedFact {
        is_ats_issued: true,
        issuer_cn: Some("Microsoft Code Signing".to_string()),
        eku_oids: vec![
            "1.3.6.1.5.5.7.3.3".to_string(),
            "1.3.6.1.4.1.311.10.3.13".to_string(),
            "1.3.6.1.4.1.311.10.3.13.5".to_string(),
        ],
    };
    assert_eq!(fact.eku_oids.len(), 3);
    match fact.get_property("is_ats_issued") {
        Some(FactValue::Bool(true)) => {}
        _ => panic!("expected true"),
    }
}

#[test]
fn compliance_fact_unicode_fips_level() {
    let fact = AtsComplianceFact {
        fips_level: "Level 3 ✓".to_string(),
        scitt_compliant: true,
    };
    match fact.get_property("fips_level") {
        Some(FactValue::Str(Cow::Borrowed(s))) => assert!(s.contains("✓")),
        _ => panic!("expected unicode fips_level"),
    }
}

#[test]
fn compliance_fact_long_fips_level() {
    let long_val = "a".repeat(10000);
    let fact = AtsComplianceFact {
        fips_level: long_val.clone(),
        scitt_compliant: false,
    };
    match fact.get_property("fips_level") {
        Some(FactValue::Str(Cow::Borrowed(s))) => assert_eq!(s.len(), 10000),
        _ => panic!("expected long Str"),
    }
}
