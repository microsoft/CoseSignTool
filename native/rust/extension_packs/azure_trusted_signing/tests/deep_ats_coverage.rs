// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Deep coverage tests for Azure Trusted Signing extension pack.
//!
//! Targets testable lines that don't require Azure credentials:
//! - AtsError Display variants
//! - AtsError std::error::Error impl
//! - AzureTrustedSigningOptions Debug/Clone
//! - AzureTrustedSigningTrustPack trait methods
//! - AtsFactProducer name + provides
//! - AtsSigningServiceIdentifiedFact / AtsComplianceFact FactProperties

extern crate cbor_primitives_everparse;

use cose_sign1_azure_trusted_signing::error::AtsError;
use cose_sign1_azure_trusted_signing::options::AzureTrustedSigningOptions;
use cose_sign1_azure_trusted_signing::validation::facts::{
    AtsComplianceFact, AtsSigningServiceIdentifiedFact,
};
use cose_sign1_azure_trusted_signing::validation::{
    AtsFactProducer, AzureTrustedSigningTrustPack,
};
use cose_sign1_validation::fluent::CoseSign1TrustPack;
use cose_sign1_validation_primitives::fact_properties::FactProperties;
use cose_sign1_validation_primitives::facts::TrustFactProducer;

// =========================================================================
// AtsError Display coverage
// =========================================================================

#[test]
fn ats_error_display_certificate_fetch_failed() {
    let e = AtsError::CertificateFetchFailed("timeout".to_string());
    let s = format!("{}", e);
    assert!(s.contains("ATS certificate fetch failed"));
    assert!(s.contains("timeout"));
}

#[test]
fn ats_error_display_signing_failed() {
    let e = AtsError::SigningFailed("key not found".to_string());
    let s = format!("{}", e);
    assert!(s.contains("ATS signing failed"));
    assert!(s.contains("key not found"));
}

#[test]
fn ats_error_display_invalid_configuration() {
    let e = AtsError::InvalidConfiguration("missing endpoint".to_string());
    let s = format!("{}", e);
    assert!(s.contains("ATS invalid configuration"));
    assert!(s.contains("missing endpoint"));
}

#[test]
fn ats_error_display_did_x509_error() {
    let e = AtsError::DidX509Error("bad chain".to_string());
    let s = format!("{}", e);
    assert!(s.contains("ATS DID:x509 error"));
    assert!(s.contains("bad chain"));
}

#[test]
fn ats_error_is_std_error() {
    let e: Box<dyn std::error::Error> =
        Box::new(AtsError::SigningFailed("test".to_string()));
    assert!(e.to_string().contains("ATS signing failed"));
}

#[test]
fn ats_error_debug() {
    let e = AtsError::CertificateFetchFailed("debug test".to_string());
    let debug = format!("{:?}", e);
    assert!(debug.contains("CertificateFetchFailed"));
}

// =========================================================================
// AzureTrustedSigningOptions coverage
// =========================================================================

#[test]
fn options_debug_and_clone() {
    let opts = AzureTrustedSigningOptions {
        endpoint: "https://eus.codesigning.azure.net".to_string(),
        account_name: "my-account".to_string(),
        certificate_profile_name: "my-profile".to_string(),
    };
    let debug = format!("{:?}", opts);
    assert!(debug.contains("my-account"));

    let cloned = opts.clone();
    assert_eq!(cloned.endpoint, opts.endpoint);
    assert_eq!(cloned.account_name, opts.account_name);
    assert_eq!(cloned.certificate_profile_name, opts.certificate_profile_name);
}

// =========================================================================
// AtsFactProducer coverage
// =========================================================================

#[test]
fn ats_fact_producer_name() {
    let producer = AtsFactProducer;
    assert_eq!(producer.name(), "azure_trusted_signing");
}

#[test]
fn ats_fact_producer_provides() {
    let producer = AtsFactProducer;
    let keys = producer.provides();
    // Currently returns empty; just exercise the method
    assert!(keys.is_empty());
}

// =========================================================================
// AzureTrustedSigningTrustPack coverage
// =========================================================================

#[test]
fn trust_pack_name() {
    let pack = AzureTrustedSigningTrustPack::new();
    assert_eq!(pack.name(), "azure_trusted_signing");
}

#[test]
fn trust_pack_fact_producer() {
    let pack = AzureTrustedSigningTrustPack::new();
    let producer = pack.fact_producer();
    assert_eq!(producer.name(), "azure_trusted_signing");
}

#[test]
fn trust_pack_cose_key_resolvers_empty() {
    let pack = AzureTrustedSigningTrustPack::new();
    let resolvers = pack.cose_key_resolvers();
    assert!(resolvers.is_empty());
}

#[test]
fn trust_pack_post_signature_validators_empty() {
    let pack = AzureTrustedSigningTrustPack::new();
    let validators = pack.post_signature_validators();
    assert!(validators.is_empty());
}

#[test]
fn trust_pack_default_plan_none() {
    let pack = AzureTrustedSigningTrustPack::new();
    assert!(pack.default_trust_plan().is_none());
}

// =========================================================================
// AtsSigningServiceIdentifiedFact FactProperties coverage
// =========================================================================

#[test]
fn ats_signing_fact_is_ats_issued() {
    let fact = AtsSigningServiceIdentifiedFact {
        is_ats_issued: true,
        issuer_cn: Some("Test CN".to_string()),
        eku_oids: vec!["1.3.6.1.4.1.311.76.59.1.1".to_string()],
    };

    match fact.get_property("is_ats_issued") {
        Some(cose_sign1_validation_primitives::fact_properties::FactValue::Bool(b)) => {
            assert!(b);
        }
        other => panic!("Expected Bool, got {:?}", other),
    }
}

#[test]
fn ats_signing_fact_issuer_cn() {
    let fact = AtsSigningServiceIdentifiedFact {
        is_ats_issued: false,
        issuer_cn: Some("My Issuer".to_string()),
        eku_oids: vec![],
    };

    match fact.get_property("issuer_cn") {
        Some(cose_sign1_validation_primitives::fact_properties::FactValue::Str(s)) => {
            assert_eq!(s.as_ref(), "My Issuer");
        }
        other => panic!("Expected Str, got {:?}", other),
    }
}

#[test]
fn ats_signing_fact_issuer_cn_none() {
    let fact = AtsSigningServiceIdentifiedFact {
        is_ats_issued: false,
        issuer_cn: None,
        eku_oids: vec![],
    };

    assert!(fact.get_property("issuer_cn").is_none());
}

#[test]
fn ats_signing_fact_unknown_property() {
    let fact = AtsSigningServiceIdentifiedFact {
        is_ats_issued: false,
        issuer_cn: None,
        eku_oids: vec![],
    };

    assert!(fact.get_property("nonexistent").is_none());
}

#[test]
fn ats_signing_fact_debug_clone() {
    let fact = AtsSigningServiceIdentifiedFact {
        is_ats_issued: true,
        issuer_cn: Some("Test".to_string()),
        eku_oids: vec!["1.2.3".to_string()],
    };
    let debug = format!("{:?}", fact);
    assert!(debug.contains("is_ats_issued"));
    let cloned = fact.clone();
    assert_eq!(cloned.is_ats_issued, fact.is_ats_issued);
}

// =========================================================================
// AtsComplianceFact FactProperties coverage
// =========================================================================

#[test]
fn compliance_fact_fips_level() {
    let fact = AtsComplianceFact {
        fips_level: "Level 3".to_string(),
        scitt_compliant: true,
    };

    match fact.get_property("fips_level") {
        Some(cose_sign1_validation_primitives::fact_properties::FactValue::Str(s)) => {
            assert_eq!(s.as_ref(), "Level 3");
        }
        other => panic!("Expected Str, got {:?}", other),
    }
}

#[test]
fn compliance_fact_scitt_compliant() {
    let fact = AtsComplianceFact {
        fips_level: "unknown".to_string(),
        scitt_compliant: false,
    };

    match fact.get_property("scitt_compliant") {
        Some(cose_sign1_validation_primitives::fact_properties::FactValue::Bool(b)) => {
            assert!(!b);
        }
        other => panic!("Expected Bool, got {:?}", other),
    }
}

#[test]
fn compliance_fact_unknown_property() {
    let fact = AtsComplianceFact {
        fips_level: "unknown".to_string(),
        scitt_compliant: false,
    };

    assert!(fact.get_property("nonexistent").is_none());
}

#[test]
fn compliance_fact_debug_clone() {
    let fact = AtsComplianceFact {
        fips_level: "Level 2".to_string(),
        scitt_compliant: true,
    };
    let debug = format!("{:?}", fact);
    assert!(debug.contains("fips_level"));
    let cloned = fact.clone();
    assert_eq!(cloned.fips_level, fact.fips_level);
}
