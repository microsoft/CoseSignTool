// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Deep coverage tests for Azure Artifact Signing extension pack.
//!
//! Targets testable lines that don't require Azure credentials:
//! - AasError Display variants
//! - AasError std::error::Error impl
//! - AzureArtifactSigningOptions Debug/Clone
//! - AzureArtifactSigningTrustPack trait methods
//! - AasFactProducer name + provides
//! - AasSigningServiceIdentifiedFact / AasComplianceFact FactProperties

extern crate cbor_primitives_everparse;

use cose_sign1_azure_artifact_signing::error::AasError;
use cose_sign1_azure_artifact_signing::options::AzureArtifactSigningOptions;
use cose_sign1_azure_artifact_signing::validation::facts::{
    AasComplianceFact, AasSigningServiceIdentifiedFact,
};
use cose_sign1_azure_artifact_signing::validation::{
    AasFactProducer, AzureArtifactSigningTrustPack,
};
use cose_sign1_validation::fluent::CoseSign1TrustPack;
use cose_sign1_validation_primitives::fact_properties::FactProperties;
use cose_sign1_validation_primitives::facts::TrustFactProducer;

// =========================================================================
// AasError Display coverage
// =========================================================================

#[test]
fn aas_error_display_certificate_fetch_failed() {
    let e = AasError::CertificateFetchFailed("timeout".to_string());
    let s = format!("{}", e);
    assert!(s.contains("AAS certificate fetch failed"));
    assert!(s.contains("timeout"));
}

#[test]
fn aas_error_display_signing_failed() {
    let e = AasError::SigningFailed("key not found".to_string());
    let s = format!("{}", e);
    assert!(s.contains("AAS signing failed"));
    assert!(s.contains("key not found"));
}

#[test]
fn aas_error_display_invalid_configuration() {
    let e = AasError::InvalidConfiguration("missing endpoint".to_string());
    let s = format!("{}", e);
    assert!(s.contains("AAS invalid configuration"));
    assert!(s.contains("missing endpoint"));
}

#[test]
fn aas_error_display_did_x509_error() {
    let e = AasError::DidX509Error("bad chain".to_string());
    let s = format!("{}", e);
    assert!(s.contains("AAS DID:x509 error"));
    assert!(s.contains("bad chain"));
}

#[test]
fn aas_error_is_std_error() {
    let e: Box<dyn std::error::Error> =
        Box::new(AasError::SigningFailed("test".to_string()));
    assert!(e.to_string().contains("AAS signing failed"));
}

#[test]
fn aas_error_debug() {
    let e = AasError::CertificateFetchFailed("debug test".to_string());
    let debug = format!("{:?}", e);
    assert!(debug.contains("CertificateFetchFailed"));
}

// =========================================================================
// AzureArtifactSigningOptions coverage
// =========================================================================

#[test]
fn options_debug_and_clone() {
    let opts = AzureArtifactSigningOptions {
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
// AasFactProducer coverage
// =========================================================================

#[test]
fn aas_fact_producer_name() {
    let producer = AasFactProducer;
    assert_eq!(producer.name(), "azure_artifact_signing");
}

#[test]
fn aas_fact_producer_provides() {
    let producer = AasFactProducer;
    let keys = producer.provides();
    // Now returns the registered fact keys
    assert_eq!(keys.len(), 2);
}

// =========================================================================
// AzureArtifactSigningTrustPack coverage
// =========================================================================

#[test]
fn trust_pack_name() {
    let pack = AzureArtifactSigningTrustPack::new();
    assert_eq!(pack.name(), "azure_artifact_signing");
}

#[test]
fn trust_pack_fact_producer() {
    let pack = AzureArtifactSigningTrustPack::new();
    let producer = pack.fact_producer();
    assert_eq!(producer.name(), "azure_artifact_signing");
}

#[test]
fn trust_pack_cose_key_resolvers_empty() {
    let pack = AzureArtifactSigningTrustPack::new();
    let resolvers = pack.cose_key_resolvers();
    assert!(resolvers.is_empty());
}

#[test]
fn trust_pack_post_signature_validators_empty() {
    let pack = AzureArtifactSigningTrustPack::new();
    let validators = pack.post_signature_validators();
    assert!(validators.is_empty());
}

#[test]
fn trust_pack_default_plan_none() {
    let pack = AzureArtifactSigningTrustPack::new();
    assert!(pack.default_trust_plan().is_none());
}

// =========================================================================
// AasSigningServiceIdentifiedFact FactProperties coverage
// =========================================================================

#[test]
fn aas_signing_fact_is_ats_issued() {
    let fact = AasSigningServiceIdentifiedFact {
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
fn aas_signing_fact_issuer_cn() {
    let fact = AasSigningServiceIdentifiedFact {
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
fn aas_signing_fact_issuer_cn_none() {
    let fact = AasSigningServiceIdentifiedFact {
        is_ats_issued: false,
        issuer_cn: None,
        eku_oids: vec![],
    };

    assert!(fact.get_property("issuer_cn").is_none());
}

#[test]
fn aas_signing_fact_unknown_property() {
    let fact = AasSigningServiceIdentifiedFact {
        is_ats_issued: false,
        issuer_cn: None,
        eku_oids: vec![],
    };

    assert!(fact.get_property("nonexistent").is_none());
}

#[test]
fn aas_signing_fact_debug_clone() {
    let fact = AasSigningServiceIdentifiedFact {
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
// AasComplianceFact FactProperties coverage
// =========================================================================

#[test]
fn compliance_fact_fips_level() {
    let fact = AasComplianceFact {
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
    let fact = AasComplianceFact {
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
    let fact = AasComplianceFact {
        fips_level: "unknown".to_string(),
        scitt_compliant: false,
    };

    assert!(fact.get_property("nonexistent").is_none());
}

#[test]
fn compliance_fact_debug_clone() {
    let fact = AasComplianceFact {
        fips_level: "Level 2".to_string(),
        scitt_compliant: true,
    };
    let debug = format!("{:?}", fact);
    assert!(debug.contains("fips_level"));
    let cloned = fact.clone();
    assert_eq!(cloned.fips_level, fact.fips_level);
}
