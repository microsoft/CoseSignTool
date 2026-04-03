// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use cose_sign1_azure_artifact_signing::validation::facts::{
    AasComplianceFact, AasSigningServiceIdentifiedFact,
};
use cose_sign1_validation_primitives::fact_properties::{FactProperties, FactValue};

#[test]
fn test_ats_signing_service_identified_fact_properties() {
    let fact = AasSigningServiceIdentifiedFact {
        is_ats_issued: true,
        issuer_cn: Some("Microsoft Artifact Signing CA".to_string()),
        eku_oids: vec!["1.3.6.1.4.1.311.10.3.13".to_string()],
    };

    // Test is_ats_issued property
    if let Some(FactValue::Bool(value)) = fact.get_property("is_ats_issued") {
        assert_eq!(value, true);
    } else {
        panic!("Expected Bool value for is_ats_issued");
    }

    // Test issuer_cn property
    if let Some(FactValue::Str(value)) = fact.get_property("issuer_cn") {
        assert_eq!(value, "Microsoft Artifact Signing CA");
    } else {
        panic!("Expected Str value for issuer_cn");
    }

    // Test non-existent property
    assert!(fact.get_property("nonexistent").is_none());
}

#[test]
fn test_ats_signing_service_identified_fact_properties_none_issuer() {
    let fact = AasSigningServiceIdentifiedFact {
        is_ats_issued: false,
        issuer_cn: None,
        eku_oids: vec![],
    };

    // Test is_ats_issued property
    if let Some(FactValue::Bool(value)) = fact.get_property("is_ats_issued") {
        assert_eq!(value, false);
    } else {
        panic!("Expected Bool value for is_ats_issued");
    }

    // Test issuer_cn property when None
    assert!(fact.get_property("issuer_cn").is_none());
}

#[test]
fn test_ats_compliance_fact_properties() {
    let fact = AasComplianceFact {
        fips_level: "FIPS 140-2 Level 3".to_string(),
        scitt_compliant: true,
    };

    // Test fips_level property
    if let Some(FactValue::Str(value)) = fact.get_property("fips_level") {
        assert_eq!(value, "FIPS 140-2 Level 3");
    } else {
        panic!("Expected Str value for fips_level");
    }

    // Test scitt_compliant property
    if let Some(FactValue::Bool(value)) = fact.get_property("scitt_compliant") {
        assert_eq!(value, true);
    } else {
        panic!("Expected Bool value for scitt_compliant");
    }

    // Test non-existent property
    assert!(fact.get_property("nonexistent").is_none());
}

#[test]
fn test_ats_compliance_fact_debug_and_clone() {
    let fact = AasComplianceFact {
        fips_level: "unknown".to_string(),
        scitt_compliant: false,
    };

    // Test Debug trait
    let debug_str = format!("{:?}", fact);
    assert!(debug_str.contains("AasComplianceFact"));
    assert!(debug_str.contains("unknown"));
    assert!(debug_str.contains("false"));

    // Test Clone trait
    let cloned = fact.clone();
    assert_eq!(cloned.fips_level, fact.fips_level);
    assert_eq!(cloned.scitt_compliant, fact.scitt_compliant);
}

#[test]
fn test_ats_signing_service_identified_fact_debug_and_clone() {
    let fact = AasSigningServiceIdentifiedFact {
        is_ats_issued: true,
        issuer_cn: Some("Test CA".to_string()),
        eku_oids: vec!["1.2.3.4".to_string(), "5.6.7.8".to_string()],
    };

    // Test Debug trait
    let debug_str = format!("{:?}", fact);
    assert!(debug_str.contains("AasSigningServiceIdentifiedFact"));
    assert!(debug_str.contains("Test CA"));
    assert!(debug_str.contains("1.2.3.4"));

    // Test Clone trait
    let cloned = fact.clone();
    assert_eq!(cloned.is_ats_issued, fact.is_ats_issued);
    assert_eq!(cloned.issuer_cn, fact.issuer_cn);
    assert_eq!(cloned.eku_oids, fact.eku_oids);
}
