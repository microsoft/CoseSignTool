// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Tests for constants module

use did_x509::constants::*;

#[test]
fn test_did_prefix_constants() {
    assert_eq!(DID_PREFIX, "did:x509");
    assert_eq!(FULL_DID_PREFIX, "did:x509:0");
    assert_eq!(VERSION, "0");
}

#[test]
fn test_separator_constants() {
    assert_eq!(POLICY_SEPARATOR, "::");
    assert_eq!(VALUE_SEPARATOR, ":");
}

#[test]
fn test_hash_algorithm_constants() {
    assert_eq!(HASH_ALGORITHM_SHA256, "sha256");
    assert_eq!(HASH_ALGORITHM_SHA384, "sha384");
    assert_eq!(HASH_ALGORITHM_SHA512, "sha512");
}

#[test]
fn test_policy_name_constants() {
    assert_eq!(POLICY_SUBJECT, "subject");
    assert_eq!(POLICY_SAN, "san");
    assert_eq!(POLICY_EKU, "eku");
    assert_eq!(POLICY_FULCIO_ISSUER, "fulcio-issuer");
}

#[test]
fn test_san_type_constants() {
    assert_eq!(SAN_TYPE_EMAIL, "email");
    assert_eq!(SAN_TYPE_DNS, "dns");
    assert_eq!(SAN_TYPE_URI, "uri");
    assert_eq!(SAN_TYPE_DN, "dn");
}

#[test]
fn test_oid_constants() {
    assert_eq!(OID_COMMON_NAME, "2.5.4.3");
    assert_eq!(OID_LOCALITY, "2.5.4.7");
    assert_eq!(OID_STATE, "2.5.4.8");
    assert_eq!(OID_ORGANIZATION, "2.5.4.10");
    assert_eq!(OID_ORGANIZATIONAL_UNIT, "2.5.4.11");
    assert_eq!(OID_COUNTRY, "2.5.4.6");
    assert_eq!(OID_STREET, "2.5.4.9");
    assert_eq!(OID_FULCIO_ISSUER, "1.3.6.1.4.1.57264.1.1");
    assert_eq!(OID_EXTENDED_KEY_USAGE, "2.5.29.37");
    assert_eq!(OID_SAN, "2.5.29.17");
    assert_eq!(OID_BASIC_CONSTRAINTS, "2.5.29.19");
}

#[test]
fn test_attribute_label_constants() {
    assert_eq!(ATTRIBUTE_CN, "CN");
    assert_eq!(ATTRIBUTE_L, "L");
    assert_eq!(ATTRIBUTE_ST, "ST");
    assert_eq!(ATTRIBUTE_O, "O");
    assert_eq!(ATTRIBUTE_OU, "OU");
    assert_eq!(ATTRIBUTE_C, "C");
    assert_eq!(ATTRIBUTE_STREET, "STREET");
}

#[test]
fn test_oid_to_attribute_label_mapping() {
    // Test all mappings
    assert_eq!(oid_to_attribute_label(OID_COMMON_NAME), Some(ATTRIBUTE_CN));
    assert_eq!(oid_to_attribute_label(OID_LOCALITY), Some(ATTRIBUTE_L));
    assert_eq!(oid_to_attribute_label(OID_STATE), Some(ATTRIBUTE_ST));
    assert_eq!(oid_to_attribute_label(OID_ORGANIZATION), Some(ATTRIBUTE_O));
    assert_eq!(oid_to_attribute_label(OID_ORGANIZATIONAL_UNIT), Some(ATTRIBUTE_OU));
    assert_eq!(oid_to_attribute_label(OID_COUNTRY), Some(ATTRIBUTE_C));
    assert_eq!(oid_to_attribute_label(OID_STREET), Some(ATTRIBUTE_STREET));
    
    // Test unmapped OID
    assert_eq!(oid_to_attribute_label("1.2.3.4"), None);
    assert_eq!(oid_to_attribute_label(""), None);
    assert_eq!(oid_to_attribute_label("invalid"), None);
}

#[test]
fn test_attribute_label_to_oid_mapping() {
    // Test all mappings with correct case
    assert_eq!(attribute_label_to_oid("CN"), Some(OID_COMMON_NAME));
    assert_eq!(attribute_label_to_oid("L"), Some(OID_LOCALITY));
    assert_eq!(attribute_label_to_oid("ST"), Some(OID_STATE));
    assert_eq!(attribute_label_to_oid("O"), Some(OID_ORGANIZATION));
    assert_eq!(attribute_label_to_oid("OU"), Some(OID_ORGANIZATIONAL_UNIT));
    assert_eq!(attribute_label_to_oid("C"), Some(OID_COUNTRY));
    assert_eq!(attribute_label_to_oid("STREET"), Some(OID_STREET));
    
    // Test case insensitive mappings
    assert_eq!(attribute_label_to_oid("cn"), Some(OID_COMMON_NAME));
    assert_eq!(attribute_label_to_oid("l"), Some(OID_LOCALITY));
    assert_eq!(attribute_label_to_oid("st"), Some(OID_STATE));
    assert_eq!(attribute_label_to_oid("o"), Some(OID_ORGANIZATION));
    assert_eq!(attribute_label_to_oid("ou"), Some(OID_ORGANIZATIONAL_UNIT));
    assert_eq!(attribute_label_to_oid("c"), Some(OID_COUNTRY));
    assert_eq!(attribute_label_to_oid("street"), Some(OID_STREET));
    
    // Test mixed case
    assert_eq!(attribute_label_to_oid("Cn"), Some(OID_COMMON_NAME));
    assert_eq!(attribute_label_to_oid("Street"), Some(OID_STREET));
    
    // Test unmapped attributes
    assert_eq!(attribute_label_to_oid("SERIALNUMBER"), None);
    assert_eq!(attribute_label_to_oid(""), None);
    assert_eq!(attribute_label_to_oid("invalid"), None);
}

#[test]
fn test_bidirectional_mapping_consistency() {
    // Test that the mappings are consistent both ways
    let test_cases = vec![
        (OID_COMMON_NAME, ATTRIBUTE_CN),
        (OID_LOCALITY, ATTRIBUTE_L),
        (OID_STATE, ATTRIBUTE_ST),
        (OID_ORGANIZATION, ATTRIBUTE_O),
        (OID_ORGANIZATIONAL_UNIT, ATTRIBUTE_OU),
        (OID_COUNTRY, ATTRIBUTE_C),
        (OID_STREET, ATTRIBUTE_STREET),
    ];
    
    for (oid, label) in test_cases {
        // Forward mapping
        assert_eq!(oid_to_attribute_label(oid), Some(label));
        // Reverse mapping
        assert_eq!(attribute_label_to_oid(label), Some(oid));
    }
}

#[test]
fn test_constant_string_properties() {
    // Test that constants are non-empty and well-formed
    assert!(!DID_PREFIX.is_empty());
    assert!(FULL_DID_PREFIX.starts_with(DID_PREFIX));
    assert!(FULL_DID_PREFIX.contains(VERSION));
    
    // Test separators
    assert!(POLICY_SEPARATOR.len() == 2);
    assert!(VALUE_SEPARATOR.len() == 1);
    
    // Test hash algorithms are lowercase
    assert_eq!(HASH_ALGORITHM_SHA256, HASH_ALGORITHM_SHA256.to_lowercase());
    assert_eq!(HASH_ALGORITHM_SHA384, HASH_ALGORITHM_SHA384.to_lowercase());
    assert_eq!(HASH_ALGORITHM_SHA512, HASH_ALGORITHM_SHA512.to_lowercase());
    
    // Test policy names are lowercase
    assert_eq!(POLICY_SUBJECT, POLICY_SUBJECT.to_lowercase());
    assert_eq!(POLICY_SAN, POLICY_SAN.to_lowercase());
    assert_eq!(POLICY_EKU, POLICY_EKU.to_lowercase());
    
    // Test SAN types are lowercase
    assert_eq!(SAN_TYPE_EMAIL, SAN_TYPE_EMAIL.to_lowercase());
    assert_eq!(SAN_TYPE_DNS, SAN_TYPE_DNS.to_lowercase());
    assert_eq!(SAN_TYPE_URI, SAN_TYPE_URI.to_lowercase());
    assert_eq!(SAN_TYPE_DN, SAN_TYPE_DN.to_lowercase());
}

#[test]
fn test_oid_format() {
    // Test that OIDs are in proper dotted decimal notation
    let oids = vec![
        OID_COMMON_NAME,
        OID_LOCALITY,
        OID_STATE,
        OID_ORGANIZATION,
        OID_ORGANIZATIONAL_UNIT,
        OID_COUNTRY,
        OID_STREET,
        OID_FULCIO_ISSUER,
        OID_EXTENDED_KEY_USAGE,
        OID_SAN,
        OID_BASIC_CONSTRAINTS,
    ];
    
    for oid in oids {
        assert!(!oid.is_empty());
        assert!(oid.chars().all(|c| c.is_ascii_digit() || c == '.'));
        assert!(oid.chars().next().map_or(false, |c| c.is_ascii_digit()));
        assert!(oid.chars().next_back().map_or(false, |c| c.is_ascii_digit()));
        assert!(!oid.contains(".."), "OID should not have consecutive dots: {}", oid);
    }
}

#[test]
fn test_attribute_label_format() {
    // Test that attribute labels are uppercase ASCII
    let labels = vec![
        ATTRIBUTE_CN,
        ATTRIBUTE_L,
        ATTRIBUTE_ST,
        ATTRIBUTE_O,
        ATTRIBUTE_OU,
        ATTRIBUTE_C,
        ATTRIBUTE_STREET,
    ];
    
    for label in labels {
        assert!(!label.is_empty());
        assert!(label.chars().all(|c| c.is_ascii_uppercase() || c.is_ascii_alphabetic()));
        assert_eq!(label, label.to_uppercase());
    }
}

// Test edge cases for mapping functions
#[test]
fn test_mapping_edge_cases() {
    // Test empty strings
    assert_eq!(oid_to_attribute_label(""), None);
    assert_eq!(attribute_label_to_oid(""), None);
    
    // Test whitespace
    assert_eq!(oid_to_attribute_label(" "), None);
    assert_eq!(attribute_label_to_oid(" "), None);
    
    // Test case sensitivity for OID lookup (should be exact match)
    assert_eq!(oid_to_attribute_label("2.5.4.3"), Some("CN"));
    assert_eq!(oid_to_attribute_label("2.5.4.3 "), None); // with space
    
    // Test that attribute lookup is case insensitive
    assert_eq!(attribute_label_to_oid("cn"), Some("2.5.4.3"));
    assert_eq!(attribute_label_to_oid("CN"), Some("2.5.4.3"));
    assert_eq!(attribute_label_to_oid("Cn"), Some("2.5.4.3"));
    assert_eq!(attribute_label_to_oid("cN"), Some("2.5.4.3"));
}
