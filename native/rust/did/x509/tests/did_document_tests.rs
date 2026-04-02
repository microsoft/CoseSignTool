// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use did_x509::{DidDocument, VerificationMethod};
use std::collections::HashMap;

#[test]
fn test_did_document_to_json() {
    let mut jwk = HashMap::new();
    jwk.insert("kty".to_string(), "RSA".to_string());
    jwk.insert("n".to_string(), "test".to_string());
    jwk.insert("e".to_string(), "AQAB".to_string());

    let doc = DidDocument {
        context: vec!["https://www.w3.org/ns/did/v1".to_string()],
        id: "did:x509:0:sha256:test::eku:1.2.3".to_string(),
        verification_method: vec![VerificationMethod {
            id: "did:x509:0:sha256:test::eku:1.2.3#key-1".to_string(),
            type_: "JsonWebKey2020".to_string(),
            controller: "did:x509:0:sha256:test::eku:1.2.3".to_string(),
            public_key_jwk: jwk,
        }],
        assertion_method: vec!["did:x509:0:sha256:test::eku:1.2.3#key-1".to_string()],
    };

    let json = doc.to_json(false).unwrap();
    assert!(json.contains("@context"));
    assert!(json.contains("did:x509:0:sha256:test::eku:1.2.3"));
    assert!(json.contains("verificationMethod"));
    assert!(json.contains("assertionMethod"));
}

#[test]
fn test_did_document_to_json_indented() {
    let mut jwk = HashMap::new();
    jwk.insert("kty".to_string(), "EC".to_string());

    let doc = DidDocument {
        context: vec!["https://www.w3.org/ns/did/v1".to_string()],
        id: "did:x509:0:sha256:test::eku:1.2.3".to_string(),
        verification_method: vec![VerificationMethod {
            id: "did:x509:0:sha256:test::eku:1.2.3#key-1".to_string(),
            type_: "JsonWebKey2020".to_string(),
            controller: "did:x509:0:sha256:test::eku:1.2.3".to_string(),
            public_key_jwk: jwk,
        }],
        assertion_method: vec!["did:x509:0:sha256:test::eku:1.2.3#key-1".to_string()],
    };

    // Test indented output
    let json_indented = doc.to_json(true).unwrap();
    assert!(json_indented.contains('\n')); // Should have newlines
    assert!(json_indented.contains("@context"));
}

#[test]
fn test_did_document_clone_partial_eq() {
    let mut jwk = HashMap::new();
    jwk.insert("kty".to_string(), "EC".to_string());

    let doc1 = DidDocument {
        context: vec!["https://www.w3.org/ns/did/v1".to_string()],
        id: "did:x509:0:sha256:test1::eku:1.2.3".to_string(),
        verification_method: vec![VerificationMethod {
            id: "did:x509:0:sha256:test1::eku:1.2.3#key-1".to_string(),
            type_: "JsonWebKey2020".to_string(),
            controller: "did:x509:0:sha256:test1::eku:1.2.3".to_string(),
            public_key_jwk: jwk.clone(),
        }],
        assertion_method: vec!["did:x509:0:sha256:test1::eku:1.2.3#key-1".to_string()],
    };

    // Clone and test equality
    let doc2 = doc1.clone();
    assert_eq!(doc1, doc2);

    // Test inequality with different doc
    let doc3 = DidDocument {
        context: vec!["https://www.w3.org/ns/did/v1".to_string()],
        id: "did:x509:0:sha256:test2::eku:1.2.3".to_string(),
        verification_method: vec![],
        assertion_method: vec![],
    };
    assert_ne!(doc1, doc3);
}
