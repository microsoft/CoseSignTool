// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Gap coverage tests for cose_sign1_certificates.
//!
//! Targets uncovered paths in: error, thumbprint, extensions, chain_builder,
//! chain_sort_order, cose_key_factory, signing/scitt, validation/facts, and
//! validation/pack.

use std::borrow::Cow;

use cbor_primitives::CborEncoder;
use cose_sign1_primitives::{CoseHeaderLabel, CoseHeaderMap, CoseHeaderValue};

use cose_sign1_certificates::error::CertificateError;
use cose_sign1_certificates::thumbprint::{
    compute_thumbprint, CoseX509Thumbprint, ThumbprintAlgorithm,
};
use cose_sign1_certificates::chain_builder::{CertificateChainBuilder, ExplicitCertificateChainBuilder};
use cose_sign1_certificates::chain_sort_order::X509ChainSortOrder;
use cose_sign1_certificates::cose_key_factory::{HashAlgorithm, X509CertificateCoseKeyFactory};
use cose_sign1_certificates::extensions::{extract_x5chain, extract_x5t, verify_x5t_matches_chain};
use cose_sign1_certificates::validation::facts::*;
use cose_sign1_certificates::validation::pack::{CertificateTrustOptions, X509CertificateTrustPack};
use cose_sign1_validation_primitives::fact_properties::{FactProperties, FactValue};

// ---------------------------------------------------------------------------
// error.rs — Display + Error trait
// ---------------------------------------------------------------------------

#[test]
fn error_is_std_error() {
    let err: Box<dyn std::error::Error> = Box::new(CertificateError::NotFound);
    assert!(err.to_string().contains("not found"));
}

#[test]
fn error_debug_formatting() {
    let err = CertificateError::InvalidCertificate("bad".into());
    let debug = format!("{:?}", err);
    assert!(debug.contains("InvalidCertificate"));
}

// ---------------------------------------------------------------------------
// thumbprint.rs — algorithm ID round-trip, unsupported IDs, serialize/deser
// ---------------------------------------------------------------------------

#[test]
fn thumbprint_algorithm_sha384_round_trip() {
    assert_eq!(ThumbprintAlgorithm::Sha384.cose_algorithm_id(), -43);
    assert_eq!(ThumbprintAlgorithm::from_cose_id(-43), Some(ThumbprintAlgorithm::Sha384));
}

#[test]
fn thumbprint_algorithm_sha512_round_trip() {
    assert_eq!(ThumbprintAlgorithm::Sha512.cose_algorithm_id(), -44);
    assert_eq!(ThumbprintAlgorithm::from_cose_id(-44), Some(ThumbprintAlgorithm::Sha512));
}

#[test]
fn thumbprint_algorithm_unsupported_id_returns_none() {
    assert_eq!(ThumbprintAlgorithm::from_cose_id(0), None);
    assert_eq!(ThumbprintAlgorithm::from_cose_id(999), None);
    assert_eq!(ThumbprintAlgorithm::from_cose_id(-1), None);
}

#[test]
fn thumbprint_new_sha384() {
    let data = b"certificate-bytes";
    let tp = CoseX509Thumbprint::new(data, ThumbprintAlgorithm::Sha384);
    assert_eq!(tp.hash_id, -43);
    assert_eq!(tp.thumbprint.len(), 48); // SHA-384 = 48 bytes
}

#[test]
fn thumbprint_new_sha512() {
    let data = b"certificate-bytes";
    let tp = CoseX509Thumbprint::new(data, ThumbprintAlgorithm::Sha512);
    assert_eq!(tp.hash_id, -44);
    assert_eq!(tp.thumbprint.len(), 64); // SHA-512 = 64 bytes
}

#[test]
fn thumbprint_serialize_deserialize_round_trip_sha256() {
    let data = b"fake-cert-der";
    let tp = CoseX509Thumbprint::from_cert(data);
    let serialized = tp.serialize().expect("serialize");
    let deserialized = CoseX509Thumbprint::deserialize(&serialized).expect("deserialize");
    assert_eq!(deserialized.hash_id, tp.hash_id);
    assert_eq!(deserialized.thumbprint, tp.thumbprint);
}

#[test]
fn thumbprint_serialize_deserialize_round_trip_sha384() {
    let data = b"test-cert";
    let tp = CoseX509Thumbprint::new(data, ThumbprintAlgorithm::Sha384);
    let serialized = tp.serialize().expect("serialize");
    let deserialized = CoseX509Thumbprint::deserialize(&serialized).expect("deserialize");
    assert_eq!(deserialized.hash_id, -43);
    assert_eq!(deserialized.thumbprint, tp.thumbprint);
}

#[test]
fn thumbprint_deserialize_not_array_errors() {
    // CBOR unsigned int 42 — not an array
    let cbor_int = vec![0x18, 0x2A];
    let result = CoseX509Thumbprint::deserialize(&cbor_int);
    assert!(result.is_err());
    let msg = result.unwrap_err().to_string();
    assert!(msg.contains("array"), "Expected 'array' in error: {}", msg);
}

#[test]
fn thumbprint_deserialize_wrong_array_length() {
    // CBOR array of length 3: [1, 2, 3]
    let cbor_arr3 = vec![0x83, 0x01, 0x02, 0x03];
    let result = CoseX509Thumbprint::deserialize(&cbor_arr3);
    assert!(result.is_err());
    let msg = result.unwrap_err().to_string();
    assert!(msg.contains("2 element"), "Expected '2 element' in error: {}", msg);
}

#[test]
fn thumbprint_deserialize_unsupported_hash_id() {
    // CBOR array [99, h'AABB'] — 99 is not a valid COSE hash algorithm
    let mut encoder = cose_sign1_primitives::provider::encoder();
    encoder.encode_array(2).unwrap();
    encoder.encode_i64(99).unwrap();
    encoder.encode_bstr(&[0xAA, 0xBB]).unwrap();
    let cbor = encoder.into_bytes();

    let result = CoseX509Thumbprint::deserialize(&cbor);
    assert!(result.is_err());
    let msg = result.unwrap_err().to_string();
    assert!(msg.contains("Unsupported"), "Expected 'Unsupported' in error: {}", msg);
}

#[test]
fn thumbprint_deserialize_non_integer_hash_id() {
    // CBOR array ["text", h'AABB'] — first element is text, not integer
    let mut encoder = cose_sign1_primitives::provider::encoder();
    encoder.encode_array(2).unwrap();
    encoder.encode_tstr("text").unwrap();
    encoder.encode_bstr(&[0xAA, 0xBB]).unwrap();
    let cbor = encoder.into_bytes();

    let result = CoseX509Thumbprint::deserialize(&cbor);
    assert!(result.is_err());
    let msg = result.unwrap_err().to_string();
    assert!(msg.contains("integer"), "Expected 'integer' in error: {}", msg);
}

#[test]
fn thumbprint_deserialize_non_bstr_thumbprint() {
    // CBOR array [-16, "text"] — second element is text, not bstr
    let mut encoder = cose_sign1_primitives::provider::encoder();
    encoder.encode_array(2).unwrap();
    encoder.encode_i64(-16).unwrap();
    encoder.encode_tstr("not-bytes").unwrap();
    let cbor = encoder.into_bytes();

    let result = CoseX509Thumbprint::deserialize(&cbor);
    assert!(result.is_err());
    let msg = result.unwrap_err().to_string();
    assert!(msg.contains("ByteString"), "Expected 'ByteString' in error: {}", msg);
}

#[test]
fn thumbprint_matches_returns_true_for_same_data() {
    let cert_der = b"some-cert-der-data";
    let tp = CoseX509Thumbprint::from_cert(cert_der);
    assert!(tp.matches(cert_der).expect("matches"));
}

#[test]
fn thumbprint_matches_returns_false_for_different_data() {
    let tp = CoseX509Thumbprint::from_cert(b"cert-A");
    assert!(!tp.matches(b"cert-B").expect("matches"));
}

#[test]
fn thumbprint_matches_unsupported_hash_id_errors() {
    let tp = CoseX509Thumbprint {
        hash_id: 999,
        thumbprint: vec![0x00],
    };
    let result = tp.matches(b"data");
    assert!(result.is_err());
}

#[test]
fn compute_thumbprint_sha384() {
    let hash = compute_thumbprint(b"data", ThumbprintAlgorithm::Sha384);
    assert_eq!(hash.len(), 48);
}

#[test]
fn compute_thumbprint_sha512() {
    let hash = compute_thumbprint(b"data", ThumbprintAlgorithm::Sha512);
    assert_eq!(hash.len(), 64);
}

// ---------------------------------------------------------------------------
// extensions.rs — extract_x5chain / extract_x5t with empty and malformed data
// ---------------------------------------------------------------------------

#[test]
fn extract_x5chain_empty_headers_returns_empty() {
    let headers = CoseHeaderMap::new();
    let chain = extract_x5chain(&headers).unwrap();
    assert!(chain.is_empty());
}

#[test]
fn extract_x5t_empty_headers_returns_none() {
    let headers = CoseHeaderMap::new();
    let result = extract_x5t(&headers).unwrap();
    assert!(result.is_none());
}

#[test]
fn extract_x5t_non_bytes_value_returns_error() {
    let mut headers = CoseHeaderMap::new();
    headers.insert(
        CoseHeaderLabel::Int(34),
        CoseHeaderValue::Text("not-bytes".into()),
    );
    let result = extract_x5t(&headers);
    assert!(result.is_err());
    let msg = result.unwrap_err().to_string();
    assert!(msg.contains("raw CBOR or bytes"), "Expected 'raw CBOR or bytes' in: {}", msg);
}

#[test]
fn verify_x5t_matches_chain_no_x5t_returns_false() {
    let headers = CoseHeaderMap::new();
    assert!(!verify_x5t_matches_chain(&headers).unwrap());
}

#[test]
fn verify_x5t_matches_chain_no_chain_returns_false() {
    // Insert x5t but no x5chain
    let cert_der = b"fake-cert";
    let tp = CoseX509Thumbprint::from_cert(cert_der);
    let serialized = tp.serialize().unwrap();

    let mut headers = CoseHeaderMap::new();
    headers.insert(
        CoseHeaderLabel::Int(34),
        CoseHeaderValue::Bytes(serialized),
    );
    assert!(!verify_x5t_matches_chain(&headers).unwrap());
}

// ---------------------------------------------------------------------------
// chain_builder.rs — ExplicitCertificateChainBuilder edge cases
// ---------------------------------------------------------------------------

#[test]
fn explicit_chain_builder_empty_chain() {
    let builder = ExplicitCertificateChainBuilder::new(vec![]);
    let chain = builder.build_chain(b"ignored").unwrap();
    assert!(chain.is_empty());
}

#[test]
fn explicit_chain_builder_multi_cert() {
    let certs = vec![vec![1, 2, 3], vec![4, 5, 6], vec![7, 8, 9]];
    let builder = ExplicitCertificateChainBuilder::new(certs.clone());
    let chain = builder.build_chain(b"any-cert").unwrap();
    assert_eq!(chain, certs);
}

#[test]
fn explicit_chain_builder_ignores_input_cert() {
    let certs = vec![vec![0xAA]];
    let builder = ExplicitCertificateChainBuilder::new(certs.clone());
    let chain = builder.build_chain(b"completely-different").unwrap();
    assert_eq!(chain, certs);
}

// ---------------------------------------------------------------------------
// chain_sort_order.rs — all sort variants, equality, clone, debug
// ---------------------------------------------------------------------------

#[test]
fn chain_sort_order_leaf_first() {
    let order = X509ChainSortOrder::LeafFirst;
    assert_eq!(order, X509ChainSortOrder::LeafFirst);
    assert_ne!(order, X509ChainSortOrder::RootFirst);
}

#[test]
fn chain_sort_order_root_first() {
    let order = X509ChainSortOrder::RootFirst;
    assert_eq!(order, X509ChainSortOrder::RootFirst);
}

#[test]
fn chain_sort_order_clone_and_copy() {
    let a = X509ChainSortOrder::LeafFirst;
    let b = a;
    assert_eq!(a, b);
}

#[test]
fn chain_sort_order_debug() {
    let debug = format!("{:?}", X509ChainSortOrder::RootFirst);
    assert!(debug.contains("RootFirst"));
}

// ---------------------------------------------------------------------------
// cose_key_factory.rs — hash algorithm selection, COSE IDs
// ---------------------------------------------------------------------------

#[test]
fn hash_algorithm_sha256_for_small_keys() {
    let alg = X509CertificateCoseKeyFactory::get_hash_algorithm_for_key_size(2048, false);
    assert_eq!(alg, HashAlgorithm::Sha256);
}

#[test]
fn hash_algorithm_sha384_for_3072_bit_key() {
    let alg = X509CertificateCoseKeyFactory::get_hash_algorithm_for_key_size(3072, false);
    assert_eq!(alg, HashAlgorithm::Sha384);
}

#[test]
fn hash_algorithm_sha384_for_ec_p521() {
    let alg = X509CertificateCoseKeyFactory::get_hash_algorithm_for_key_size(521, true);
    assert_eq!(alg, HashAlgorithm::Sha384);
}

#[test]
fn hash_algorithm_sha512_for_4096_bit_key() {
    let alg = X509CertificateCoseKeyFactory::get_hash_algorithm_for_key_size(4096, false);
    assert_eq!(alg, HashAlgorithm::Sha512);
}

#[test]
fn hash_algorithm_sha512_for_8192_bit_key() {
    let alg = X509CertificateCoseKeyFactory::get_hash_algorithm_for_key_size(8192, false);
    assert_eq!(alg, HashAlgorithm::Sha512);
}

#[test]
fn hash_algorithm_cose_ids() {
    assert_eq!(HashAlgorithm::Sha256.cose_algorithm_id(), -16);
    assert_eq!(HashAlgorithm::Sha384.cose_algorithm_id(), -43);
    assert_eq!(HashAlgorithm::Sha512.cose_algorithm_id(), -44);
}

#[test]
fn hash_algorithm_debug_and_equality() {
    assert_eq!(HashAlgorithm::Sha256, HashAlgorithm::Sha256);
    assert_ne!(HashAlgorithm::Sha256, HashAlgorithm::Sha384);
    let debug = format!("{:?}", HashAlgorithm::Sha512);
    assert!(debug.contains("Sha512"));
}

#[test]
fn create_from_public_key_with_garbage_errors() {
    let result = X509CertificateCoseKeyFactory::create_from_public_key(b"not-a-certificate");
    assert!(result.is_err());
    let msg = match result {
        Err(e) => e.to_string(),
        Ok(_) => panic!("Expected error"),
    };
    assert!(msg.contains("Failed to parse certificate"), "Unexpected error: {}", msg);
}
// ---------------------------------------------------------------------------
// validation/facts.rs — FactProperties implementations
// ---------------------------------------------------------------------------

#[test]
fn signing_cert_identity_fact_all_properties() {
    let fact = X509SigningCertificateIdentityFact {
        certificate_thumbprint: "AA:BB".into(),
        subject: "CN=Test".into(),
        issuer: "CN=Root".into(),
        serial_number: "01".into(),
        not_before_unix_seconds: 1000,
        not_after_unix_seconds: 2000,
    };
    assert_eq!(fact.get_property("certificate_thumbprint"), Some(FactValue::Str(Cow::Borrowed("AA:BB"))));
    assert_eq!(fact.get_property("subject"), Some(FactValue::Str(Cow::Borrowed("CN=Test"))));
    assert_eq!(fact.get_property("issuer"), Some(FactValue::Str(Cow::Borrowed("CN=Root"))));
    assert_eq!(fact.get_property("serial_number"), Some(FactValue::Str(Cow::Borrowed("01"))));
    assert_eq!(fact.get_property("not_before_unix_seconds"), Some(FactValue::I64(1000)));
    assert_eq!(fact.get_property("not_after_unix_seconds"), Some(FactValue::I64(2000)));
    assert_eq!(fact.get_property("nonexistent"), None);
}

#[test]
fn chain_element_identity_fact_all_properties() {
    let fact = X509ChainElementIdentityFact {
        index: 0,
        certificate_thumbprint: "CC:DD".into(),
        subject: "CN=Leaf".into(),
        issuer: "CN=Intermediate".into(),
    };
    assert_eq!(fact.get_property("index"), Some(FactValue::Usize(0)));
    assert_eq!(fact.get_property("certificate_thumbprint"), Some(FactValue::Str(Cow::Borrowed("CC:DD"))));
    assert_eq!(fact.get_property("subject"), Some(FactValue::Str(Cow::Borrowed("CN=Leaf"))));
    assert_eq!(fact.get_property("issuer"), Some(FactValue::Str(Cow::Borrowed("CN=Intermediate"))));
    assert_eq!(fact.get_property("unknown_field"), None);
}

#[test]
fn chain_element_validity_fact_all_properties() {
    let fact = X509ChainElementValidityFact {
        index: 2,
        not_before_unix_seconds: 500,
        not_after_unix_seconds: 1500,
    };
    assert_eq!(fact.get_property("index"), Some(FactValue::Usize(2)));
    assert_eq!(fact.get_property("not_before_unix_seconds"), Some(FactValue::I64(500)));
    assert_eq!(fact.get_property("not_after_unix_seconds"), Some(FactValue::I64(1500)));
    assert_eq!(fact.get_property("nope"), None);
}

#[test]
fn chain_trusted_fact_all_properties() {
    let fact = X509ChainTrustedFact {
        chain_built: true,
        is_trusted: false,
        status_flags: 0x01,
        status_summary: Some("partial".into()),
        element_count: 3,
    };
    assert_eq!(fact.get_property("chain_built"), Some(FactValue::Bool(true)));
    assert_eq!(fact.get_property("is_trusted"), Some(FactValue::Bool(false)));
    assert_eq!(fact.get_property("status_flags"), Some(FactValue::U32(0x01)));
    assert_eq!(fact.get_property("element_count"), Some(FactValue::Usize(3)));
    assert_eq!(fact.get_property("status_summary"), Some(FactValue::Str(Cow::Borrowed("partial"))));
    assert_eq!(fact.get_property("garbage"), None);
}

#[test]
fn chain_trusted_fact_none_status_summary() {
    let fact = X509ChainTrustedFact {
        chain_built: false,
        is_trusted: false,
        status_flags: 0,
        status_summary: None,
        element_count: 0,
    };
    assert_eq!(fact.get_property("status_summary"), None);
}

#[test]
fn public_key_algorithm_fact_all_properties() {
    let fact = X509PublicKeyAlgorithmFact {
        certificate_thumbprint: "EE:FF".into(),
        algorithm_oid: "1.2.840.113549.1.1.11".into(),
        algorithm_name: Some("sha256WithRSAEncryption".into()),
        is_pqc: false,
    };
    assert_eq!(fact.get_property("certificate_thumbprint"), Some(FactValue::Str(Cow::Borrowed("EE:FF"))));
    assert_eq!(fact.get_property("algorithm_oid"), Some(FactValue::Str(Cow::Borrowed("1.2.840.113549.1.1.11"))));
    assert_eq!(
        fact.get_property("algorithm_name"),
        Some(FactValue::Str(Cow::Borrowed("sha256WithRSAEncryption")))
    );
    assert_eq!(fact.get_property("is_pqc"), Some(FactValue::Bool(false)));
    assert_eq!(fact.get_property("missing"), None);
}

#[test]
fn public_key_algorithm_fact_none_name() {
    let fact = X509PublicKeyAlgorithmFact {
        certificate_thumbprint: "AA".into(),
        algorithm_oid: "1.2.3".into(),
        algorithm_name: None,
        is_pqc: true,
    };
    assert_eq!(fact.get_property("algorithm_name"), None);
    assert_eq!(fact.get_property("is_pqc"), Some(FactValue::Bool(true)));
}

// ---------------------------------------------------------------------------
// validation/pack.rs — CertificateTrustOptions construction
// ---------------------------------------------------------------------------

#[test]
fn certificate_trust_options_default() {
    let opts = CertificateTrustOptions::default();
    assert!(opts.allowed_thumbprints.is_empty());
    assert!(!opts.identity_pinning_enabled);
    assert!(opts.pqc_algorithm_oids.is_empty());
    assert!(!opts.trust_embedded_chain_as_trusted);
}

#[test]
fn certificate_trust_options_custom() {
    let opts = CertificateTrustOptions {
        allowed_thumbprints: vec!["AABB".into()],
        identity_pinning_enabled: true,
        pqc_algorithm_oids: vec!["1.3.6.1.4.1.2.267.12.4.4".into()],
        trust_embedded_chain_as_trusted: true,
    };
    assert_eq!(opts.allowed_thumbprints.len(), 1);
    assert!(opts.identity_pinning_enabled);
    assert!(!opts.pqc_algorithm_oids.is_empty());
    assert!(opts.trust_embedded_chain_as_trusted);
}

#[test]
fn x509_trust_pack_new_default() {
    let _pack = X509CertificateTrustPack::default();
    // Ensure default construction works without panic
}

#[test]
fn x509_trust_pack_trust_embedded() {
    let pack = X509CertificateTrustPack::trust_embedded_chain_as_trusted();
    let _cloned = pack.clone();
    // Ensure the convenience constructor works without panic
}

#[test]
fn x509_trust_pack_with_custom_options() {
    let opts = CertificateTrustOptions {
        allowed_thumbprints: vec!["AA".into(), "BB".into()],
        identity_pinning_enabled: true,
        pqc_algorithm_oids: vec![],
        trust_embedded_chain_as_trusted: false,
    };
    let pack = X509CertificateTrustPack::new(opts);
    let _cloned = pack.clone();
}

// ---------------------------------------------------------------------------
// Fact struct construction — Debug, Clone, Eq
// ---------------------------------------------------------------------------

#[test]
fn fact_structs_debug_clone_eq() {
    let identity = X509SigningCertificateIdentityFact {
        certificate_thumbprint: "t".into(),
        subject: "s".into(),
        issuer: "i".into(),
        serial_number: "n".into(),
        not_before_unix_seconds: 0,
        not_after_unix_seconds: 0,
    };
    let cloned = identity.clone();
    assert_eq!(identity, cloned);
    let _ = format!("{:?}", identity);

    let elem = X509ChainElementIdentityFact {
        index: 1,
        certificate_thumbprint: "x".into(),
        subject: "s".into(),
        issuer: "i".into(),
    };
    assert_eq!(elem.clone(), elem);

    let validity = X509ChainElementValidityFact {
        index: 0,
        not_before_unix_seconds: 100,
        not_after_unix_seconds: 200,
    };
    assert_eq!(validity.clone(), validity);

    let trusted = X509ChainTrustedFact {
        chain_built: true,
        is_trusted: true,
        status_flags: 0,
        status_summary: None,
        element_count: 1,
    };
    assert_eq!(trusted.clone(), trusted);

    let algo = X509PublicKeyAlgorithmFact {
        certificate_thumbprint: "a".into(),
        algorithm_oid: "1.2.3".into(),
        algorithm_name: None,
        is_pqc: false,
    };
    assert_eq!(algo.clone(), algo);

    let allowed = X509SigningCertificateIdentityAllowedFact {
        certificate_thumbprint: "t".into(),
        subject: "s".into(),
        issuer: "i".into(),
        is_allowed: true,
    };
    assert_eq!(allowed.clone(), allowed);

    let eku = X509SigningCertificateEkuFact {
        certificate_thumbprint: "t".into(),
        oid_value: "1.3.6.1".into(),
    };
    assert_eq!(eku.clone(), eku);

    let ku = X509SigningCertificateKeyUsageFact {
        certificate_thumbprint: "t".into(),
        usages: vec!["digitalSignature".into()],
    };
    assert_eq!(ku.clone(), ku);

    let bc = X509SigningCertificateBasicConstraintsFact {
        certificate_thumbprint: "t".into(),
        is_ca: false,
        path_len_constraint: Some(0),
    };
    assert_eq!(bc.clone(), bc);

    let chain_id = X509X5ChainCertificateIdentityFact {
        certificate_thumbprint: "t".into(),
        subject: "s".into(),
        issuer: "i".into(),
    };
    assert_eq!(chain_id.clone(), chain_id);

    let signing_key = CertificateSigningKeyTrustFact {
        thumbprint: "t".into(),
        subject: "s".into(),
        issuer: "i".into(),
        chain_built: true,
        chain_trusted: true,
        chain_status_flags: 0,
        chain_status_summary: None,
    };
    assert_eq!(signing_key.clone(), signing_key);
}
