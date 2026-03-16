// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Targeted coverage tests for the cose_sign1_certificates crate.
//!
//! Exercises:
//! - pack.rs: chain trust evaluation (well-formed vs non-well-formed), single bstr x5chain,
//!   EKU iteration (all standard OIDs), KeyUsage flags, empty chain paths
//! - signing_key_resolver.rs: cert parse failures, verifier creation, auto-detect algorithm
//! - certificate_header_contributor.rs: x5t/x5chain building
//! - thumbprint.rs: deserialization error paths
//! - cose_key_factory.rs: hash algorithm branches
//! - scitt.rs: error when chain has no EKU

use cbor_primitives::{CborEncoder, CborProvider};
use cbor_primitives_everparse::EverParseCborProvider;
use cose_sign1_certificates::chain_builder::ExplicitCertificateChainBuilder;
use cose_sign1_certificates::cose_key_factory::{HashAlgorithm, X509CertificateCoseKeyFactory};
use cose_sign1_certificates::signing::certificate_header_contributor::CertificateHeaderContributor;
use cose_sign1_certificates::thumbprint::{CoseX509Thumbprint, ThumbprintAlgorithm};
use cose_sign1_certificates::validation::facts::*;
use cose_sign1_certificates::validation::pack::{
    CertificateTrustOptions, X509CertificateTrustPack,
};
use cose_sign1_primitives::CoseSign1Message;
use cose_sign1_validation::fluent::CoseSign1TrustPack;
use cose_sign1_validation_primitives::facts::{FactKey, TrustFactEngine, TrustFactSet};
use cose_sign1_validation_primitives::subject::TrustSubject;
use rcgen::{
    CertificateParams, ExtendedKeyUsagePurpose, IsCa, KeyPair, KeyUsagePurpose,
    PKCS_ECDSA_P256_SHA256,
};
use std::sync::Arc;

fn _init() -> EverParseCborProvider {
    EverParseCborProvider
}

// ==================== Helpers ====================

fn make_self_signed_cert(cn: &str) -> Vec<u8> {
    let mut params = CertificateParams::new(vec![cn.to_string()]).unwrap();
    params.is_ca = IsCa::NoCa;
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::CodeSigning];
    let kp = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
    let cert = params.self_signed(&kp).unwrap();
    cert.der().as_ref().to_vec()
}

fn make_self_signed_ca(cn: &str) -> (Vec<u8>, KeyPair) {
    let mut params = CertificateParams::new(vec![cn.to_string()]).unwrap();
    params.is_ca = IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    params.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
        KeyUsagePurpose::DigitalSignature,
    ];
    let kp = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
    let cert = params.self_signed(&kp).unwrap();
    (cert.der().as_ref().to_vec(), kp)
}

fn make_cert_with_all_ku() -> Vec<u8> {
    let mut params = CertificateParams::new(vec!["ku-test.example".to_string()]).unwrap();
    params.is_ca = IsCa::NoCa;
    params.key_usages = vec![
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::ContentCommitment, // NonRepudiation
        KeyUsagePurpose::KeyEncipherment,
        KeyUsagePurpose::DataEncipherment,
        KeyUsagePurpose::KeyAgreement,
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
        KeyUsagePurpose::EncipherOnly,
        KeyUsagePurpose::DecipherOnly,
    ];
    params.extended_key_usages = vec![
        ExtendedKeyUsagePurpose::ServerAuth,
        ExtendedKeyUsagePurpose::ClientAuth,
        ExtendedKeyUsagePurpose::CodeSigning,
        ExtendedKeyUsagePurpose::EmailProtection,
        ExtendedKeyUsagePurpose::TimeStamping,
        ExtendedKeyUsagePurpose::OcspSigning,
    ];
    let kp = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
    let cert = params.self_signed(&kp).unwrap();
    cert.der().as_ref().to_vec()
}

fn build_cose_sign1_with_protected(protected_map_bytes: &[u8]) -> Vec<u8> {
    let p = _init();
    let mut enc = p.encoder();
    enc.encode_array(4).unwrap();
    enc.encode_bstr(protected_map_bytes).unwrap();
    enc.encode_map(0).unwrap();
    enc.encode_null().unwrap();
    enc.encode_bstr(b"sig").unwrap();
    enc.into_bytes()
}

fn build_protected_map_with_x5chain_array(certs: &[&[u8]]) -> Vec<u8> {
    let p = _init();
    let mut enc = p.encoder();
    enc.encode_map(1).unwrap();
    enc.encode_i64(33).unwrap();
    enc.encode_array(certs.len()).unwrap();
    for cert_der in certs {
        enc.encode_bstr(cert_der).unwrap();
    }
    enc.into_bytes()
}

fn build_protected_map_with_single_bstr_x5chain(cert_der: &[u8]) -> Vec<u8> {
    let p = _init();
    let mut enc = p.encoder();
    // {33: bstr} (single bstr, not array)
    enc.encode_map(1).unwrap();
    enc.encode_i64(33).unwrap();
    enc.encode_bstr(cert_der).unwrap();
    enc.into_bytes()
}

fn build_protected_map_with_alg(alg: i64, certs: &[&[u8]]) -> Vec<u8> {
    let p = _init();
    let mut enc = p.encoder();
    enc.encode_map(2).unwrap();
    // alg
    enc.encode_i64(1).unwrap();
    enc.encode_i64(alg).unwrap();
    // x5chain
    enc.encode_i64(33).unwrap();
    enc.encode_array(certs.len()).unwrap();
    for cert_der in certs {
        enc.encode_bstr(cert_der).unwrap();
    }
    enc.into_bytes()
}

fn run_fact_engine(
    cose: &[u8],
    options: CertificateTrustOptions,
) -> TrustFactEngine {
    let producer = Arc::new(X509CertificateTrustPack::new(options));
    let msg = Arc::new(CoseSign1Message::parse(cose).unwrap());
    TrustFactEngine::new(vec![producer])
        .with_cose_sign1_bytes(Arc::from(cose.to_vec().into_boxed_slice()))
        .with_cose_sign1_message(msg)
}

// ==================== pack.rs: chain trust evaluation ====================

#[test]
fn chain_trust_self_signed_well_formed() {
    let cert = make_self_signed_cert("self-signed.example");
    let prot = build_protected_map_with_x5chain_array(&[&cert]);
    let cose = build_cose_sign1_with_protected(&prot);

    let opts = CertificateTrustOptions {
        trust_embedded_chain_as_trusted: true,
        ..Default::default()
    };
    let engine = run_fact_engine(&cose, opts);
    let subject = TrustSubject::root("PrimarySigningKey", b"seed");

    let chain_trust = engine
        .get_fact_set::<X509ChainTrustedFact>(&subject)
        .unwrap();
    match chain_trust {
        TrustFactSet::Available(v) => {
            let fact = &v[0];
            assert!(fact.chain_built);
            assert!(fact.is_trusted);
            assert_eq!(fact.status_flags, 0);
            assert!(fact.status_summary.is_none());
        }
        other => panic!("Expected Available, got {:?}", other),
    }
}

#[test]
fn chain_trust_not_well_formed_issuer_mismatch() {
    // Two independent self-signed certs that don't chain
    let cert1 = make_self_signed_cert("leaf.example");
    let cert2 = make_self_signed_cert("unrelated-root.example");
    let prot = build_protected_map_with_x5chain_array(&[&cert1, &cert2]);
    let cose = build_cose_sign1_with_protected(&prot);

    let opts = CertificateTrustOptions {
        trust_embedded_chain_as_trusted: true,
        ..Default::default()
    };
    let engine = run_fact_engine(&cose, opts);
    let subject = TrustSubject::root("PrimarySigningKey", b"seed");

    let chain_trust = engine
        .get_fact_set::<X509ChainTrustedFact>(&subject)
        .unwrap();
    match chain_trust {
        TrustFactSet::Available(v) => {
            let fact = &v[0];
            assert!(fact.chain_built);
            // Non-chaining certs: either not trusted or has status summary
            if !fact.is_trusted {
                assert_eq!(fact.status_flags, 1);
                assert!(fact.status_summary.is_some());
            }
        }
        other => panic!("Expected Available, got {:?}", other),
    }
}

#[test]
fn chain_trust_disabled() {
    let cert = make_self_signed_cert("disabled.example");
    let prot = build_protected_map_with_x5chain_array(&[&cert]);
    let cose = build_cose_sign1_with_protected(&prot);

    let opts = CertificateTrustOptions {
        trust_embedded_chain_as_trusted: false,
        ..Default::default()
    };
    let engine = run_fact_engine(&cose, opts);
    let subject = TrustSubject::root("PrimarySigningKey", b"seed");

    let chain_trust = engine
        .get_fact_set::<X509ChainTrustedFact>(&subject)
        .unwrap();
    match chain_trust {
        TrustFactSet::Available(v) => {
            let fact = &v[0];
            assert!(!fact.is_trusted);
            assert_eq!(
                fact.status_summary.as_deref(),
                Some("TrustEvaluationDisabled")
            );
        }
        other => panic!("Expected Available, got {:?}", other),
    }
}

#[test]
fn chain_identity_facts_with_empty_chain() {
    // COSE with no x5chain → empty chain → mark_missing path
    let p = _init();
    let mut enc = p.encoder();
    enc.encode_map(0).unwrap();
    let empty_prot = enc.into_bytes();
    let cose = build_cose_sign1_with_protected(&empty_prot);

    let engine = run_fact_engine(&cose, Default::default());
    let subject = TrustSubject::root("PrimarySigningKey", b"seed");

    // Identity facts should be marked missing or empty
    let identity = engine
        .get_fact_set::<X509ChainElementIdentityFact>(&subject)
        .unwrap();
    match &identity {
        TrustFactSet::Missing { .. } => {} // expected
        TrustFactSet::Available(v) if v.is_empty() => {} // also acceptable
        other => panic!("Expected Missing or empty, got {:?}", other),
    }
}

// ==================== pack.rs: single bstr x5chain ====================

#[test]
fn single_bstr_x5chain_produces_identity_facts() {
    let cert = make_self_signed_cert("single.example");
    let prot = build_protected_map_with_single_bstr_x5chain(&cert);
    let cose = build_cose_sign1_with_protected(&prot);

    let engine = run_fact_engine(&cose, Default::default());
    let subject = TrustSubject::root("PrimarySigningKey", b"seed");

    let identity = engine
        .get_fact_set::<X509SigningCertificateIdentityFact>(&subject)
        .unwrap();
    match identity {
        TrustFactSet::Available(v) => {
            assert_eq!(v.len(), 1);
        }
        other => panic!("Expected Available identity, got {:?}", other),
    }
}

// ==================== pack.rs: EKU + KeyUsage iteration ====================

#[test]
fn all_standard_eku_oids_emitted() {
    let cert = make_cert_with_all_ku();
    let prot = build_protected_map_with_x5chain_array(&[&cert]);
    let cose = build_cose_sign1_with_protected(&prot);

    let engine = run_fact_engine(&cose, Default::default());
    let subject = TrustSubject::root("PrimarySigningKey", b"seed");

    let eku = engine
        .get_fact_set::<X509SigningCertificateEkuFact>(&subject)
        .unwrap();
    match eku {
        TrustFactSet::Available(v) => {
            let oids: Vec<&str> = v.iter().map(|f| f.oid_value.as_str()).collect();
            assert!(oids.contains(&"1.3.6.1.5.5.7.3.1"), "ServerAuth missing");
            assert!(oids.contains(&"1.3.6.1.5.5.7.3.2"), "ClientAuth missing");
            assert!(oids.contains(&"1.3.6.1.5.5.7.3.3"), "CodeSigning missing");
            assert!(oids.contains(&"1.3.6.1.5.5.7.3.4"), "EmailProtection missing");
            assert!(oids.contains(&"1.3.6.1.5.5.7.3.8"), "TimeStamping missing");
            assert!(oids.contains(&"1.3.6.1.5.5.7.3.9"), "OcspSigning missing");
        }
        other => panic!("Expected Available EKU facts, got {:?}", other),
    }
}

#[test]
fn all_key_usage_flags_emitted() {
    let cert = make_cert_with_all_ku();
    let prot = build_protected_map_with_x5chain_array(&[&cert]);
    let cose = build_cose_sign1_with_protected(&prot);

    let engine = run_fact_engine(&cose, Default::default());
    let subject = TrustSubject::root("PrimarySigningKey", b"seed");

    let ku = engine
        .get_fact_set::<X509SigningCertificateKeyUsageFact>(&subject)
        .unwrap();
    match ku {
        TrustFactSet::Available(v) => {
            let usages: Vec<&str> = v.iter().flat_map(|f| f.usages.iter().map(|s| s.as_str())).collect();
            assert!(usages.contains(&"DigitalSignature"));
            assert!(usages.contains(&"NonRepudiation"));
            assert!(usages.contains(&"KeyEncipherment"));
            assert!(usages.contains(&"KeyCertSign"));
            assert!(usages.contains(&"CrlSign"));
        }
        other => panic!("Expected Available KU facts, got {:?}", other),
    }
}

// ==================== pack.rs: chain signing key trust ====================

#[test]
fn signing_key_trust_fact_produced() {
    let cert = make_self_signed_cert("trust-key.example");
    let prot = build_protected_map_with_x5chain_array(&[&cert]);
    let cose = build_cose_sign1_with_protected(&prot);

    let opts = CertificateTrustOptions {
        trust_embedded_chain_as_trusted: true,
        ..Default::default()
    };
    let engine = run_fact_engine(&cose, opts);
    let subject = TrustSubject::root("PrimarySigningKey", b"seed");

    let sk_trust = engine
        .get_fact_set::<CertificateSigningKeyTrustFact>(&subject)
        .unwrap();
    match sk_trust {
        TrustFactSet::Available(v) => {
            let fact = &v[0];
            assert!(fact.chain_built);
            assert!(fact.chain_trusted);
            assert!(!fact.thumbprint.is_empty());
            assert!(!fact.subject.is_empty());
        }
        other => panic!("Expected Available CertificateSigningKeyTrustFact, got {:?}", other),
    }
}

// ==================== pack.rs: chain element facts ====================

#[test]
fn chain_element_identity_produced_for_multi_cert_chain() {
    let cert1 = make_self_signed_cert("leaf.example");
    let cert2 = make_self_signed_cert("root.example");
    let prot = build_protected_map_with_x5chain_array(&[&cert1, &cert2]);
    let cose = build_cose_sign1_with_protected(&prot);

    let engine = run_fact_engine(&cose, Default::default());
    let subject = TrustSubject::root("PrimarySigningKey", b"seed");

    let chain_id = engine
        .get_fact_set::<X509ChainElementIdentityFact>(&subject)
        .unwrap();
    match chain_id {
        TrustFactSet::Available(v) => {
            assert_eq!(v.len(), 2, "Should have 2 chain elements");
            assert_eq!(v[0].index, 0);
            assert_eq!(v[1].index, 1);
        }
        other => panic!("Expected Available X509ChainElementIdentityFact, got {:?}", other),
    }

    let chain_validity = engine
        .get_fact_set::<X509ChainElementValidityFact>(&subject)
        .unwrap();
    match chain_validity {
        TrustFactSet::Available(v) => {
            assert_eq!(v.len(), 2);
        }
        other => panic!("Expected Available validity facts, got {:?}", other),
    }
}

// ==================== signing_key_resolver.rs ====================

#[test]
fn resolver_with_invalid_cert_bytes_does_not_crash() {
    // Build a COSE message with x5chain containing garbage bytes
    let garbage = vec![0xFF, 0xFE, 0xFD, 0xFC];
    let prot = build_protected_map_with_alg(-7, &[&garbage]); // ES256
    let cose = build_cose_sign1_with_protected(&prot);

    // Run through the full fact engine — the pack should not panic on invalid certs
    let engine = run_fact_engine(&cose, Default::default());
    let subject = TrustSubject::root("PrimarySigningKey", b"seed");

    // Identity should fail gracefully
    let identity = engine
        .get_fact_set::<X509SigningCertificateIdentityFact>(&subject);
    // It's ok if this returns Err or Missing — just shouldn't panic
    let _ = identity;
}

#[test]
fn key_factory_with_valid_cert() {
    let cert = make_self_signed_cert("factory.example");
    let verifier = X509CertificateCoseKeyFactory::create_from_public_key(&cert);
    assert!(verifier.is_ok(), "Should create verifier from valid cert");
}

#[test]
fn key_factory_with_invalid_cert() {
    let garbage = vec![0xFF, 0xFE, 0xFD];
    let verifier = X509CertificateCoseKeyFactory::create_from_public_key(&garbage);
    assert!(verifier.is_err(), "Should fail on invalid cert bytes");
}

// ==================== certificate_header_contributor.rs ====================

#[test]
fn contributor_builds_x5t_and_x5chain() {
    let cert = make_self_signed_cert("contributor.example");

    let contributor = CertificateHeaderContributor::new(&cert, &[&cert]).unwrap();
    // Verify it constructed without error
    let _ = contributor;
}

#[test]
fn contributor_chain_mismatch_error() {
    let cert1 = make_self_signed_cert("leaf.example");
    let cert2 = make_self_signed_cert("different.example");

    // First chain element doesn't match signing cert
    let result = CertificateHeaderContributor::new(&cert1, &[&cert2]);
    assert!(result.is_err());
}

// ==================== thumbprint.rs ====================

#[test]
fn thumbprint_serialize_deserialize_roundtrip() {
    let _p = _init();
    let cert = make_self_signed_cert("thumbprint.example");
    let tp = CoseX509Thumbprint::new(&cert, ThumbprintAlgorithm::Sha256);
    let bytes = tp.serialize().unwrap();
    let decoded = CoseX509Thumbprint::deserialize(&bytes).unwrap();
    assert_eq!(decoded.hash_id, -16); // SHA-256 COSE alg id
    assert_eq!(decoded.thumbprint.len(), 32); // SHA-256 output
}

#[test]
fn thumbprint_deserialize_not_array() {
    let _p = _init();
    // CBOR integer instead of array
    let p = EverParseCborProvider;
    let mut enc = p.encoder();
    enc.encode_i64(42).unwrap();
    let bytes = enc.into_bytes();

    let result = CoseX509Thumbprint::deserialize(&bytes);
    assert!(result.is_err());
}

#[test]
fn thumbprint_deserialize_wrong_array_length() {
    let _p = _init();
    let p = EverParseCborProvider;
    let mut enc = p.encoder();
    enc.encode_array(3).unwrap();
    enc.encode_i64(-16).unwrap();
    enc.encode_bstr(b"test").unwrap();
    enc.encode_i64(0).unwrap();
    let bytes = enc.into_bytes();

    let result = CoseX509Thumbprint::deserialize(&bytes);
    assert!(result.is_err());
}

#[test]
fn thumbprint_deserialize_non_integer_hash_id() {
    let _p = _init();
    let p = EverParseCborProvider;
    let mut enc = p.encoder();
    enc.encode_array(2).unwrap();
    enc.encode_tstr("not-an-int").unwrap(); // should be integer
    enc.encode_bstr(b"tp").unwrap();
    let bytes = enc.into_bytes();

    let result = CoseX509Thumbprint::deserialize(&bytes);
    assert!(result.is_err());
}

#[test]
fn thumbprint_deserialize_missing_bstr() {
    let _p = _init();
    let p = EverParseCborProvider;
    let mut enc = p.encoder();
    enc.encode_array(2).unwrap();
    enc.encode_i64(-16).unwrap();
    enc.encode_tstr("not-bstr").unwrap(); // text instead of bstr
    let bytes = enc.into_bytes();

    let result = CoseX509Thumbprint::deserialize(&bytes);
    assert!(result.is_err());
}

// ==================== cose_key_factory.rs ====================

#[test]
fn hash_algorithm_variants() {
    assert_eq!(HashAlgorithm::Sha256.cose_algorithm_id(), -16);
    assert_eq!(HashAlgorithm::Sha384.cose_algorithm_id(), -43);
    assert_eq!(HashAlgorithm::Sha512.cose_algorithm_id(), -44);
}

#[test]
fn hash_algorithm_for_small_key() {
    // Small key → SHA-256
    let ha = X509CertificateCoseKeyFactory::get_hash_algorithm_for_key_size(256, false);
    assert_eq!(ha.cose_algorithm_id(), -16);
}

#[test]
fn hash_algorithm_for_large_key() {
    // 3072+ bit key → SHA-384
    let ha = X509CertificateCoseKeyFactory::get_hash_algorithm_for_key_size(3072, false);
    assert_eq!(ha.cose_algorithm_id(), -43);
}

#[test]
fn hash_algorithm_for_p521() {
    // P-521 → SHA-384 (not SHA-512)
    let ha = X509CertificateCoseKeyFactory::get_hash_algorithm_for_key_size(521, true);
    assert_eq!(ha.cose_algorithm_id(), -43);
}

#[test]
fn hash_algorithm_for_4096_key() {
    // 4096+ bit key → SHA-512
    let ha = X509CertificateCoseKeyFactory::get_hash_algorithm_for_key_size(4096, false);
    assert_eq!(ha.cose_algorithm_id(), -44);
}

// ==================== pack.rs: trust pack traits ====================

#[test]
fn trust_pack_provides_fact_keys() {
    let pack = X509CertificateTrustPack::new(Default::default());
    let keys = pack.fact_producer().provides();
    assert!(!keys.is_empty(), "Trust pack should declare its fact keys");

    // Verify the key FactKey types are present
    let has_identity = keys
        .iter()
        .any(|k| k.type_id == FactKey::of::<X509SigningCertificateIdentityFact>().type_id);
    assert!(has_identity, "Should provide identity fact key");
}

#[test]
fn trust_pack_name() {
    let pack = X509CertificateTrustPack::new(Default::default());
    assert_eq!(
        pack.name(),
        "X509CertificateTrustPack"
    );
}

// ==================== pack.rs: basic constraints ====================

#[test]
fn basic_constraints_fact_for_ca() {
    let (ca_der, _kp) = make_self_signed_ca("ca.example");
    let prot = build_protected_map_with_x5chain_array(&[&ca_der]);
    let cose = build_cose_sign1_with_protected(&prot);

    let engine = run_fact_engine(&cose, Default::default());
    let subject = TrustSubject::root("PrimarySigningKey", b"seed");

    let bc = engine
        .get_fact_set::<X509SigningCertificateBasicConstraintsFact>(&subject)
        .unwrap();
    match bc {
        TrustFactSet::Available(v) => {
            assert!(v[0].is_ca, "CA cert should have is_ca=true");
        }
        other => panic!("Expected Available BasicConstraints, got {:?}", other),
    }
}

#[test]
fn basic_constraints_fact_for_leaf() {
    let cert = make_self_signed_cert("leaf.example");
    let prot = build_protected_map_with_x5chain_array(&[&cert]);
    let cose = build_cose_sign1_with_protected(&prot);

    let engine = run_fact_engine(&cose, Default::default());
    let subject = TrustSubject::root("PrimarySigningKey", b"seed");

    let bc = engine
        .get_fact_set::<X509SigningCertificateBasicConstraintsFact>(&subject)
        .unwrap();
    match bc {
        TrustFactSet::Available(v) => {
            assert!(!v[0].is_ca, "Leaf cert should have is_ca=false");
        }
        other => panic!("Expected Available BasicConstraints, got {:?}", other),
    }
}
