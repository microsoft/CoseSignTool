// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use cbor_primitives_everparse::EverParseCborProvider;
use cose_sign1_primitives::CoseSign1Message;
use cose_sign1_certificates::validation::facts::{
    CertificateSigningKeyTrustFact, X509ChainElementIdentityFact, X509ChainTrustedFact,
    X509X5ChainCertificateIdentityFact,
};
use cose_sign1_certificates::validation::pack::X509CertificateTrustPack;
use cose_sign1_validation_primitives::facts::{TrustFactEngine, TrustFactSet};
use cose_sign1_validation_primitives::subject::TrustSubject;
use cbor_primitives::{CborEncoder, CborProvider};
use std::sync::Arc;
use rcgen::{generate_simple_self_signed, CertificateParams, DnType, KeyPair, PKCS_ECDSA_P256_SHA256};

fn build_protected_map_with_alg_only() -> Vec<u8> {
    let p = EverParseCborProvider;
    let mut hdr_enc = p.encoder();

    // { 1: -7 }
    hdr_enc.encode_map(1).unwrap();
    hdr_enc.encode_i64(1).unwrap();
    hdr_enc.encode_i64(-7).unwrap();

    hdr_enc.into_bytes()
}

fn build_cose_sign1_with_protected_header_map(protected_map_bytes: &[u8]) -> Vec<u8> {
    let p = EverParseCborProvider;
    let mut enc = p.encoder();

    enc.encode_array(4).unwrap();

    // protected header: bstr(CBOR map)
    enc.encode_bstr(protected_map_bytes).unwrap();

    // unprotected header: {}
    enc.encode_map(0).unwrap();

    // payload: null
    enc.encode_null().unwrap();

    // signature: b"sig"
    enc.encode_bstr(b"sig").unwrap();

    enc.into_bytes()
}

#[test]
fn chain_identity_and_trust_are_available_empty_for_non_signing_key_subjects() {
    let protected_map = build_protected_map_with_alg_only();
    let cose = build_cose_sign1_with_protected_header_map(&protected_map);

    let producer = Arc::new(X509CertificateTrustPack::new(Default::default()));
    let engine = TrustFactEngine::new(vec![producer])
        .with_cose_sign1_bytes(Arc::from(cose.into_boxed_slice()));

    let subject = TrustSubject::message(b"seed");

    let chain_identity = engine
        .get_fact_set::<X509X5ChainCertificateIdentityFact>(&subject)
        .unwrap();
    match chain_identity {
        TrustFactSet::Available(v) => assert!(v.is_empty()),
        _ => panic!("expected Available/empty"),
    }

    let chain_elements = engine
        .get_fact_set::<X509ChainElementIdentityFact>(&subject)
        .unwrap();
    match chain_elements {
        TrustFactSet::Available(v) => assert!(v.is_empty()),
        _ => panic!("expected Available/empty"),
    }

    let chain_trusted = engine
        .get_fact_set::<X509ChainTrustedFact>(&subject)
        .unwrap();
    match chain_trusted {
        TrustFactSet::Available(v) => assert!(v.is_empty()),
        _ => panic!("expected Available/empty"),
    }

    let signing_key_trust = engine
        .get_fact_set::<CertificateSigningKeyTrustFact>(&subject)
        .unwrap();
    match signing_key_trust {
        TrustFactSet::Available(v) => assert!(v.is_empty()),
        _ => panic!("expected Available/empty"),
    }
}

#[test]
fn chain_trust_is_missing_when_no_cose_bytes() {
    let producer = Arc::new(X509CertificateTrustPack::new(Default::default()));
    let engine = TrustFactEngine::new(vec![producer]);

    let subject = TrustSubject::root("PrimarySigningKey", b"seed");

    assert!(engine
        .get_fact_set::<X509ChainTrustedFact>(&subject)
        .unwrap()
        .is_missing());
    assert!(engine
        .get_fact_set::<CertificateSigningKeyTrustFact>(&subject)
        .unwrap()
        .is_missing());
}

#[test]
fn chain_identity_and_trust_are_missing_when_no_x5chain_headers_present() {
    let protected_map = build_protected_map_with_alg_only();
    let cose = build_cose_sign1_with_protected_header_map(&protected_map);

    let producer = Arc::new(X509CertificateTrustPack::new(Default::default()));
    let engine = TrustFactEngine::new(vec![producer])
        .with_cose_sign1_bytes(Arc::from(cose.into_boxed_slice()));

    let subject = TrustSubject::root("PrimarySigningKey", b"seed");

    assert!(engine
        .get_fact_set::<X509X5ChainCertificateIdentityFact>(&subject)
        .unwrap()
        .is_missing());
    assert!(engine
        .get_fact_set::<X509ChainTrustedFact>(&subject)
        .unwrap()
        .is_missing());
}

fn protected_map_x5chain_array(certs: &[Vec<u8>]) -> Vec<u8> {
    let p = EverParseCborProvider;
    let mut hdr_enc = p.encoder();

    hdr_enc.encode_map(2).unwrap();
    hdr_enc.encode_i64(1).unwrap();
    hdr_enc.encode_i64(-7).unwrap();
    hdr_enc.encode_i64(33).unwrap();
    hdr_enc.encode_array(certs.len()).unwrap();
    for c in certs {
        hdr_enc.encode_bstr(c.as_slice()).unwrap();
    }

    hdr_enc.into_bytes()
}

#[test]
fn chain_trust_reports_trust_evaluation_disabled_when_not_trusting_embedded_chain() {
    let leaf = generate_simple_self_signed(vec!["leaf.example".to_string()]).unwrap();
    let leaf_der = leaf.cert.der().as_ref().to_vec();

    let protected = protected_map_x5chain_array(&[leaf_der]);
    let cose = build_cose_sign1_with_protected_header_map(protected.as_slice());

    let parsed = CoseSign1Message::parse(cose.as_slice())
        .expect("parse cose");

    let producer = Arc::new(X509CertificateTrustPack::new(Default::default()));
    let engine = TrustFactEngine::new(vec![producer])
        .with_cose_sign1_bytes(Arc::from(cose.clone().into_boxed_slice()))
        .with_cose_sign1_message(Arc::new(parsed));

    let subject = TrustSubject::root("PrimarySigningKey", b"seed");
    let trusted = engine.get_fact_set::<X509ChainTrustedFact>(&subject).unwrap();

    let TrustFactSet::Available(v) = trusted else {
        panic!("expected Available, got {trusted:?}");
    };

    assert_eq!(1, v.len());
    assert!(v[0].chain_built);
    assert!(!v[0].is_trusted);
    assert_eq!(Some("TrustEvaluationDisabled".to_string()), v[0].status_summary);
}

#[test]
fn chain_trust_reports_not_well_formed_when_trusting_embedded_chain_but_chain_is_invalid() {
    // NOTE: `generate_simple_self_signed` can yield identical subject/issuer DNs regardless of the
    // SANs passed in, which can accidentally make the chain look well-formed. Use explicit DNs.
    let key_pair_1 = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
    let mut params_1 = CertificateParams::new(Vec::<String>::new()).unwrap();
    params_1
        .distinguished_name
        .push(DnType::CommonName, "c1.example");
    let c1 = params_1.self_signed(&key_pair_1).unwrap();

    let key_pair_2 = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
    let mut params_2 = CertificateParams::new(Vec::<String>::new()).unwrap();
    params_2
        .distinguished_name
        .push(DnType::CommonName, "c2.example");
    let c2 = params_2.self_signed(&key_pair_2).unwrap();

    // Two unrelated self-signed certs => issuer/subject chain won't match.
    let protected = protected_map_x5chain_array(&[
        c1.der().as_ref().to_vec(),
        c2.der().as_ref().to_vec(),
    ]);
    let cose = build_cose_sign1_with_protected_header_map(protected.as_slice());

    let producer = Arc::new(X509CertificateTrustPack::new(
        cose_sign1_certificates::validation::pack::CertificateTrustOptions {
            trust_embedded_chain_as_trusted: true,
            ..Default::default()
        },
    ));

    let parsed = CoseSign1Message::parse(cose.as_slice())
        .expect("parse cose");

    let engine = TrustFactEngine::new(vec![producer])
        .with_cose_sign1_bytes(Arc::from(cose.clone().into_boxed_slice()))
        .with_cose_sign1_message(Arc::new(parsed));

    let subject = TrustSubject::root("PrimarySigningKey", b"seed");
    let trusted = engine.get_fact_set::<X509ChainTrustedFact>(&subject).unwrap();

    let TrustFactSet::Available(v) = trusted else {
        panic!("expected Available, got {trusted:?}");
    };

    assert_eq!(1, v.len());
    assert!(v[0].chain_built);
    assert!(!v[0].is_trusted);
    assert_eq!(Some("EmbeddedChainNotWellFormed".to_string()), v[0].status_summary);
}
