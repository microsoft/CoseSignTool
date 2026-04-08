// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use cbor_primitives::{CborEncoder, CborProvider};
use cbor_primitives_everparse::EverParseCborProvider;
use cose_sign1_certificates::validation::facts::{
    X509SigningCertificateBasicConstraintsFact, X509SigningCertificateEkuFact,
    X509SigningCertificateIdentityFact, X509SigningCertificateKeyUsageFact,
};
use cose_sign1_certificates::validation::pack::X509CertificateTrustPack;
use cose_sign1_primitives::CoseSign1Message;
use cose_sign1_validation_primitives::facts::{TrustFactEngine, TrustFactSet};
use cose_sign1_validation_primitives::subject::TrustSubject;
use rcgen::{
    CertificateParams, ExtendedKeyUsagePurpose, IsCa, KeyPair, KeyUsagePurpose,
    PKCS_ECDSA_P256_SHA256,
};
use std::sync::Arc;

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

fn build_protected_map_with_x5chain(cert_der: &[u8]) -> Vec<u8> {
    let p = EverParseCborProvider;
    let mut hdr_enc = p.encoder();

    // {33: [ cert_der ]}
    hdr_enc.encode_map(1).unwrap();
    hdr_enc.encode_i64(33).unwrap();
    hdr_enc.encode_array(1).unwrap();
    hdr_enc.encode_bstr(cert_der).unwrap();

    hdr_enc.into_bytes()
}

fn build_protected_empty_map() -> Vec<u8> {
    let p = EverParseCborProvider;
    let mut hdr_enc = p.encoder();
    hdr_enc.encode_map(0).unwrap();
    hdr_enc.into_bytes()
}

fn make_cert_with_extensions() -> Vec<u8> {
    let mut params = CertificateParams::new(vec!["signing.example".to_string()]).unwrap();
    params.is_ca = IsCa::NoCa;
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::CodeSigning];

    let key_pair = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
    let cert = params.self_signed(&key_pair).unwrap();
    cert.der().as_ref().to_vec()
}

#[test]
fn signing_certificate_facts_are_available_when_x5chain_present() {
    let cert_der = make_cert_with_extensions();
    let protected_map = build_protected_map_with_x5chain(&cert_der);
    let cose = build_cose_sign1_with_protected_header_map(&protected_map);

    let producer = Arc::new(X509CertificateTrustPack::new(Default::default()));
    let msg = Arc::new(CoseSign1Message::parse(&cose).unwrap());
    let engine = TrustFactEngine::new(vec![producer])
        .with_cose_sign1_bytes(Arc::from(cose.into_boxed_slice()))
        .with_cose_sign1_message(msg);

    let subject = TrustSubject::root("PrimarySigningKey", b"seed");

    let eku = engine
        .get_fact_set::<X509SigningCertificateEkuFact>(&subject)
        .unwrap();
    match eku {
        TrustFactSet::Available(v) => {
            assert!(v.iter().any(|f| &*f.oid_value == "1.3.6.1.5.5.7.3.3"));
        }
        _ => panic!("expected Available EKU facts"),
    }

    let ku = engine
        .get_fact_set::<X509SigningCertificateKeyUsageFact>(&subject)
        .unwrap();
    match ku {
        TrustFactSet::Available(v) => {
            assert_eq!(v.len(), 1);
            assert!(v[0].usages.iter().any(|u| u == "DigitalSignature"));
        }
        _ => panic!("expected Available key usage facts"),
    }

    let bc = engine
        .get_fact_set::<X509SigningCertificateBasicConstraintsFact>(&subject)
        .unwrap();
    match bc {
        TrustFactSet::Available(v) => {
            assert_eq!(v.len(), 1);
            assert!(!v[0].is_ca);
        }
        _ => panic!("expected Available basic constraints facts"),
    }
}

#[test]
fn signing_certificate_identity_is_missing_when_no_cose_bytes() {
    let producer = Arc::new(X509CertificateTrustPack::new(Default::default()));
    let engine = TrustFactEngine::new(vec![producer]);

    let subject = TrustSubject::root("PrimarySigningKey", b"seed");

    let identity = engine
        .get_fact_set::<X509SigningCertificateIdentityFact>(&subject)
        .unwrap();

    assert!(identity.is_missing());
}

#[test]
fn signing_certificate_identity_is_missing_when_no_certificate_headers() {
    let protected_map = build_protected_empty_map();
    let cose = build_cose_sign1_with_protected_header_map(&protected_map);

    let producer = Arc::new(X509CertificateTrustPack::new(Default::default()));
    let msg = Arc::new(CoseSign1Message::parse(&cose).unwrap());
    let engine = TrustFactEngine::new(vec![producer])
        .with_cose_sign1_bytes(Arc::from(cose.into_boxed_slice()))
        .with_cose_sign1_message(msg);

    let subject = TrustSubject::root("PrimarySigningKey", b"seed");

    let identity = engine
        .get_fact_set::<X509SigningCertificateIdentityFact>(&subject)
        .unwrap();

    assert!(identity.is_missing());
}

#[test]
fn non_applicable_subject_is_available_empty_even_if_cert_present() {
    let cert_der = make_cert_with_extensions();
    let protected_map = build_protected_map_with_x5chain(&cert_der);
    let cose = build_cose_sign1_with_protected_header_map(&protected_map);

    let producer = Arc::new(X509CertificateTrustPack::new(Default::default()));
    let msg = Arc::new(CoseSign1Message::parse(&cose).unwrap());
    let engine = TrustFactEngine::new(vec![producer])
        .with_cose_sign1_bytes(Arc::from(cose.into_boxed_slice()))
        .with_cose_sign1_message(msg);

    let subject = TrustSubject::message(b"seed");

    let identity = engine
        .get_fact_set::<X509SigningCertificateIdentityFact>(&subject)
        .unwrap();

    match identity {
        TrustFactSet::Available(v) => assert!(v.is_empty()),
        _ => panic!("expected Available empty"),
    }
}
