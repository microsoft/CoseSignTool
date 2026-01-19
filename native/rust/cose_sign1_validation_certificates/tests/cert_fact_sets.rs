// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use cose_sign1_validation_certificates::facts::{
    X509SigningCertificateBasicConstraintsFact, X509SigningCertificateEkuFact,
    X509SigningCertificateIdentityFact, X509SigningCertificateKeyUsageFact,
};
use cose_sign1_validation_certificates::pack::X509CertificateTrustPack;
use cose_sign1_validation_trust::facts::{TrustFactEngine, TrustFactSet};
use cose_sign1_validation_trust::subject::TrustSubject;
use rcgen::{
    CertificateParams, ExtendedKeyUsagePurpose, IsCa, KeyPair, KeyUsagePurpose,
    PKCS_ECDSA_P256_SHA256,
};
use std::sync::Arc;
use tinycbor::{Encode, Encoder};

fn build_cose_sign1_with_protected_header_map(protected_map_bytes: &[u8]) -> Vec<u8> {
    let mut buf = vec![0u8; 4096];
    let buf_len = buf.len();
    let mut enc = Encoder(buf.as_mut_slice());

    enc.array(4).unwrap();

    // protected header: bstr(CBOR map)
    protected_map_bytes.encode(&mut enc).unwrap();

    // unprotected header: {}
    enc.map(0).unwrap();

    // payload: null
    Option::<&[u8]>::None.encode(&mut enc).unwrap();

    // signature: b"sig"
    b"sig".as_slice().encode(&mut enc).unwrap();

    let used = buf_len - enc.0.len();
    buf.truncate(used);
    buf
}

fn build_protected_map_with_x5chain(cert_der: &[u8]) -> Vec<u8> {
    let mut hdr_buf = vec![0u8; 2048];
    let hdr_len = hdr_buf.len();
    let mut hdr_enc = Encoder(hdr_buf.as_mut_slice());

    // {33: [ cert_der ]}
    hdr_enc.map(1).unwrap();
    (33i64).encode(&mut hdr_enc).unwrap();
    hdr_enc.array(1).unwrap();
    cert_der.encode(&mut hdr_enc).unwrap();

    let used_hdr = hdr_len - hdr_enc.0.len();
    hdr_buf.truncate(used_hdr);
    hdr_buf
}

fn build_protected_empty_map() -> Vec<u8> {
    let mut hdr_buf = vec![0u8; 64];
    let hdr_len = hdr_buf.len();
    let mut hdr_enc = Encoder(hdr_buf.as_mut_slice());
    hdr_enc.map(0).unwrap();
    let used_hdr = hdr_len - hdr_enc.0.len();
    hdr_buf.truncate(used_hdr);
    hdr_buf
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

    let producer = Arc::new(X509CertificateTrustPack::default());
    let engine = TrustFactEngine::new(vec![producer])
        .with_cose_sign1_bytes(Arc::from(cose.into_boxed_slice()));

    let subject = TrustSubject::root("PrimarySigningKey", b"seed");

    let eku = engine
        .get_fact_set::<X509SigningCertificateEkuFact>(&subject)
        .unwrap();
    match eku {
        TrustFactSet::Available(v) => {
            assert!(v.iter().any(|f| f.oid_value == "1.3.6.1.5.5.7.3.3"));
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
    let producer = Arc::new(X509CertificateTrustPack::default());
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

    let producer = Arc::new(X509CertificateTrustPack::default());
    let engine = TrustFactEngine::new(vec![producer])
        .with_cose_sign1_bytes(Arc::from(cose.into_boxed_slice()));

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

    let producer = Arc::new(X509CertificateTrustPack::default());
    let engine = TrustFactEngine::new(vec![producer])
        .with_cose_sign1_bytes(Arc::from(cose.into_boxed_slice()));

    let subject = TrustSubject::message(b"seed");

    let identity = engine
        .get_fact_set::<X509SigningCertificateIdentityFact>(&subject)
        .unwrap();

    match identity {
        TrustFactSet::Available(v) => assert!(v.is_empty()),
        _ => panic!("expected Available empty"),
    }
}
