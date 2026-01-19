// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use cose_sign1_validation_certificates::facts::{
    CertificateSigningKeyTrustFact, X509ChainElementIdentityFact, X509ChainTrustedFact,
    X509X5ChainCertificateIdentityFact,
};
use cose_sign1_validation_certificates::pack::X509CertificateTrustPack;
use cose_sign1_validation_trust::facts::{TrustFactEngine, TrustFactSet};
use cose_sign1_validation_trust::subject::TrustSubject;
use std::sync::Arc;
use tinycbor::{Encode, Encoder};

fn build_protected_map_with_alg_only() -> Vec<u8> {
    let mut hdr_buf = vec![0u8; 64];
    let hdr_len = hdr_buf.len();
    let mut hdr_enc = Encoder(hdr_buf.as_mut_slice());

    // { 1: -7 }
    hdr_enc.map(1).unwrap();
    (1i64).encode(&mut hdr_enc).unwrap();
    (-7i64).encode(&mut hdr_enc).unwrap();

    let used_hdr = hdr_len - hdr_enc.0.len();
    hdr_buf.truncate(used_hdr);
    hdr_buf
}

fn build_cose_sign1_with_protected_header_map(protected_map_bytes: &[u8]) -> Vec<u8> {
    let mut buf = vec![0u8; 1024];
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

#[test]
fn chain_identity_and_trust_are_available_empty_for_non_signing_key_subjects() {
    let protected_map = build_protected_map_with_alg_only();
    let cose = build_cose_sign1_with_protected_header_map(&protected_map);

    let producer = Arc::new(X509CertificateTrustPack::default());
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
    let producer = Arc::new(X509CertificateTrustPack::default());
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

    let producer = Arc::new(X509CertificateTrustPack::default());
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
