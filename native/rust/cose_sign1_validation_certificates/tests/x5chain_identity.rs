// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use cose_sign1_validation_certificates::facts::X509SigningCertificateIdentityFact;
use cose_sign1_validation_certificates::pack::X509CertificateTrustPack;
use cose_sign1_validation_trust::facts::TrustFactEngine;
use cose_sign1_validation_trust::policy::TrustPolicyBuilder;
use cose_sign1_validation_trust::subject::TrustSubject;
use cose_sign1_validation_trust::{TrustDecision, TrustEvaluationOptions};
use rcgen::{generate_simple_self_signed, CertifiedKey};
use std::sync::Arc;
use tinycbor::{Encode, Encoder};

fn build_cose_sign1_with_x5chain(cert_der: &[u8]) -> Vec<u8> {
    let mut buf = vec![0u8; 2048];
    let buf_len = buf.len();
    let mut enc = Encoder(buf.as_mut_slice());

    enc.array(4).unwrap();

    // protected header bytes: {33: [ cert_der ]}
    // Build the inner map into a temporary buffer, then encode as bstr.
    let mut hdr_buf = vec![0u8; 1024];
    let hdr_len = hdr_buf.len();
    let mut hdr_enc = Encoder(hdr_buf.as_mut_slice());
    hdr_enc.map(1).unwrap();
    (33i64).encode(&mut hdr_enc).unwrap();
    hdr_enc.array(1).unwrap();
    cert_der.encode(&mut hdr_enc).unwrap();
    let used_hdr = hdr_len - hdr_enc.0.len();
    let protected_bytes = &hdr_buf[..used_hdr];

    protected_bytes.encode(&mut enc).unwrap();

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
fn x5chain_identity_fact_is_produced() {
    let CertifiedKey { cert, .. } =
        generate_simple_self_signed(vec!["test-leaf.example".to_string()]).unwrap();
    let cert_der = cert.der().as_ref().to_vec();

    let cose = build_cose_sign1_with_x5chain(&cert_der);

    let producer = Arc::new(X509CertificateTrustPack::default());
    let engine = TrustFactEngine::new(vec![producer])
        .with_cose_sign1_bytes(Arc::from(cose.into_boxed_slice()));

    let subject = TrustSubject::root("PrimarySigningKey", b"seed");
    let policy = TrustPolicyBuilder::new()
        .require_fact(cose_sign1_validation_trust::facts::FactKey::of::<
            X509SigningCertificateIdentityFact,
        >())
        .add_trust_source(Arc::new(cose_sign1_validation_trust::rules::FnRule::new(
            "allow",
            |_e: &TrustFactEngine, _s: &TrustSubject| Ok(TrustDecision::trusted()),
        )))
        .build();

    let plan = policy.compile();
    assert!(
        plan.evaluate(&engine, &subject, &TrustEvaluationOptions::default())
            .unwrap()
            .is_trusted
    );

    let facts = engine
        .get_facts::<X509SigningCertificateIdentityFact>(&subject)
        .unwrap();
    assert_eq!(1, facts.len());
    assert_eq!(40, facts[0].certificate_thumbprint.len());
    assert!(!facts[0].subject.is_empty());
    assert!(!facts[0].issuer.is_empty());
    assert!(!facts[0].serial_number.is_empty());
}
