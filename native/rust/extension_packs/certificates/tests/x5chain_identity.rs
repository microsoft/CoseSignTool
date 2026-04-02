// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use cbor_primitives::{CborEncoder, CborProvider};
use cbor_primitives_everparse::EverParseCborProvider;
use cose_sign1_certificates::validation::facts::X509SigningCertificateIdentityFact;
use cose_sign1_certificates::validation::pack::X509CertificateTrustPack;
use cose_sign1_primitives::CoseSign1Message;
use cose_sign1_validation_primitives::facts::TrustFactEngine;
use cose_sign1_validation_primitives::policy::TrustPolicyBuilder;
use cose_sign1_validation_primitives::subject::TrustSubject;
use cose_sign1_validation_primitives::{TrustDecision, TrustEvaluationOptions};
use rcgen::{generate_simple_self_signed, CertifiedKey};
use std::sync::Arc;

fn build_cose_sign1_with_x5chain(cert_der: &[u8]) -> Vec<u8> {
    let p = EverParseCborProvider;
    let mut enc = p.encoder();

    enc.encode_array(4).unwrap();

    // protected header bytes: {33: [ cert_der ]}
    // Build the inner map into a temporary buffer, then encode as bstr.
    let mut hdr_enc = p.encoder();
    hdr_enc.encode_map(1).unwrap();
    hdr_enc.encode_i64(33).unwrap();
    hdr_enc.encode_array(1).unwrap();
    hdr_enc.encode_bstr(cert_der).unwrap();
    let protected_bytes = hdr_enc.into_bytes();

    enc.encode_bstr(&protected_bytes).unwrap();

    // unprotected header: {}
    enc.encode_map(0).unwrap();

    // payload: null
    enc.encode_null().unwrap();

    // signature: b"sig"
    enc.encode_bstr(b"sig").unwrap();

    enc.into_bytes()
}

#[test]
fn x5chain_identity_fact_is_produced() {
    let CertifiedKey { cert, .. } =
        generate_simple_self_signed(vec!["test-leaf.example".to_string()]).unwrap();
    let cert_der = cert.der().as_ref().to_vec();

    let cose = build_cose_sign1_with_x5chain(&cert_der);

    let producer = Arc::new(X509CertificateTrustPack::new(Default::default()));
    let msg = Arc::new(CoseSign1Message::parse(&cose).unwrap());
    let engine = TrustFactEngine::new(vec![producer])
        .with_cose_sign1_bytes(Arc::from(cose.into_boxed_slice()))
        .with_cose_sign1_message(msg);

    let subject = TrustSubject::root("PrimarySigningKey", b"seed");
    let policy = TrustPolicyBuilder::new()
        .require_fact(cose_sign1_validation_primitives::facts::FactKey::of::<
            X509SigningCertificateIdentityFact,
        >())
        .add_trust_source(Arc::new(
            cose_sign1_validation_primitives::rules::FnRule::new(
                "allow",
                |_e: &TrustFactEngine, _s: &TrustSubject| Ok(TrustDecision::trusted()),
            ),
        ))
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
    assert_eq!(64, facts[0].certificate_thumbprint.len());
    assert!(!facts[0].subject.is_empty());
    assert!(!facts[0].issuer.is_empty());
    assert!(!facts[0].serial_number.is_empty());
}
