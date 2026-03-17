// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use cbor_primitives::{CborEncoder, CborProvider};
use cbor_primitives_everparse::EverParseCborProvider;
use cose_sign1_certificates::validation::facts::X509X5ChainCertificateIdentityFact;
use cose_sign1_certificates::validation::pack::X509CertificateTrustPack;
use cose_sign1_validation_primitives::facts::TrustFactEngine;
use cose_sign1_validation_primitives::facts::TrustFactSet;
use cose_sign1_validation_primitives::subject::TrustSubject;
use std::sync::Arc;

fn build_cose_sign1_with_x5chain(leaf_der: &[u8]) -> Vec<u8> {
    let p = EverParseCborProvider;
    let mut enc = p.encoder();

    enc.encode_array(4).unwrap();

    // protected header: bstr(CBOR map {1: -7, 33: bstr(cert_der)})
    let mut hdr_enc = p.encoder();
    hdr_enc.encode_map(2).unwrap();
    hdr_enc.encode_i64(1).unwrap();
    hdr_enc.encode_i64(-7).unwrap();
    hdr_enc.encode_i64(33).unwrap();
    hdr_enc.encode_bstr(leaf_der).unwrap();
    let protected_bytes = hdr_enc.into_bytes();
    enc.encode_bstr(&protected_bytes).unwrap();

    // unprotected header: empty map
    enc.encode_map(0).unwrap();

    // payload: embedded bstr
    enc.encode_bstr(b"payload").unwrap();

    // signature: arbitrary bstr
    enc.encode_bstr(b"sig").unwrap();

    enc.into_bytes()
}

fn main() {
    // Generate a self-signed certificate for the example.
    let rcgen::CertifiedKey { cert, .. } =
        rcgen::generate_simple_self_signed(vec!["example-leaf".to_string()]).expect("rcgen failed");
    let der = cert.der().to_vec();

    let cose = build_cose_sign1_with_x5chain(&der);

    let message_subject = TrustSubject::message(cose.as_slice());
    let signing_key_subject = TrustSubject::primary_signing_key(&message_subject);

    let pack = Arc::new(X509CertificateTrustPack::new(Default::default()));
    let engine =
        TrustFactEngine::new(vec![pack]).with_cose_sign1_bytes(Arc::from(cose.into_boxed_slice()));

    let facts = engine
        .get_fact_set::<X509X5ChainCertificateIdentityFact>(&signing_key_subject)
        .expect("fact eval failed");

    match facts {
        TrustFactSet::Available(items) => {
            // Example-only: log only derived, non-sensitive metadata (counts and booleans).
            let count = items.len();
            println!("x5chain items: {}", count);
            for f in &items {
                let tp_len = f.certificate_thumbprint.len();
                let has_subject = !f.subject.is_empty();
                let has_issuer = !f.issuer.is_empty();
                println!("thumbprint: [{} bytes]", tp_len);
                println!("subject: [present={}]", has_subject);
                println!("issuer: [present={}]", has_issuer);
            }
        }
        _other => {
            println!("unexpected fact set variant");
        }
    }
}
