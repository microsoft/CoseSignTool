// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use cose_sign1_validation_certificates::facts::X509X5ChainCertificateIdentityFact;
use cose_sign1_validation_certificates::pack::X509CertificateTrustPack;
use cose_sign1_validation_trust::facts::TrustFactEngine;
use cose_sign1_validation_trust::facts::TrustFactSet;
use cose_sign1_validation_trust::subject::TrustSubject;
use std::sync::Arc;
use tinycbor::{Encode, Encoder};

fn build_cose_sign1_with_x5chain(leaf_der: &[u8]) -> Vec<u8> {
    let mut buf = vec![0u8; 2048];
    let buf_len = buf.len();
    let mut enc = Encoder(buf.as_mut_slice());

    enc.array(4).unwrap();

    // protected header: bstr(CBOR map {1: -7, 33: bstr(cert_der)})
    let mut hdr_buf = vec![0u8; 1024];
    let hdr_len = hdr_buf.len();
    let mut hdr_enc = Encoder(hdr_buf.as_mut_slice());
    hdr_enc.map(2).unwrap();
    (1i64).encode(&mut hdr_enc).unwrap();
    (-7i64).encode(&mut hdr_enc).unwrap();
    (33i64).encode(&mut hdr_enc).unwrap();
    leaf_der.encode(&mut hdr_enc).unwrap();
    let used_hdr = hdr_len - hdr_enc.0.len();
    let protected_bytes = &hdr_buf[..used_hdr];
    protected_bytes.encode(&mut enc).unwrap();

    // unprotected header: empty map
    enc.map(0).unwrap();

    // payload: embedded bstr
    b"payload".as_slice().encode(&mut enc).unwrap();

    // signature: arbitrary bstr
    b"sig".as_slice().encode(&mut enc).unwrap();

    let used = buf_len - enc.0.len();
    buf.truncate(used);
    buf
}

fn main() {
    // Generate a self-signed certificate for the example.
    let rcgen::CertifiedKey { cert, .. } =
        rcgen::generate_simple_self_signed(vec!["example-leaf".to_string()]).expect("rcgen failed");
    let der = cert.der().to_vec();

    let cose = build_cose_sign1_with_x5chain(&der);

    let message_subject = TrustSubject::message(b"seed");
    let signing_key_subject = TrustSubject::primary_signing_key(&message_subject);

    let pack = Arc::new(X509CertificateTrustPack::default());
    let engine =
        TrustFactEngine::new(vec![pack]).with_cose_sign1_bytes(Arc::from(cose.into_boxed_slice()));

    let facts = engine
        .get_fact_set::<X509X5ChainCertificateIdentityFact>(&signing_key_subject)
        .expect("fact eval failed");

    match facts {
        TrustFactSet::Available(items) => {
            println!("x5chain items: {}", items.len());
            for f in items {
                println!("thumbprint: {}", f.certificate_thumbprint);
                println!("subject: {}", f.subject);
                println!("issuer: {}", f.issuer);
            }
        }
        other => {
            println!("unexpected fact set: {:?}", other);
        }
    }
}
