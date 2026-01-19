// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use cose_sign1_validation::fluent::*;
use cose_sign1_validation_transparent_mst::facts::MstReceiptPresentFact;
use cose_sign1_validation_transparent_mst::pack::{MstTrustPack, MST_RECEIPT_HEADER_LABEL};
use cose_sign1_validation_trust::facts::{TrustFactEngine, TrustFactSet};
use cose_sign1_validation_trust::subject::TrustSubject;
use std::sync::Arc;
use tinycbor::{Encode, Encoder};

fn build_cose_sign1_with_unprotected_receipts(receipts: &[&[u8]]) -> Vec<u8> {
    let mut buf = vec![0u8; 2048];
    let buf_len = buf.len();
    let mut enc = Encoder(buf.as_mut_slice());

    enc.array(4).unwrap();

    // protected header: bstr(CBOR map {1: -7})  (alg = ES256)
    let mut hdr_buf = vec![0u8; 64];
    let hdr_len = hdr_buf.len();
    let mut hdr_enc = Encoder(hdr_buf.as_mut_slice());
    hdr_enc.map(1).unwrap();
    (1i64).encode(&mut hdr_enc).unwrap();
    (-7i64).encode(&mut hdr_enc).unwrap();
    let used_hdr = hdr_len - hdr_enc.0.len();
    let protected_bytes = &hdr_buf[..used_hdr];
    protected_bytes.encode(&mut enc).unwrap();

    // unprotected header: map { MST_RECEIPT_HEADER_LABEL: [ bstr... ] }
    enc.map(1).unwrap();
    MST_RECEIPT_HEADER_LABEL.encode(&mut enc).unwrap();
    enc.array(receipts.len()).unwrap();
    for r in receipts {
        r.encode(&mut enc).unwrap();
    }

    // payload: embedded bstr
    b"payload".as_slice().encode(&mut enc).unwrap();

    // signature: b"sig"
    b"sig".as_slice().encode(&mut enc).unwrap();

    let used = buf_len - enc.0.len();
    buf.truncate(used);
    buf
}

fn main() {
    let receipts: [&[u8]; 1] = [b"receipt1".as_slice()];
    let cose = build_cose_sign1_with_unprotected_receipts(&receipts);

    let producers: Vec<Arc<dyn cose_sign1_validation_trust::facts::TrustFactProducer>> = vec![
        Arc::new(CoseSign1MessageFactProducer::new()),
        Arc::new(MstTrustPack {
            allow_network: false,
            offline_jwks_json: None,
            jwks_api_version: None,
        }),
    ];

    let engine =
        TrustFactEngine::new(producers).with_cose_sign1_bytes(Arc::from(cose.into_boxed_slice()));
    let subject = TrustSubject::message(b"seed");

    let present = engine
        .get_fact_set::<MstReceiptPresentFact>(&subject)
        .expect("fact eval failed");

    match present {
        TrustFactSet::Available(items) => {
            let is_present = items.iter().any(|f| f.present);
            println!("MST receipt present: {is_present}");
        }
        other => println!("unexpected: {:?}", other),
    }
}
