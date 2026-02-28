// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use cbor_primitives::{CborEncoder, CborProvider};
use cbor_primitives_everparse::EverParseCborProvider;
use cose_sign1_transparent_mst::validation::facts::MstReceiptPresentFact;
use cose_sign1_transparent_mst::validation::pack::{MstTrustPack, MST_RECEIPT_HEADER_LABEL};
use cose_sign1_validation::fluent::*;
use cose_sign1_validation_primitives::facts::{TrustFactEngine, TrustFactSet};
use cose_sign1_validation_primitives::subject::TrustSubject;
use std::sync::Arc;

fn build_cose_sign1_with_unprotected_receipts(receipts: &[&[u8]]) -> Vec<u8> {
    let p = EverParseCborProvider;
    let mut enc = p.encoder();

    enc.encode_array(4).unwrap();

    // protected header: bstr(CBOR map {1: -7})  (alg = ES256)
    let mut hdr_enc = p.encoder();
    hdr_enc.encode_map(1).unwrap();
    hdr_enc.encode_i64(1).unwrap();
    hdr_enc.encode_i64(-7).unwrap();
    let protected_bytes = hdr_enc.into_bytes();
    enc.encode_bstr(&protected_bytes).unwrap();

    // unprotected header: map { MST_RECEIPT_HEADER_LABEL: [ bstr... ] }
    enc.encode_map(1).unwrap();
    enc.encode_i64(MST_RECEIPT_HEADER_LABEL).unwrap();
    enc.encode_array(receipts.len()).unwrap();
    for r in receipts {
        enc.encode_bstr(r).unwrap();
    }

    // payload: embedded bstr
    enc.encode_bstr(b"payload").unwrap();

    // signature: b"sig"
    enc.encode_bstr(b"sig").unwrap();

    enc.into_bytes()
}

fn main() {
    let receipts: [&[u8]; 1] = [b"receipt1".as_slice()];
    let cose = build_cose_sign1_with_unprotected_receipts(&receipts);

    let subject = TrustSubject::message(cose.as_slice());

    let producers: Vec<Arc<dyn cose_sign1_validation_primitives::facts::TrustFactProducer>> = vec![
        Arc::new(CoseSign1MessageFactProducer::new()),
        Arc::new(MstTrustPack {
            allow_network: false,
            offline_jwks_json: None,
            jwks_api_version: None,
        }),
    ];

    let engine =
        TrustFactEngine::new(producers).with_cose_sign1_bytes(Arc::from(cose.into_boxed_slice()));

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
