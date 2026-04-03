// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use cbor_primitives::{CborEncoder, CborProvider};
use cbor_primitives_everparse::EverParseCborProvider;
use cose_sign1_primitives::CoseSign1Message;
use cose_sign1_transparent_mst::validation::facts::{MstReceiptPresentFact, MstReceiptTrustedFact};
use cose_sign1_transparent_mst::validation::pack::{MstTrustPack, MST_RECEIPT_HEADER_LABEL};
use cose_sign1_validation::fluent::*;
use cose_sign1_validation_primitives::facts::{TrustFactEngine, TrustFactProducer, TrustFactSet};
use cose_sign1_validation_primitives::subject::TrustSubject;
use std::sync::Arc;

fn build_cose_sign1_with_unprotected_receipts(receipts: Option<&[&[u8]]>) -> Vec<u8> {
    let p = EverParseCborProvider;
    let mut enc = p.encoder();

    enc.encode_array(4).unwrap();

    // protected header bytes: encode empty map {} and wrap in bstr
    let mut hdr_enc = p.encoder();
    hdr_enc.encode_map(0).unwrap();
    let protected_bytes = hdr_enc.into_bytes();
    enc.encode_bstr(&protected_bytes).unwrap();

    // unprotected header: map
    match receipts {
        None => {
            enc.encode_map(0).unwrap();
        }
        Some(receipts) => {
            enc.encode_map(1).unwrap();
            enc.encode_i64(MST_RECEIPT_HEADER_LABEL).unwrap();
            enc.encode_array(receipts.len()).unwrap();
            for r in receipts {
                enc.encode_bstr(r).unwrap();
            }
        }
    }

    // payload: null
    enc.encode_null().unwrap();

    // signature: b"sig"
    enc.encode_bstr(b"sig").unwrap();

    enc.into_bytes()
}

fn build_cose_sign1_with_unprotected_other_key() -> Vec<u8> {
    let p = EverParseCborProvider;
    let mut enc = p.encoder();

    enc.encode_array(4).unwrap();

    // protected header bytes: encode empty map {} and wrap in bstr
    let mut hdr_enc = p.encoder();
    hdr_enc.encode_map(0).unwrap();
    let protected_bytes = hdr_enc.into_bytes();
    enc.encode_bstr(&protected_bytes).unwrap();

    // unprotected header: map with an unrelated label
    enc.encode_map(1).unwrap();
    enc.encode_i64(999).unwrap();
    enc.encode_bool(true).unwrap();

    // payload: null
    enc.encode_null().unwrap();

    // signature: b"sig"
    enc.encode_bstr(b"sig").unwrap();

    enc.into_bytes()
}

fn build_cose_sign1_with_unprotected_single_receipt_as_bstr(receipt: &[u8]) -> Vec<u8> {
    let p = EverParseCborProvider;
    let mut enc = p.encoder();

    enc.encode_array(4).unwrap();

    // protected header bytes: encode empty map {} and wrap in bstr
    let mut hdr_enc = p.encoder();
    hdr_enc.encode_map(0).unwrap();
    let protected_bytes = hdr_enc.into_bytes();
    enc.encode_bstr(&protected_bytes).unwrap();

    // unprotected header: map with MST receipt label -> single bstr
    enc.encode_map(1).unwrap();
    enc.encode_i64(MST_RECEIPT_HEADER_LABEL).unwrap();
    enc.encode_bstr(receipt).unwrap();

    // payload: null
    enc.encode_null().unwrap();

    // signature: b"sig"
    enc.encode_bstr(b"sig").unwrap();

    enc.into_bytes()
}

fn build_cose_sign1_with_unprotected_receipt_value(
    value_encoder: impl FnOnce(&mut cbor_primitives_everparse::EverParseEncoder),
) -> Vec<u8> {
    let p = EverParseCborProvider;
    let mut enc = p.encoder();

    enc.encode_array(4).unwrap();

    // protected header bytes: encode empty map {} and wrap in bstr
    let mut hdr_enc = p.encoder();
    hdr_enc.encode_map(0).unwrap();
    let protected_bytes = hdr_enc.into_bytes();
    enc.encode_bstr(&protected_bytes).unwrap();

    // unprotected header: map with MST receipt label
    enc.encode_map(1).unwrap();
    enc.encode_i64(MST_RECEIPT_HEADER_LABEL).unwrap();
    value_encoder(&mut enc);

    // payload: null
    enc.encode_null().unwrap();

    // signature: b"sig"
    enc.encode_bstr(b"sig").unwrap();

    enc.into_bytes()
}

fn build_malformed_cose_sign1_with_unprotected_array() -> Vec<u8> {
    let p = EverParseCborProvider;
    let mut enc = p.encoder();

    // COSE_Sign1 should be an array(4); make it an array(3) to trigger decode errors.
    enc.encode_array(3).unwrap();
    enc.encode_bstr(b"hdr").unwrap();
    enc.encode_array(0).unwrap();
    enc.encode_bstr(b"sig").unwrap();

    enc.into_bytes()
}

#[test]
fn mst_receipt_present_true_when_header_exists() {
    let receipts: [&[u8]; 2] = [b"r1".as_slice(), b"r2".as_slice()];
    let cose = build_cose_sign1_with_unprotected_receipts(Some(&receipts));

    let parsed = CoseSign1Message::parse(cose.as_slice()).expect("parse cose");

    let producer = Arc::new(MstTrustPack {
        allow_network: false,
        offline_jwks_json: None,
        jwks_api_version: None,
    });
    let engine = TrustFactEngine::new(vec![producer])
        .with_cose_sign1_bytes(Arc::from(cose.into_boxed_slice()))
        .with_cose_sign1_message(Arc::new(parsed));

    let subject = TrustSubject::message(b"seed");

    // Receipts are projected as counter-signature subjects.
    let cs = engine
        .get_fact_set::<CounterSignatureSubjectFact>(&subject)
        .unwrap();
    let cs = match cs {
        TrustFactSet::Available(v) => v,
        other => panic!("expected Available, got {other:?}"),
    };
    assert_eq!(2, cs.len());

    for c in cs {
        let facts = engine
            .get_facts::<MstReceiptPresentFact>(&c.subject)
            .unwrap();
        assert_eq!(1, facts.len());
        assert!(facts[0].present);
    }
}

#[test]
fn mst_receipt_present_errors_when_header_is_single_bstr() {
    let cose = build_cose_sign1_with_unprotected_single_receipt_as_bstr(b"r1");

    let parsed = CoseSign1Message::parse(cose.as_slice()).expect("parse cose");

    let producer = Arc::new(MstTrustPack {
        allow_network: false,
        offline_jwks_json: None,
        jwks_api_version: None,
    });
    let engine = TrustFactEngine::new(vec![producer])
        .with_cose_sign1_bytes(Arc::from(cose.into_boxed_slice()))
        .with_cose_sign1_message(Arc::new(parsed));

    let subject = TrustSubject::message(b"seed");

    // Canonical encoding is array-of-bstr; a single bstr is rejected.
    let err = engine
        .get_fact_set::<CounterSignatureSubjectFact>(&subject)
        .expect_err("expected fact production error");
    assert!(err.to_string().contains("invalid header"));
}

#[test]
fn mst_receipt_present_errors_when_header_value_is_not_an_array() {
    let cose = build_cose_sign1_with_unprotected_receipt_value(|enc| {
        enc.encode_bool(true).unwrap();
    });

    let parsed = CoseSign1Message::parse(cose.as_slice()).expect("parse cose");

    let producer = Arc::new(MstTrustPack {
        allow_network: false,
        offline_jwks_json: None,
        jwks_api_version: None,
    });
    let engine = TrustFactEngine::new(vec![producer])
        .with_cose_sign1_bytes(Arc::from(cose.into_boxed_slice()))
        .with_cose_sign1_message(Arc::new(parsed));

    let subject = TrustSubject::message(b"seed");

    let err = engine
        .get_fact_set::<CounterSignatureSubjectFact>(&subject)
        .expect_err("expected invalid header error");
    assert!(err.to_string().contains("invalid header"));
}

#[test]
fn mst_receipt_present_errors_when_header_array_contains_non_bstr_items() {
    let cose = build_cose_sign1_with_unprotected_receipt_value(|enc| {
        enc.encode_array(1).unwrap();
        enc.encode_i64(123).unwrap();
    });

    let parsed = CoseSign1Message::parse(cose.as_slice()).expect("parse cose");

    let producer = Arc::new(MstTrustPack {
        allow_network: false,
        offline_jwks_json: None,
        jwks_api_version: None,
    });
    let engine = TrustFactEngine::new(vec![producer])
        .with_cose_sign1_bytes(Arc::from(cose.into_boxed_slice()))
        .with_cose_sign1_message(Arc::new(parsed));

    let subject = TrustSubject::message(b"seed");

    let _err = engine
        .get_fact_set::<CounterSignatureSubjectFact>(&subject)
        .expect_err("expected fact production error");
}

#[test]
fn mst_receipt_present_errors_when_cose_container_is_malformed() {
    let cose = build_malformed_cose_sign1_with_unprotected_array();

    // Malformed COSE should fail to parse
    let err = CoseSign1Message::parse(cose.as_slice());
    assert!(err.is_err(), "expected decode failure for malformed COSE");
}

#[test]
fn mst_receipt_present_false_when_header_missing() {
    let cose = build_cose_sign1_with_unprotected_receipts(None);

    let parsed = CoseSign1Message::parse(cose.as_slice()).expect("parse cose");

    let producer = Arc::new(MstTrustPack {
        allow_network: false,
        offline_jwks_json: None,
        jwks_api_version: None,
    });
    let engine = TrustFactEngine::new(vec![producer])
        .with_cose_sign1_bytes(Arc::from(cose.into_boxed_slice()))
        .with_cose_sign1_message(Arc::new(parsed));

    let subject = TrustSubject::message(b"seed");
    let facts = engine
        .get_facts::<CounterSignatureSubjectFact>(&subject)
        .unwrap();
    assert!(facts.is_empty());
}

#[test]
fn mst_receipt_present_false_when_unprotected_has_other_key() {
    let cose = build_cose_sign1_with_unprotected_other_key();

    let parsed = CoseSign1Message::parse(cose.as_slice()).expect("parse cose");

    let producer = Arc::new(MstTrustPack {
        allow_network: false,
        offline_jwks_json: None,
        jwks_api_version: None,
    });
    let engine = TrustFactEngine::new(vec![producer])
        .with_cose_sign1_bytes(Arc::from(cose.into_boxed_slice()))
        .with_cose_sign1_message(Arc::new(parsed));

    let subject = TrustSubject::message(b"seed");
    let facts = engine
        .get_facts::<CounterSignatureSubjectFact>(&subject)
        .unwrap();
    assert!(facts.is_empty());
}

#[test]
fn mst_trusted_is_available_when_receipt_present_even_if_invalid() {
    let receipts: [&[u8]; 1] = [b"r1".as_slice()];
    let cose = build_cose_sign1_with_unprotected_receipts(Some(&receipts));

    let parsed = CoseSign1Message::parse(cose.as_slice()).expect("parse cose");

    let producer = Arc::new(MstTrustPack {
        allow_network: false,
        offline_jwks_json: None,
        jwks_api_version: None,
    });
    let engine = TrustFactEngine::new(vec![producer])
        .with_cose_sign1_bytes(Arc::from(cose.into_boxed_slice()))
        .with_cose_sign1_message(Arc::new(parsed));

    let subject = TrustSubject::message(b"seed");
    let cs = engine
        .get_facts::<CounterSignatureSubjectFact>(&subject)
        .unwrap();
    assert_eq!(1, cs.len());
    let cs_subject = &cs[0].subject;

    let set = engine
        .get_fact_set::<MstReceiptTrustedFact>(cs_subject)
        .unwrap();
    match set {
        TrustFactSet::Available(v) => {
            assert_eq!(1, v.len());
            assert!(!v[0].trusted);
            assert!(v[0]
                .details
                .as_deref()
                .unwrap_or("")
                .contains("receipt_decode_failed"));
        }
        _ => panic!("expected Available"),
    }
}

#[test]
fn mst_group_production_is_order_independent() {
    let receipts: [&[u8]; 1] = [b"r1".as_slice()];
    let cose = build_cose_sign1_with_unprotected_receipts(Some(&receipts));

    let parsed = CoseSign1Message::parse(cose.as_slice()).expect("parse cose");

    let producer = Arc::new(MstTrustPack {
        allow_network: false,
        offline_jwks_json: Some("{\"keys\":[]}".to_string()),
        jwks_api_version: None,
    });
    let engine = TrustFactEngine::new(vec![producer])
        .with_cose_sign1_bytes(Arc::from(cose.into_boxed_slice()))
        .with_cose_sign1_message(Arc::new(parsed));

    let subject = TrustSubject::message(b"seed");
    let cs = engine
        .get_facts::<CounterSignatureSubjectFact>(&subject)
        .unwrap();
    assert_eq!(1, cs.len());
    let cs_subject = &cs[0].subject;

    // Request trusted first...
    let trusted = engine
        .get_facts::<MstReceiptTrustedFact>(cs_subject)
        .unwrap();
    assert_eq!(1, trusted.len());
    assert!(!trusted[0].trusted);
    assert!(trusted[0]
        .details
        .as_deref()
        .unwrap_or("")
        .contains("receipt_decode_failed"));

    // ...then present should already be available and correct.
    let present = engine
        .get_facts::<MstReceiptPresentFact>(cs_subject)
        .unwrap();
    assert_eq!(1, present.len());
    assert!(present[0].present);
}

#[test]
fn mst_trusted_is_available_when_offline_jwks_is_not_configured() {
    let receipts: [&[u8]; 1] = [b"r1".as_slice()];
    let cose = build_cose_sign1_with_unprotected_receipts(Some(&receipts));

    let parsed = CoseSign1Message::parse(cose.as_slice()).expect("parse cose");

    let producer = Arc::new(MstTrustPack {
        allow_network: false,
        offline_jwks_json: None,
        jwks_api_version: None,
    });
    let engine = TrustFactEngine::new(vec![producer])
        .with_cose_sign1_bytes(Arc::from(cose.into_boxed_slice()))
        .with_cose_sign1_message(Arc::new(parsed));

    let subject = TrustSubject::message(b"seed");
    let cs = engine
        .get_facts::<CounterSignatureSubjectFact>(&subject)
        .unwrap();
    assert_eq!(1, cs.len());
    let cs_subject = &cs[0].subject;

    let set = engine
        .get_fact_set::<MstReceiptTrustedFact>(cs_subject)
        .unwrap();
    match set {
        TrustFactSet::Available(v) => {
            assert_eq!(1, v.len());
            assert!(!v[0].trusted);
        }
        other => panic!("expected Available, got {other:?}"),
    }
}

#[test]
fn mst_facts_are_noop_for_non_message_subjects() {
    let receipts: [&[u8]; 1] = [b"r1".as_slice()];
    let cose = build_cose_sign1_with_unprotected_receipts(Some(&receipts));

    let parsed = CoseSign1Message::parse(cose.as_slice()).expect("parse cose");

    let producer = Arc::new(MstTrustPack {
        allow_network: false,
        offline_jwks_json: None,
        jwks_api_version: None,
    });
    let engine = TrustFactEngine::new(vec![producer])
        .with_cose_sign1_bytes(Arc::from(cose.into_boxed_slice()))
        .with_cose_sign1_message(Arc::new(parsed));

    // Any non-message subject should short-circuit and not produce facts.
    let subject = TrustSubject::root("NotMessage", b"seed");
    let present = engine.get_facts::<MstReceiptPresentFact>(&subject).unwrap();
    let trusted = engine.get_facts::<MstReceiptTrustedFact>(&subject).unwrap();
    assert!(present.is_empty());
    assert!(trusted.is_empty());
}

#[test]
fn mst_facts_are_missing_when_message_is_unavailable() {
    let producer = Arc::new(MstTrustPack {
        allow_network: false,
        offline_jwks_json: None,
        jwks_api_version: None,
    });

    // No cose_sign1_message and no cose_sign1_bytes.
    let engine = TrustFactEngine::new(vec![producer]);
    let subject = TrustSubject::message(b"seed");

    let cs = engine
        .get_fact_set::<CounterSignatureSubjectFact>(&subject)
        .unwrap();
    let cs_key = engine
        .get_fact_set::<CounterSignatureSigningKeySubjectFact>(&subject)
        .unwrap();
    let cs_bytes = engine
        .get_fact_set::<UnknownCounterSignatureBytesFact>(&subject)
        .unwrap();

    assert!(matches!(cs, TrustFactSet::Missing { .. }));
    assert!(matches!(cs_key, TrustFactSet::Missing { .. }));
    assert!(matches!(cs_bytes, TrustFactSet::Missing { .. }));
}

#[test]
fn mst_trusted_reports_verification_error_when_offline_keys_present_but_receipt_invalid() {
    let receipts: [&[u8]; 1] = [b"r1".as_slice()];
    let cose = build_cose_sign1_with_unprotected_receipts(Some(&receipts));

    let parsed = CoseSign1Message::parse(cose.as_slice()).expect("parse cose");

    let producer = Arc::new(MstTrustPack {
        allow_network: false,
        offline_jwks_json: Some("{\"keys\":[]}".to_string()),
        jwks_api_version: None,
    });
    let engine = TrustFactEngine::new(vec![producer])
        .with_cose_sign1_bytes(Arc::from(cose.into_boxed_slice()))
        .with_cose_sign1_message(Arc::new(parsed));

    let subject = TrustSubject::message(b"seed");
    let cs = engine
        .get_facts::<CounterSignatureSubjectFact>(&subject)
        .unwrap();
    assert_eq!(1, cs.len());
    let cs_subject = &cs[0].subject;

    let trusted = engine
        .get_facts::<MstReceiptTrustedFact>(cs_subject)
        .unwrap();
    assert_eq!(1, trusted.len());
    assert!(!trusted[0].trusted);
    assert!(trusted[0]
        .details
        .as_deref()
        .unwrap_or("")
        .contains("receipt_decode_failed"));
}

#[test]
fn mst_trusted_reports_no_receipt_when_absent() {
    let cose = build_cose_sign1_with_unprotected_receipts(None);

    let parsed = CoseSign1Message::parse(cose.as_slice()).expect("parse cose");

    let producer = Arc::new(MstTrustPack {
        allow_network: false,
        offline_jwks_json: None,
        jwks_api_version: None,
    });
    let engine = TrustFactEngine::new(vec![producer])
        .with_cose_sign1_bytes(Arc::from(cose.into_boxed_slice()))
        .with_cose_sign1_message(Arc::new(parsed));

    let subject = TrustSubject::message(b"seed");
    let cs = engine
        .get_facts::<CounterSignatureSubjectFact>(&subject)
        .unwrap();
    assert!(cs.is_empty());
}

#[test]
fn mst_receipt_present_errors_on_malformed_cose_bytes() {
    // Not a COSE_Sign1 array(4).
    let cose = vec![0xa0];

    // Malformed COSE should fail to parse
    let err = CoseSign1Message::parse(cose.as_slice());
    assert!(err.is_err(), "expected parse error for malformed COSE");
}

#[test]
fn mst_pack_provides_reports_expected_fact_keys() {
    let pack = MstTrustPack {
        allow_network: false,
        offline_jwks_json: None,
        jwks_api_version: None,
    };
    let provided = TrustFactProducer::provides(&pack);
    assert_eq!(11, provided.len());
}
