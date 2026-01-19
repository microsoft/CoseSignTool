// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use cose_sign1_validation::fluent::*;
use cose_sign1_validation_trust::evaluation_options::TrustEvaluationOptions;
use cose_sign1_validation_trust::facts::{TrustFactEngine, TrustFactSet};
use cose_sign1_validation_trust::subject::TrustSubject;
use std::sync::Arc;
use tinycbor::{Encode, Encoder};

fn encode_map(pairs: &[(i64, CborValue)]) -> Vec<u8> {
    let mut buf = vec![0u8; 256];
    let buf_len = buf.len();
    let mut enc = Encoder(buf.as_mut_slice());

    enc.map(pairs.len()).unwrap();
    for (k, v) in pairs {
        k.encode(&mut enc).unwrap();
        match v {
            CborValue::I64(i) => i.encode(&mut enc).unwrap(),
            CborValue::Text(s) => s.encode(&mut enc).unwrap(),
            CborValue::Bytes(b) => b.as_slice().encode(&mut enc).unwrap(),
        }
    }

    let used = buf_len - enc.0.len();
    buf.truncate(used);
    buf
}

enum CborValue {
    I64(i64),
    Text(&'static str),
    Bytes(Vec<u8>),
}

fn build_cose_sign1_bytes(
    protected_map: &[(i64, CborValue)],
    unprotected_map: &[(i64, CborValue)],
    payload: Option<&[u8]>,
) -> Vec<u8> {
    let protected_bytes = encode_map(protected_map);

    let unprotected_pairs = unprotected_map;

    let mut buf = vec![0u8; 1024];
    let buf_len = buf.len();
    let mut enc = Encoder(buf.as_mut_slice());

    enc.array(4).unwrap();

    // protected header is bstr of the CBOR map bytes
    protected_bytes.as_slice().encode(&mut enc).unwrap();

    // unprotected header is an actual map
    enc.map(unprotected_pairs.len()).unwrap();
    for (k, v) in unprotected_pairs {
        k.encode(&mut enc).unwrap();
        match v {
            CborValue::I64(i) => i.encode(&mut enc).unwrap(),
            CborValue::Text(s) => s.encode(&mut enc).unwrap(),
            CborValue::Bytes(b) => b.as_slice().encode(&mut enc).unwrap(),
        }
    }

    // payload
    match payload {
        Some(p) => p.encode(&mut enc).unwrap(),
        None => {
            let none: Option<&[u8]> = None;
            none.encode(&mut enc).unwrap();
        }
    }

    // signature
    b"sig".as_slice().encode(&mut enc).unwrap();

    let used = buf_len - enc.0.len();
    buf.truncate(used);
    buf
}

fn build_cose_sign1_bytes_with_protected_header_bytes(
    protected_header_map_bytes: &[u8],
    payload: Option<&[u8]>,
) -> Vec<u8> {
    let mut buf = vec![0u8; 1024];
    let buf_len = buf.len();
    let mut enc = Encoder(buf.as_mut_slice());

    enc.array(4).unwrap();

    // protected header is bstr of the CBOR map bytes
    protected_header_map_bytes.encode(&mut enc).unwrap();

    // unprotected header is an actual map (empty)
    enc.map(0).unwrap();

    // payload
    match payload {
        Some(p) => p.encode(&mut enc).unwrap(),
        None => {
            let none: Option<&[u8]> = None;
            none.encode(&mut enc).unwrap();
        }
    }

    // signature
    b"sig".as_slice().encode(&mut enc).unwrap();

    let used = buf_len - enc.0.len();
    buf.truncate(used);
    buf
}

fn encode_cwt_claims_map_bytes() -> Vec<u8> {
    // Build a CWT claims map with both numeric and text keys:
    // { 99: [1,2,3], "custom": {"x": 42} }
    let mut buf = vec![0u8; 256];
    let buf_len = buf.len();
    let mut enc = Encoder(buf.as_mut_slice());

    enc.map(2).unwrap();

    // 99: [1,2,3]
    99i64.encode(&mut enc).unwrap();
    enc.array(3).unwrap();
    1i64.encode(&mut enc).unwrap();
    2i64.encode(&mut enc).unwrap();
    3i64.encode(&mut enc).unwrap();

    // "custom": {"x": 42}
    "custom".encode(&mut enc).unwrap();
    enc.map(1).unwrap();
    "x".encode(&mut enc).unwrap();
    42i64.encode(&mut enc).unwrap();

    let used = buf_len - enc.0.len();
    buf.truncate(used);
    buf
}

fn encode_protected_header_with_cwt_claims() -> Vec<u8> {
    // COSE header parameter label 15 = CWT claims.
    const CWT_CLAIMS_LABEL: i64 = 15;

    let mut buf = vec![0u8; 256];
    let buf_len = buf.len();
    let mut enc = Encoder(buf.as_mut_slice());

    enc.map(1).unwrap();
    CWT_CLAIMS_LABEL.encode(&mut enc).unwrap();

    // Embed claims as a CBOR map value.
    let claims_bytes = encode_cwt_claims_map_bytes();
    // Re-decode and re-encode by writing the raw bytes directly into the protected header.
    // We do this by copying the already-encoded CBOR value bytes into the encoder buffer.
    if enc.0.len() < claims_bytes.len() {
        panic!("buffer too small for claims map");
    }
    let remaining = std::mem::take(&mut enc.0);
    let (head, tail) = remaining.split_at_mut(claims_bytes.len());
    head.copy_from_slice(claims_bytes.as_slice());
    enc.0 = tail;

    let used = buf_len - enc.0.len();
    buf.truncate(used);
    buf
}

#[test]
fn message_fact_producer_is_noop_for_non_message_subject() {
    let cose_bytes = build_cose_sign1_bytes(&[(1, CborValue::I64(-7))], &[], Some(b"payload"));

    let producer = Arc::new(CoseSign1MessageFactProducer::new());
    let engine = TrustFactEngine::new(vec![producer])
        .with_cose_sign1_bytes(Arc::from(cose_bytes.into_boxed_slice()));

    let subject = TrustSubject::root("NotMessage", b"seed");

    let parts = engine
        .get_fact_set::<CoseSign1MessagePartsFact>(&subject)
        .unwrap();
    match parts {
        TrustFactSet::Available(v) => assert!(v.is_empty()),
        other => panic!("expected Available(empty), got {other:?}"),
    }
}

#[test]
fn message_fact_producer_marks_missing_when_message_bytes_are_unavailable() {
    let producer = Arc::new(CoseSign1MessageFactProducer::new());
    let engine = TrustFactEngine::new(vec![producer]);

    let subject = TrustSubject::message(b"seed");

    let bytes = engine
        .get_fact_set::<CoseSign1MessageBytesFact>(&subject)
        .unwrap();
    assert!(matches!(bytes, TrustFactSet::Missing { .. }));

    let parts = engine
        .get_fact_set::<CoseSign1MessagePartsFact>(&subject)
        .unwrap();
    assert!(matches!(parts, TrustFactSet::Missing { .. }));

    let detached = engine
        .get_fact_set::<DetachedPayloadPresentFact>(&subject)
        .unwrap();
    assert!(matches!(detached, TrustFactSet::Missing { .. }));

    let ct = engine.get_fact_set::<ContentTypeFact>(&subject).unwrap();
    assert!(matches!(ct, TrustFactSet::Missing { .. }));

    let cs = engine
        .get_fact_set::<CounterSignatureSubjectFact>(&subject)
        .unwrap();
    assert!(matches!(cs, TrustFactSet::Missing { .. }));

    let psk = engine
        .get_fact_set::<PrimarySigningKeySubjectFact>(&subject)
        .unwrap();
    assert!(matches!(psk, TrustFactSet::Missing { .. }));

    let cssk = engine
        .get_fact_set::<CounterSignatureSigningKeySubjectFact>(&subject)
        .unwrap();
    assert!(matches!(cssk, TrustFactSet::Missing { .. }));

    let unk = engine
        .get_fact_set::<UnknownCounterSignatureBytesFact>(&subject)
        .unwrap();
    assert!(matches!(unk, TrustFactSet::Missing { .. }));
}

#[test]
fn message_fact_producer_marks_error_when_cose_decode_fails() {
    let producer = Arc::new(CoseSign1MessageFactProducer::new());
    let engine = TrustFactEngine::new(vec![producer])
        .with_cose_sign1_bytes(Arc::from(vec![0xA0u8].into_boxed_slice()));

    let subject = TrustSubject::message(b"seed");

    let parts = engine
        .get_fact_set::<CoseSign1MessagePartsFact>(&subject)
        .unwrap();
    match parts {
        TrustFactSet::Error { message } => assert!(message.contains("cose_decode_failed")),
        other => panic!("expected Error, got {other:?}"),
    }
}

#[test]
fn message_fact_producer_skips_parsed_message_dependent_facts_when_from_parts_fails() {
    // protected header bytes are not a CBOR map (this makes from_parts fail)
    let mut buf = vec![0u8; 128];
    let buf_len = buf.len();
    let mut enc = Encoder(buf.as_mut_slice());

    enc.array(4).unwrap();
    b"\x01".as_slice().encode(&mut enc).unwrap(); // protected header bstr containing non-map CBOR
    enc.map(0).unwrap();
    b"payload".as_slice().encode(&mut enc).unwrap();
    b"sig".as_slice().encode(&mut enc).unwrap();

    let used = buf_len - enc.0.len();
    buf.truncate(used);

    let producer = Arc::new(CoseSign1MessageFactProducer::new());
    let engine = TrustFactEngine::new(vec![producer])
        .with_cose_sign1_bytes(Arc::from(buf.into_boxed_slice()));

    let subject = TrustSubject::message(b"seed");

    // Parts and detached are still produced from raw COSE decoding.
    let parts = engine
        .get_fact_set::<CoseSign1MessagePartsFact>(&subject)
        .unwrap();
    assert!(matches!(parts, TrustFactSet::Available(_)));

    let ct = engine.get_fact_set::<ContentTypeFact>(&subject).unwrap();
    match ct {
        TrustFactSet::Available(v) => assert!(v.is_empty()),
        other => panic!("expected Available(empty), got {other:?}"),
    }

    let psk = engine
        .get_fact_set::<PrimarySigningKeySubjectFact>(&subject)
        .unwrap();
    match psk {
        TrustFactSet::Available(v) => assert!(v.is_empty()),
        other => panic!("expected Available(empty), got {other:?}"),
    }
}

#[test]
fn content_type_strips_cose_hash_v_suffix() {
    let cose_bytes = build_cose_sign1_bytes(
        &[
            (1, CborValue::I64(-7)),
            (3, CborValue::Text("application/json+cose-hash-v")),
        ],
        &[],
        Some(b"payload"),
    );

    let msg = CoseSign1::from_cbor(&cose_bytes).unwrap();
    let parsed = cose_sign1_validation_trust::CoseSign1ParsedMessage::from_parts(
        msg.protected_header,
        msg.unprotected_header.as_ref(),
        msg.payload,
        msg.signature,
    )
    .unwrap();

    let producer = Arc::new(CoseSign1MessageFactProducer::new());
    let engine = TrustFactEngine::new(vec![producer])
        .with_cose_sign1_bytes(Arc::from(cose_bytes.into_boxed_slice()))
        .with_cose_sign1_message(Arc::new(parsed));

    let subject = TrustSubject::message(b"seed");
    let ct = engine.get_facts::<ContentTypeFact>(&subject).unwrap();
    assert_eq!(1, ct.len());
    assert_eq!("application/json", ct[0].content_type);
}

#[test]
fn cwt_claims_fact_preserves_raw_values_and_supports_custom_claim_rules() {
    let protected_header_bytes = encode_protected_header_with_cwt_claims();
    let cose_bytes = build_cose_sign1_bytes_with_protected_header_bytes(
        protected_header_bytes.as_slice(),
        Some(b"payload"),
    );

    let producer = Arc::new(CoseSign1MessageFactProducer::new());
    let engine = TrustFactEngine::new(vec![producer])
        .with_cose_sign1_bytes(Arc::from(cose_bytes.into_boxed_slice()));

    let subject = TrustSubject::message(b"seed");

    let claims = engine.get_fact_set::<CwtClaimsFact>(&subject).unwrap();
    let fact = match claims {
        TrustFactSet::Available(v) => v.into_iter().next().expect("expected one CwtClaimsFact"),
        other => panic!("expected Available, got {other:?}"),
    };

    assert!(fact.raw_claims.contains_key(&99));
    assert!(fact.raw_claims_text.contains_key("custom"));

    // Now prove the fluent custom-claim APIs can parse the claim values via the opaque reader.
    let plan = TrustPlanBuilder::new(vec![]).for_message(|msg| {
        msg.require_cwt_claim(99, |r| {
            let mut d = tinycbor::Decoder(r.bytes());
            let Ok(mut arr) = d.array_visitor() else {
                return false;
            };
            let mut values = Vec::new();
            while let Some(item) = arr.visit::<i64>() {
                let Ok(v) = item else {
                    return false;
                };
                values.push(v);
            }
            values == vec![1, 2, 3]
        })
        .require_cwt_claim("custom", |r| {
            let mut d = tinycbor::Decoder(r.bytes());
            let Ok(mut map) = d.map_visitor() else {
                return false;
            };
            while let Some(entry) = map.visit::<&str, i64>() {
                let Ok((k, v)) = entry else {
                    return false;
                };
                if k == "x" {
                    return v == 42;
                }
            }
            false
        })
    });

    let compiled = plan.compile().expect("plan compile failed");
    let decision = compiled
        .plan()
        .evaluate(&engine, &subject, &TrustEvaluationOptions::default())
        .expect("plan evaluate failed");

    assert!(decision.is_trusted);
}

#[test]
fn content_type_strips_legacy_hash_suffix() {
    let cose_bytes = build_cose_sign1_bytes(
        &[
            (1, CborValue::I64(-7)),
            (3, CborValue::Text("application/json+hash-sha256")),
        ],
        &[],
        Some(b"payload"),
    );

    let msg = CoseSign1::from_cbor(&cose_bytes).unwrap();
    let parsed = cose_sign1_validation_trust::CoseSign1ParsedMessage::from_parts(
        msg.protected_header,
        msg.unprotected_header.as_ref(),
        msg.payload,
        msg.signature,
    )
    .unwrap();

    let producer = Arc::new(CoseSign1MessageFactProducer::new());
    let engine = TrustFactEngine::new(vec![producer])
        .with_cose_sign1_bytes(Arc::from(cose_bytes.into_boxed_slice()))
        .with_cose_sign1_message(Arc::new(parsed));

    let subject = TrustSubject::message(b"seed");
    let ct = engine.get_facts::<ContentTypeFact>(&subject).unwrap();
    assert_eq!(1, ct.len());
    assert_eq!("application/json", ct[0].content_type);
}

#[test]
fn content_type_prefers_preimage_content_type_when_envelope_marker_present() {
    // If payload-hash-alg is present, then PREIMAGE_CONTENT_TYPE takes precedence.
    let cose_bytes = build_cose_sign1_bytes(
        &[
            (1, CborValue::I64(-7)),
            (258, CborValue::I64(1)),
            (259, CborValue::Text("application/cbor")),
            (3, CborValue::Text("ignored")),
        ],
        &[],
        Some(b"payload"),
    );

    let msg = CoseSign1::from_cbor(&cose_bytes).unwrap();
    let parsed = cose_sign1_validation_trust::CoseSign1ParsedMessage::from_parts(
        msg.protected_header,
        msg.unprotected_header.as_ref(),
        msg.payload,
        msg.signature,
    )
    .unwrap();

    let producer = Arc::new(CoseSign1MessageFactProducer::new());
    let engine = TrustFactEngine::new(vec![producer])
        .with_cose_sign1_bytes(Arc::from(cose_bytes.into_boxed_slice()))
        .with_cose_sign1_message(Arc::new(parsed));

    let subject = TrustSubject::message(b"seed");
    let ct = engine.get_facts::<ContentTypeFact>(&subject).unwrap();
    assert_eq!(1, ct.len());
    assert_eq!("application/cbor", ct[0].content_type);
}

#[test]
fn content_type_formats_integer_preimage_content_type_as_coap() {
    let cose_bytes = build_cose_sign1_bytes(
        &[
            (1, CborValue::I64(-7)),
            (258, CborValue::I64(1)),
            (259, CborValue::I64(42)),
        ],
        &[],
        Some(b"payload"),
    );

    let msg = CoseSign1::from_cbor(&cose_bytes).unwrap();
    let parsed = cose_sign1_validation_trust::CoseSign1ParsedMessage::from_parts(
        msg.protected_header,
        msg.unprotected_header.as_ref(),
        msg.payload,
        msg.signature,
    )
    .unwrap();

    let producer = Arc::new(CoseSign1MessageFactProducer::new());
    let engine = TrustFactEngine::new(vec![producer])
        .with_cose_sign1_bytes(Arc::from(cose_bytes.into_boxed_slice()))
        .with_cose_sign1_message(Arc::new(parsed));

    let subject = TrustSubject::message(b"seed");
    let ct = engine.get_facts::<ContentTypeFact>(&subject).unwrap();
    assert_eq!(1, ct.len());
    assert_eq!("coap/42", ct[0].content_type);
}

#[test]
fn content_type_accepts_utf8_bytes_from_unprotected_header() {
    let cose_bytes = build_cose_sign1_bytes(
        &[(1, CborValue::I64(-7))],
        &[(3, CborValue::Bytes(b"text/plain".to_vec()))],
        Some(b"payload"),
    );

    let msg = CoseSign1::from_cbor(&cose_bytes).unwrap();
    let parsed = cose_sign1_validation_trust::CoseSign1ParsedMessage::from_parts(
        msg.protected_header,
        msg.unprotected_header.as_ref(),
        msg.payload,
        msg.signature,
    )
    .unwrap();

    let producer = Arc::new(CoseSign1MessageFactProducer::new());
    let engine = TrustFactEngine::new(vec![producer])
        .with_cose_sign1_bytes(Arc::from(cose_bytes.into_boxed_slice()))
        .with_cose_sign1_message(Arc::new(parsed));

    let subject = TrustSubject::message(b"seed");
    let ct = engine.get_facts::<ContentTypeFact>(&subject).unwrap();
    assert_eq!(1, ct.len());
    assert_eq!("text/plain", ct[0].content_type);
}
