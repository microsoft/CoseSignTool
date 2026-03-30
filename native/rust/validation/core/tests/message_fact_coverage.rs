// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Additional coverage for `CoseSign1MessageFactProducer` paths not exercised
//! by the existing `message_fact_producer_more` tests.

use cose_sign1_validation::fluent::*;
use cose_sign1_validation_primitives::facts::{TrustFactEngine, TrustFactSet};
use cose_sign1_validation_primitives::subject::TrustSubject;
use cbor_primitives::{CborEncoder, CborProvider};
use cbor_primitives_everparse::EverParseCborProvider;
use std::sync::Arc;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

enum CborValue {
    I64(i64),
    Text(&'static str),
}

fn encode_map(pairs: &[(i64, CborValue)]) -> Vec<u8> {
    let p = EverParseCborProvider;
    let mut enc = p.encoder();
    enc.encode_map(pairs.len()).unwrap();
    for (k, v) in pairs {
        enc.encode_i64(*k).unwrap();
        match v {
            CborValue::I64(i) => enc.encode_i64(*i).unwrap(),
            CborValue::Text(s) => enc.encode_tstr(s).unwrap(),
        }
    }
    enc.into_bytes()
}

fn build_cose_sign1(
    protected_map: &[(i64, CborValue)],
    unprotected_map: &[(i64, CborValue)],
    payload: Option<&[u8]>,
) -> Vec<u8> {
    let protected_bytes = encode_map(protected_map);

    let p = EverParseCborProvider;
    let mut enc = p.encoder();
    enc.encode_array(4).unwrap();

    // protected header as bstr
    enc.encode_bstr(&protected_bytes).unwrap();

    // unprotected header as map
    enc.encode_map(unprotected_map.len()).unwrap();
    for (k, v) in unprotected_map {
        enc.encode_i64(*k).unwrap();
        match v {
            CborValue::I64(i) => enc.encode_i64(*i).unwrap(),
            CborValue::Text(s) => enc.encode_tstr(s).unwrap(),
        }
    }

    match payload {
        Some(p) => enc.encode_bstr(p).unwrap(),
        None => enc.encode_null().unwrap(),
    }

    enc.encode_bstr(b"sig").unwrap();
    enc.into_bytes()
}

fn build_cose_sign1_with_raw_protected(
    protected_header_bytes: &[u8],
    payload: Option<&[u8]>,
) -> Vec<u8> {
    let p = EverParseCborProvider;
    let mut enc = p.encoder();
    enc.encode_array(4).unwrap();
    enc.encode_bstr(protected_header_bytes).unwrap();
    enc.encode_map(0).unwrap();
    match payload {
        Some(p) => enc.encode_bstr(p).unwrap(),
        None => enc.encode_null().unwrap(),
    }
    enc.encode_bstr(b"sig").unwrap();
    enc.into_bytes()
}

/// Build an engine with the given COSE bytes pre-parsed.
fn engine_with_parsed(cose_bytes: &[u8]) -> TrustFactEngine {
    let parsed = cose_sign1_primitives::CoseSign1Message::parse(cose_bytes,
    )
    .expect("parse");

    let producer = Arc::new(CoseSign1MessageFactProducer::new());
    TrustFactEngine::new(vec![producer])
        .with_cose_sign1_bytes(Arc::from(cose_bytes.to_vec().into_boxed_slice()))
        .with_cose_sign1_message(Arc::new(parsed))
}

fn message_subject() -> TrustSubject {
    TrustSubject::message(b"seed")
}

// ---------------------------------------------------------------------------
// CWT claims from Map — well-known integer-keyed claims (iss=1 … iat=6)
// ---------------------------------------------------------------------------

/// Encode a protected header whose CWT claims (label 15) map contains
/// the well-known claims keyed by integer (1–6) with appropriate types.
fn encode_protected_with_wellknown_int_claims() -> Vec<u8> {
    let p = EverParseCborProvider;
    let mut enc = p.encoder();

    // outer header map: { 15: { 1: "issuer", 2: "subject", 3: "audience", 4: 1700000000, 5: 1600000000, 6: 1650000000 } }
    enc.encode_map(1).unwrap();
    enc.encode_i64(15).unwrap();

    // inner CWT claims map
    enc.encode_map(6).unwrap();
    enc.encode_i64(1).unwrap();
    enc.encode_tstr("issuer").unwrap();
    enc.encode_i64(2).unwrap();
    enc.encode_tstr("subject").unwrap();
    enc.encode_i64(3).unwrap();
    enc.encode_tstr("audience").unwrap();
    enc.encode_i64(4).unwrap();
    enc.encode_i64(1_700_000_000).unwrap();
    enc.encode_i64(5).unwrap();
    enc.encode_i64(1_600_000_000).unwrap();
    enc.encode_i64(6).unwrap();
    enc.encode_i64(1_650_000_000).unwrap();

    enc.into_bytes()
}

#[test]
fn cwt_claims_map_extracts_wellknown_int_keyed_claims() {
    let phdr = encode_protected_with_wellknown_int_claims();
    let cose_bytes = build_cose_sign1_with_raw_protected(&phdr, Some(b"payload"));
    let engine = engine_with_parsed(&cose_bytes);
    let subject = message_subject();

    let fact = match engine.get_fact_set::<CwtClaimsFact>(&subject).unwrap() {
        TrustFactSet::Available(v) => v.into_iter().next().expect("one CwtClaimsFact"),
        other => panic!("expected Available, got {other:?}"),
    };

    assert_eq!(fact.iss.as_deref(), Some("issuer"));
    assert_eq!(fact.sub.as_deref(), Some("subject"));
    assert_eq!(fact.aud.as_deref(), Some("audience"));
    assert_eq!(fact.exp, Some(1_700_000_000));
    assert_eq!(fact.nbf, Some(1_600_000_000));
    assert_eq!(fact.iat, Some(1_650_000_000));

    // Scalar claims should contain the same values.
    assert!(matches!(
        fact.scalar_claims.get(&1),
        Some(CwtClaimScalar::Str(s)) if s == "issuer"
    ));
    assert!(matches!(
        fact.scalar_claims.get(&4),
        Some(CwtClaimScalar::I64(1_700_000_000))
    ));
}

// ---------------------------------------------------------------------------
// CWT claims from Map — text-keyed well-known claims
// ---------------------------------------------------------------------------

fn encode_protected_with_wellknown_text_claims() -> Vec<u8> {
    let p = EverParseCborProvider;
    let mut enc = p.encoder();

    // { 15: { "iss": "txt-issuer", "sub": "txt-subject", "aud": "txt-audience",
    //         "exp": 2000000000, "nbf": 1900000000, "iat": 1950000000 } }
    enc.encode_map(1).unwrap();
    enc.encode_i64(15).unwrap();

    enc.encode_map(6).unwrap();
    enc.encode_tstr("iss").unwrap();
    enc.encode_tstr("txt-issuer").unwrap();
    enc.encode_tstr("sub").unwrap();
    enc.encode_tstr("txt-subject").unwrap();
    enc.encode_tstr("aud").unwrap();
    enc.encode_tstr("txt-audience").unwrap();
    enc.encode_tstr("exp").unwrap();
    enc.encode_i64(2_000_000_000).unwrap();
    enc.encode_tstr("nbf").unwrap();
    enc.encode_i64(1_900_000_000).unwrap();
    enc.encode_tstr("iat").unwrap();
    enc.encode_i64(1_950_000_000).unwrap();

    enc.into_bytes()
}

#[test]
fn cwt_claims_map_extracts_wellknown_text_keyed_claims() {
    let phdr = encode_protected_with_wellknown_text_claims();
    let cose_bytes = build_cose_sign1_with_raw_protected(&phdr, Some(b"payload"));
    let engine = engine_with_parsed(&cose_bytes);
    let subject = message_subject();

    let fact = match engine.get_fact_set::<CwtClaimsFact>(&subject).unwrap() {
        TrustFactSet::Available(v) => v.into_iter().next().expect("one CwtClaimsFact"),
        other => panic!("expected Available, got {other:?}"),
    };

    assert_eq!(fact.iss.as_deref(), Some("txt-issuer"));
    assert_eq!(fact.sub.as_deref(), Some("txt-subject"));
    assert_eq!(fact.aud.as_deref(), Some("txt-audience"));
    assert_eq!(fact.exp, Some(2_000_000_000));
    assert_eq!(fact.nbf, Some(1_900_000_000));
    assert_eq!(fact.iat, Some(1_950_000_000));

    // Text-keyed raw claims should be present.
    assert!(fact.raw_claims_text.contains_key("iss"));
    assert!(fact.raw_claims_text.contains_key("exp"));
}

// ---------------------------------------------------------------------------
// CWT claims from Map — bool value (extract_bool branch)
// ---------------------------------------------------------------------------

fn encode_protected_with_bool_claim() -> Vec<u8> {
    let p = EverParseCborProvider;
    let mut enc = p.encoder();

    // { 15: { 100: true, 101: false } }
    enc.encode_map(1).unwrap();
    enc.encode_i64(15).unwrap();

    enc.encode_map(2).unwrap();
    enc.encode_i64(100).unwrap();
    enc.encode_bool(true).unwrap();
    enc.encode_i64(101).unwrap();
    enc.encode_bool(false).unwrap();

    enc.into_bytes()
}

#[test]
fn cwt_claims_map_extracts_bool_values() {
    let phdr = encode_protected_with_bool_claim();
    let cose_bytes = build_cose_sign1_with_raw_protected(&phdr, Some(b"payload"));
    let engine = engine_with_parsed(&cose_bytes);
    let subject = message_subject();

    let fact = match engine.get_fact_set::<CwtClaimsFact>(&subject).unwrap() {
        TrustFactSet::Available(v) => v.into_iter().next().expect("one CwtClaimsFact"),
        other => panic!("expected Available, got {other:?}"),
    };

    assert!(matches!(
        fact.scalar_claims.get(&100),
        Some(CwtClaimScalar::Bool(true))
    ));
    assert!(matches!(
        fact.scalar_claims.get(&101),
        Some(CwtClaimScalar::Bool(false))
    ));

    // Raw claims bytes should still be populated.
    assert!(fact.raw_claims.contains_key(&100));
    assert!(fact.raw_claims.contains_key(&101));
}

// ---------------------------------------------------------------------------
// CWT claims from Map — nested array, nested map, tagged value
// (exercises encode_value_recursive for Array, Map, Tagged variants)
// ---------------------------------------------------------------------------

fn encode_protected_with_nested_claims() -> Vec<u8> {
    let p = EverParseCborProvider;
    let mut enc = p.encoder();

    // { 15: { 200: [10, 20], 201: { 1: "nested" }, 202: tag(1, 99) } }
    enc.encode_map(1).unwrap();
    enc.encode_i64(15).unwrap();

    enc.encode_map(3).unwrap();

    // 200: [10, 20]
    enc.encode_i64(200).unwrap();
    enc.encode_array(2).unwrap();
    enc.encode_i64(10).unwrap();
    enc.encode_i64(20).unwrap();

    // 201: { 1: "nested" }
    enc.encode_i64(201).unwrap();
    enc.encode_map(1).unwrap();
    enc.encode_i64(1).unwrap();
    enc.encode_tstr("nested").unwrap();

    // 202: tag(1, 99)
    enc.encode_i64(202).unwrap();
    enc.encode_tag(1).unwrap();
    enc.encode_i64(99).unwrap();

    enc.into_bytes()
}

#[test]
fn cwt_claims_map_handles_nested_array_map_and_tagged_values() {
    let phdr = encode_protected_with_nested_claims();
    let cose_bytes = build_cose_sign1_with_raw_protected(&phdr, Some(b"payload"));
    let engine = engine_with_parsed(&cose_bytes);
    let subject = message_subject();

    let fact = match engine.get_fact_set::<CwtClaimsFact>(&subject).unwrap() {
        TrustFactSet::Available(v) => v.into_iter().next().expect("one CwtClaimsFact"),
        other => panic!("expected Available, got {other:?}"),
    };

    // Array, Map, and Tagged values are not scalar — they should NOT appear
    // in scalar_claims, but their raw_claims bytes should be present.
    assert!(!fact.scalar_claims.contains_key(&200));
    assert!(!fact.scalar_claims.contains_key(&201));
    assert!(!fact.scalar_claims.contains_key(&202));

    // Raw claims bytes must contain the re-encoded values.
    assert!(fact.raw_claims.contains_key(&200));
    assert!(fact.raw_claims.contains_key(&201));
    assert!(fact.raw_claims.contains_key(&202));
}

// ---------------------------------------------------------------------------
// CWT claims from Map — unknown claim IDs (no well-known match)
// ---------------------------------------------------------------------------

#[test]
fn cwt_claims_map_stores_unknown_int_and_text_keys() {
    let p = EverParseCborProvider;
    let mut enc = p.encoder();

    // { 15: { 999: "val999", "custom_key": 42 } }
    enc.encode_map(1).unwrap();
    enc.encode_i64(15).unwrap();

    enc.encode_map(2).unwrap();
    enc.encode_i64(999).unwrap();
    enc.encode_tstr("val999").unwrap();
    enc.encode_tstr("custom_key").unwrap();
    enc.encode_i64(42).unwrap();

    let phdr = enc.into_bytes();
    let cose_bytes = build_cose_sign1_with_raw_protected(&phdr, Some(b"payload"));
    let engine = engine_with_parsed(&cose_bytes);
    let subject = message_subject();

    let fact = match engine.get_fact_set::<CwtClaimsFact>(&subject).unwrap() {
        TrustFactSet::Available(v) => v.into_iter().next().expect("one CwtClaimsFact"),
        other => panic!("expected Available, got {other:?}"),
    };

    // Well-known fields should all be None.
    assert!(fact.iss.is_none());
    assert!(fact.sub.is_none());
    assert!(fact.aud.is_none());
    assert!(fact.exp.is_none());
    assert!(fact.nbf.is_none());
    assert!(fact.iat.is_none());

    // Int-keyed unknown claim.
    assert!(matches!(
        fact.scalar_claims.get(&999),
        Some(CwtClaimScalar::Str(s)) if s == "val999"
    ));
    assert!(fact.raw_claims.contains_key(&999));

    // Text-keyed unknown claim.
    assert!(fact.raw_claims_text.contains_key("custom_key"));
}

// ---------------------------------------------------------------------------
// Content type — no content-type header at all
// ---------------------------------------------------------------------------

#[test]
fn content_type_is_absent_when_header_is_missing() {
    let cose_bytes = build_cose_sign1(
        &[(1, CborValue::I64(-7))],
        &[],
        Some(b"payload"),
    );
    let engine = engine_with_parsed(&cose_bytes);
    let subject = message_subject();

    let ct = engine.get_fact_set::<ContentTypeFact>(&subject).unwrap();
    match ct {
        TrustFactSet::Available(v) => assert!(v.is_empty(), "expected no ContentTypeFact"),
        other => panic!("expected Available(empty), got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// Content type — plain content type (no hash suffix, no envelope marker)
// ---------------------------------------------------------------------------

#[test]
fn content_type_returns_plain_value_without_hash_suffix() {
    let cose_bytes = build_cose_sign1(
        &[(1, CborValue::I64(-7)), (3, CborValue::Text("application/octet-stream"))],
        &[],
        Some(b"payload"),
    );
    let engine = engine_with_parsed(&cose_bytes);
    let subject = message_subject();

    let ct = engine.get_facts::<ContentTypeFact>(&subject).unwrap();
    assert_eq!(1, ct.len());
    assert_eq!("application/octet-stream", ct[0].content_type);
}

// ---------------------------------------------------------------------------
// Content type — from unprotected header only
// ---------------------------------------------------------------------------

#[test]
fn content_type_falls_back_to_unprotected_header() {
    let cose_bytes = build_cose_sign1(
        &[(1, CborValue::I64(-7))],
        &[(3, CborValue::Text("text/xml"))],
        Some(b"payload"),
    );
    let engine = engine_with_parsed(&cose_bytes);
    let subject = message_subject();

    let ct = engine.get_facts::<ContentTypeFact>(&subject).unwrap();
    assert_eq!(1, ct.len());
    assert_eq!("text/xml", ct[0].content_type);
}

// ---------------------------------------------------------------------------
// Content type — preimage content-type from unprotected header (envelope mode)
// ---------------------------------------------------------------------------

#[test]
fn content_type_reads_preimage_from_unprotected_when_envelope_marker_in_protected() {
    // Protected: { 1: -7, 258: 1 }, Unprotected: { 259: "image/png" }
    let cose_bytes = build_cose_sign1(
        &[(1, CborValue::I64(-7)), (258, CborValue::I64(1))],
        &[(259, CborValue::Text("image/png"))],
        Some(b"payload"),
    );
    let engine = engine_with_parsed(&cose_bytes);
    let subject = message_subject();

    let ct = engine.get_facts::<ContentTypeFact>(&subject).unwrap();
    assert_eq!(1, ct.len());
    assert_eq!("image/png", ct[0].content_type);
}

// ---------------------------------------------------------------------------
// Content type — integer preimage content-type from unprotected header
// ---------------------------------------------------------------------------

#[test]
fn content_type_reads_integer_preimage_from_unprotected() {
    // Protected: { 1: -7, 258: 1 }, Unprotected: { 259: 50 }
    let cose_bytes = build_cose_sign1(
        &[(1, CborValue::I64(-7)), (258, CborValue::I64(1))],
        &[(259, CborValue::I64(50))],
        Some(b"payload"),
    );
    let engine = engine_with_parsed(&cose_bytes);
    let subject = message_subject();

    let ct = engine.get_facts::<ContentTypeFact>(&subject).unwrap();
    assert_eq!(1, ct.len());
    assert_eq!("coap/50", ct[0].content_type);
}

// ---------------------------------------------------------------------------
// CWT claims — not present (no label 15)
// ---------------------------------------------------------------------------

#[test]
fn cwt_claims_present_is_false_when_no_label_15() {
    let cose_bytes = build_cose_sign1(
        &[(1, CborValue::I64(-7))],
        &[],
        Some(b"payload"),
    );
    let engine = engine_with_parsed(&cose_bytes);
    let subject = message_subject();

    let present = match engine.get_fact_set::<CwtClaimsPresentFact>(&subject).unwrap() {
        TrustFactSet::Available(v) => v.into_iter().next().expect("one CwtClaimsPresentFact"),
        other => panic!("expected Available, got {other:?}"),
    };
    assert!(!present.present);
}

// ---------------------------------------------------------------------------
// CWT claims from Map — mixed scalar types in same map
// ---------------------------------------------------------------------------

#[test]
fn cwt_claims_map_mixed_scalar_types() {
    let p = EverParseCborProvider;
    let mut enc = p.encoder();

    // { 15: { 1: "iss-val", 4: 123456, 50: true, 51: h'AABB' } }
    enc.encode_map(1).unwrap();
    enc.encode_i64(15).unwrap();

    enc.encode_map(4).unwrap();
    enc.encode_i64(1).unwrap();
    enc.encode_tstr("iss-val").unwrap();
    enc.encode_i64(4).unwrap();
    enc.encode_i64(123456).unwrap();
    enc.encode_i64(50).unwrap();
    enc.encode_bool(true).unwrap();
    enc.encode_i64(51).unwrap();
    enc.encode_bstr(b"\xAA\xBB").unwrap();

    let phdr = enc.into_bytes();
    let cose_bytes = build_cose_sign1_with_raw_protected(&phdr, Some(b"payload"));
    let engine = engine_with_parsed(&cose_bytes);
    let subject = message_subject();

    let fact = match engine.get_fact_set::<CwtClaimsFact>(&subject).unwrap() {
        TrustFactSet::Available(v) => v.into_iter().next().expect("one CwtClaimsFact"),
        other => panic!("expected Available, got {other:?}"),
    };

    assert_eq!(fact.iss.as_deref(), Some("iss-val"));
    assert_eq!(fact.exp, Some(123456));
    assert!(matches!(
        fact.scalar_claims.get(&50),
        Some(CwtClaimScalar::Bool(true))
    ));

    // Bytes value should extract as a string via extract_string Bytes branch.
    // \xAA\xBB is not valid UTF-8, so no scalar string for claim 51.
    assert!(!fact.scalar_claims.contains_key(&51));
    assert!(fact.raw_claims.contains_key(&51));
}

// ---------------------------------------------------------------------------
// CWT claims from Map — Bytes value that IS valid UTF-8 (extract_string Bytes branch)
// ---------------------------------------------------------------------------

#[test]
fn cwt_claims_map_extracts_string_from_utf8_bytes_value() {
    let p = EverParseCborProvider;
    let mut enc = p.encoder();

    // { 15: { 1: h'6973737565725f62' } } — h'6973737565725f62' is UTF-8 for "issuer_b"
    enc.encode_map(1).unwrap();
    enc.encode_i64(15).unwrap();

    enc.encode_map(1).unwrap();
    enc.encode_i64(1).unwrap();
    enc.encode_bstr(b"issuer_b").unwrap();

    let phdr = enc.into_bytes();
    let cose_bytes = build_cose_sign1_with_raw_protected(&phdr, Some(b"payload"));
    let engine = engine_with_parsed(&cose_bytes);
    let subject = message_subject();

    let fact = match engine.get_fact_set::<CwtClaimsFact>(&subject).unwrap() {
        TrustFactSet::Available(v) => v.into_iter().next().expect("one CwtClaimsFact"),
        other => panic!("expected Available, got {other:?}"),
    };

    // extract_string should decode CoseHeaderValue::Bytes as UTF-8, mapping to iss.
    assert_eq!(fact.iss.as_deref(), Some("issuer_b"));
    assert!(matches!(
        fact.scalar_claims.get(&1),
        Some(CwtClaimScalar::Str(s)) if s == "issuer_b"
    ));
}

// ---------------------------------------------------------------------------
// CWT claims from Map — Uint value within i64 range (extract_i64 Uint branch)
// ---------------------------------------------------------------------------

#[test]
fn cwt_claims_map_extracts_i64_from_uint_value() {
    let p = EverParseCborProvider;
    let mut enc = p.encoder();

    // { 15: { 4: uint(42) } }
    enc.encode_map(1).unwrap();
    enc.encode_i64(15).unwrap();

    enc.encode_map(1).unwrap();
    enc.encode_i64(4).unwrap();
    enc.encode_u64(42).unwrap();

    let phdr = enc.into_bytes();
    let cose_bytes = build_cose_sign1_with_raw_protected(&phdr, Some(b"payload"));
    let engine = engine_with_parsed(&cose_bytes);
    let subject = message_subject();

    let fact = match engine.get_fact_set::<CwtClaimsFact>(&subject).unwrap() {
        TrustFactSet::Available(v) => v.into_iter().next().expect("one CwtClaimsFact"),
        other => panic!("expected Available, got {other:?}"),
    };

    assert_eq!(fact.exp, Some(42));
    assert!(matches!(
        fact.scalar_claims.get(&4),
        Some(CwtClaimScalar::I64(42))
    ));
}

// ---------------------------------------------------------------------------
// Detached payload — payload is None
// ---------------------------------------------------------------------------

#[test]
fn detached_payload_present_true_when_payload_is_null() {
    let cose_bytes = build_cose_sign1(
        &[(1, CborValue::I64(-7))],
        &[],
        None,
    );
    let engine = engine_with_parsed(&cose_bytes);
    let subject = message_subject();

    let dp = match engine.get_fact_set::<DetachedPayloadPresentFact>(&subject).unwrap() {
        TrustFactSet::Available(v) => v.into_iter().next().expect("one DetachedPayloadPresentFact"),
        other => panic!("expected Available, got {other:?}"),
    };
    assert!(dp.present);
}

#[test]
fn detached_payload_present_false_when_payload_exists() {
    let cose_bytes = build_cose_sign1(
        &[(1, CborValue::I64(-7))],
        &[],
        Some(b"data"),
    );
    let engine = engine_with_parsed(&cose_bytes);
    let subject = message_subject();

    let dp = match engine.get_fact_set::<DetachedPayloadPresentFact>(&subject).unwrap() {
        TrustFactSet::Available(v) => v.into_iter().next().expect("one DetachedPayloadPresentFact"),
        other => panic!("expected Available, got {other:?}"),
    };
    assert!(!dp.present);
}

// ---------------------------------------------------------------------------
// Non-Message subject — short-circuits and marks all facts as produced (empty)
// ---------------------------------------------------------------------------

#[test]
fn non_message_subject_produces_empty_fact_sets_for_all_fact_types() {
    let cose_bytes = build_cose_sign1(
        &[(1, CborValue::I64(-7)), (3, CborValue::Text("text/plain"))],
        &[],
        Some(b"payload"),
    );

    let producer = Arc::new(CoseSign1MessageFactProducer::new());
    let engine = TrustFactEngine::new(vec![producer])
        .with_cose_sign1_bytes(Arc::from(cose_bytes.into_boxed_slice()));

    let subject = TrustSubject::root("SigningKey", b"seed");

    // Every fact type the producer provides should be Available(empty).
    let bytes = engine.get_fact_set::<CoseSign1MessageBytesFact>(&subject).unwrap();
    assert!(matches!(bytes, TrustFactSet::Available(v) if v.is_empty()));

    let ct = engine.get_fact_set::<ContentTypeFact>(&subject).unwrap();
    assert!(matches!(ct, TrustFactSet::Available(v) if v.is_empty()));

    let cwt = engine.get_fact_set::<CwtClaimsFact>(&subject).unwrap();
    assert!(matches!(cwt, TrustFactSet::Available(v) if v.is_empty()));

    let cwtp = engine.get_fact_set::<CwtClaimsPresentFact>(&subject).unwrap();
    assert!(matches!(cwtp, TrustFactSet::Available(v) if v.is_empty()));

    let dp = engine.get_fact_set::<DetachedPayloadPresentFact>(&subject).unwrap();
    assert!(matches!(dp, TrustFactSet::Available(v) if v.is_empty()));

    let psk = engine.get_fact_set::<PrimarySigningKeySubjectFact>(&subject).unwrap();
    assert!(matches!(psk, TrustFactSet::Available(v) if v.is_empty()));
}

// ---------------------------------------------------------------------------
// Missing message bytes — marks all facts missing with reason
// ---------------------------------------------------------------------------

#[test]
fn missing_bytes_marks_cwt_claims_and_present_as_missing() {
    let producer = Arc::new(CoseSign1MessageFactProducer::new());
    let engine = TrustFactEngine::new(vec![producer]);
    let subject = message_subject();

    let cwtp = engine.get_fact_set::<CwtClaimsPresentFact>(&subject).unwrap();
    assert!(matches!(cwtp, TrustFactSet::Missing { .. }));

    let cwt = engine.get_fact_set::<CwtClaimsFact>(&subject).unwrap();
    assert!(matches!(cwt, TrustFactSet::Missing { .. }));
}

// ---------------------------------------------------------------------------
// CWT claims from Map — encode_value_recursive coverage
// (Null, Undefined, Float, Raw passthrough via nested values)
// ---------------------------------------------------------------------------

fn encode_protected_with_null_claim() -> Vec<u8> {
    let p = EverParseCborProvider;
    let mut enc = p.encoder();

    // { 15: { 300: null } }
    enc.encode_map(1).unwrap();
    enc.encode_i64(15).unwrap();

    enc.encode_map(1).unwrap();
    enc.encode_i64(300).unwrap();
    enc.encode_null().unwrap();

    enc.into_bytes()
}

#[test]
fn cwt_claims_map_handles_null_value() {
    let phdr = encode_protected_with_null_claim();
    let cose_bytes = build_cose_sign1_with_raw_protected(&phdr, Some(b"payload"));
    let engine = engine_with_parsed(&cose_bytes);
    let subject = message_subject();

    let fact = match engine.get_fact_set::<CwtClaimsFact>(&subject).unwrap() {
        TrustFactSet::Available(v) => v.into_iter().next().expect("one CwtClaimsFact"),
        other => panic!("expected Available, got {other:?}"),
    };

    // Null is not extractable as a scalar claim.
    assert!(!fact.scalar_claims.contains_key(&300));

    // Raw claims bytes should still be populated via encode_value_to_bytes.
    assert!(fact.raw_claims.contains_key(&300));
}

// ---------------------------------------------------------------------------
// Primary signing key subject is always produced for Message subjects
// ---------------------------------------------------------------------------

#[test]
fn primary_signing_key_subject_is_produced() {
    let cose_bytes = build_cose_sign1(
        &[(1, CborValue::I64(-7))],
        &[],
        Some(b"payload"),
    );
    let engine = engine_with_parsed(&cose_bytes);
    let subject = message_subject();

    let psk = engine.get_facts::<PrimarySigningKeySubjectFact>(&subject).unwrap();
    assert_eq!(1, psk.len());
    assert_eq!("PrimarySigningKey", psk[0].subject.kind);
}
