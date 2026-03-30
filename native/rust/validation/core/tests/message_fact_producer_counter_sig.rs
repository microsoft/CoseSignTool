// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Tests targeting uncovered code paths in `message_fact_producer.rs`:
//! counter-signature resolution, content-type resolution edge cases,
//! header extraction, CWT text-keyed claims from Map, and
//! encode_value_recursive complex types.

use cbor_primitives::{CborEncoder, CborProvider};
use cbor_primitives_everparse::EverParseCborProvider;
use cose_sign1_validation::fluent::*;
use cose_sign1_validation_primitives::facts::{TrustFactEngine, TrustFactSet};
use cose_sign1_validation_primitives::subject::TrustSubject;
use std::sync::Arc;

// ---------------------------------------------------------------------------
// Mock types for counter-signature resolution
// ---------------------------------------------------------------------------

struct SimpleCounterSignature {
    raw: Arc<[u8]>,
    protected: bool,
}

impl CounterSignature for SimpleCounterSignature {
    fn raw_counter_signature_bytes(&self) -> Arc<[u8]> {
        self.raw.clone()
    }

    fn is_protected_header(&self) -> bool {
        self.protected
    }

    fn cose_key(&self) -> Arc<dyn CryptoVerifier> {
        Arc::new(NoopVerifier)
    }
}

struct NoopVerifier;

impl CryptoVerifier for NoopVerifier {
    fn algorithm(&self) -> i64 {
        -7
    }

    fn verify(&self, _data: &[u8], _signature: &[u8]) -> Result<bool, CryptoError> {
        Ok(false)
    }
}

struct SuccessResolver {
    sigs: Vec<Arc<dyn CounterSignature>>,
}

impl CounterSignatureResolver for SuccessResolver {
    fn name(&self) -> &'static str {
        "success_resolver"
    }

    fn resolve(&self, _: &CoseSign1Message) -> CounterSignatureResolutionResult {
        CounterSignatureResolutionResult::success(self.sigs.clone())
    }
}

struct FailResolver {
    resolver_name: &'static str,
    error_msg: Option<&'static str>,
}

impl CounterSignatureResolver for FailResolver {
    fn name(&self) -> &'static str {
        self.resolver_name
    }

    fn resolve(&self, _: &CoseSign1Message) -> CounterSignatureResolutionResult {
        CounterSignatureResolutionResult::failure(None, self.error_msg.map(|s| s.to_string()))
    }
}

// ---------------------------------------------------------------------------
// COSE builder helpers
// ---------------------------------------------------------------------------

enum CborValue {
    I64(i64),
    Text(&'static str),
    Bytes(Vec<u8>),
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
            CborValue::Bytes(b) => enc.encode_bstr(b.as_slice()).unwrap(),
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
    enc.encode_bstr(&protected_bytes).unwrap();
    enc.encode_map(unprotected_map.len()).unwrap();
    for (k, v) in unprotected_map {
        enc.encode_i64(*k).unwrap();
        match v {
            CborValue::I64(i) => enc.encode_i64(*i).unwrap(),
            CborValue::Text(s) => enc.encode_tstr(s).unwrap(),
            CborValue::Bytes(b) => enc.encode_bstr(b.as_slice()).unwrap(),
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

fn engine_with_parsed(cose_bytes: &[u8]) -> TrustFactEngine {
    let parsed = cose_sign1_primitives::CoseSign1Message::parse(cose_bytes).expect("parse");

    let producer = Arc::new(CoseSign1MessageFactProducer::new());
    TrustFactEngine::new(vec![producer])
        .with_cose_sign1_bytes(Arc::from(cose_bytes.to_vec().into_boxed_slice()))
        .with_cose_sign1_message(Arc::new(parsed))
}

fn engine_with_parsed_and_resolvers(
    cose_bytes: &[u8],
    resolvers: Vec<Arc<dyn CounterSignatureResolver>>,
) -> TrustFactEngine {
    let parsed = cose_sign1_primitives::CoseSign1Message::parse(cose_bytes).expect("parse");

    let producer =
        Arc::new(CoseSign1MessageFactProducer::new().with_counter_signature_resolvers(resolvers));
    TrustFactEngine::new(vec![producer])
        .with_cose_sign1_bytes(Arc::from(cose_bytes.to_vec().into_boxed_slice()))
        .with_cose_sign1_message(Arc::new(parsed))
}

fn message_subject() -> TrustSubject {
    TrustSubject::message(b"seed")
}

fn simple_cose_bytes() -> Vec<u8> {
    build_cose_sign1(&[(1, CborValue::I64(-7))], &[], Some(b"payload"))
}

// ===========================================================================
// Counter-signature resolution tests
// ===========================================================================

#[test]
fn counter_sig_mixed_success_and_failure_produces_facts_from_successful_resolver() {
    let cose_bytes = simple_cose_bytes();
    let cs: Arc<dyn CounterSignature> = Arc::new(SimpleCounterSignature {
        raw: Arc::from(b"cs-alpha".as_slice()),
        protected: true,
    });

    let engine = engine_with_parsed_and_resolvers(
        &cose_bytes,
        vec![
            Arc::new(FailResolver {
                resolver_name: "failing",
                error_msg: Some("boom"),
            }),
            Arc::new(SuccessResolver { sigs: vec![cs] }),
        ],
    );
    let subject = message_subject();

    // Despite one resolver failing, counter-signature facts should be produced.
    let subjects = engine
        .get_facts::<CounterSignatureSubjectFact>(&subject)
        .unwrap();
    assert_eq!(1, subjects.len());
    assert_eq!("CounterSignature", subjects[0].subject.kind);
    assert!(subjects[0].is_protected_header);

    let signing_keys = engine
        .get_facts::<CounterSignatureSigningKeySubjectFact>(&subject)
        .unwrap();
    assert_eq!(1, signing_keys.len());
    assert_eq!("CounterSignatureSigningKey", signing_keys[0].subject.kind);

    let unknowns = engine
        .get_facts::<UnknownCounterSignatureBytesFact>(&subject)
        .unwrap();
    assert_eq!(1, unknowns.len());
    assert_eq!(
        b"cs-alpha".as_slice(),
        unknowns[0].raw_counter_signature_bytes.as_ref()
    );

    // Facts should NOT be missing since at least one resolver succeeded.
    let set = engine
        .get_fact_set::<CounterSignatureSubjectFact>(&subject)
        .unwrap();
    assert!(matches!(set, TrustFactSet::Available(_)));
}

#[test]
fn counter_sig_dedup_across_two_resolvers_with_same_raw_bytes() {
    let cose_bytes = simple_cose_bytes();
    let raw: Arc<[u8]> = Arc::from(b"shared-bytes".as_slice());

    let cs1: Arc<dyn CounterSignature> = Arc::new(SimpleCounterSignature {
        raw: raw.clone(),
        protected: true,
    });
    let cs2: Arc<dyn CounterSignature> = Arc::new(SimpleCounterSignature {
        raw: raw.clone(),
        protected: false,
    });

    let engine = engine_with_parsed_and_resolvers(
        &cose_bytes,
        vec![
            Arc::new(SuccessResolver { sigs: vec![cs1] }),
            Arc::new(SuccessResolver { sigs: vec![cs2] }),
        ],
    );
    let subject = message_subject();

    // Two CounterSignatureSubjectFact entries (one per counter-sig instance).
    let subjects = engine
        .get_facts::<CounterSignatureSubjectFact>(&subject)
        .unwrap();
    assert_eq!(2, subjects.len());

    // UnknownCounterSignatureBytesFact is deduplicated: same raw bytes → one entry.
    let unknowns = engine
        .get_facts::<UnknownCounterSignatureBytesFact>(&subject)
        .unwrap();
    assert_eq!(1, unknowns.len());
    assert_eq!(
        b"shared-bytes".as_slice(),
        unknowns[0].raw_counter_signature_bytes.as_ref()
    );
}

#[test]
fn counter_sig_failure_with_none_error_message() {
    let cose_bytes = simple_cose_bytes();

    let engine = engine_with_parsed_and_resolvers(
        &cose_bytes,
        vec![Arc::new(FailResolver {
            resolver_name: "none_msg",
            error_msg: None,
        })],
    );
    let subject = message_subject();

    let set = engine
        .get_fact_set::<CounterSignatureSubjectFact>(&subject)
        .unwrap();
    match set {
        TrustFactSet::Missing { reason } => {
            assert!(reason.contains("ProducerFailed:none_msg"));
            // No extra colon when error_message is None.
            assert!(!reason.contains("ProducerFailed:none_msg:"));
        }
        other => panic!("expected Missing, got {other:?}"),
    }
}

#[test]
fn counter_sig_failure_with_empty_error_message_trims_to_no_suffix() {
    let cose_bytes = simple_cose_bytes();

    let engine = engine_with_parsed_and_resolvers(
        &cose_bytes,
        vec![Arc::new(FailResolver {
            resolver_name: "empty_msg",
            error_msg: Some(""),
        })],
    );
    let subject = message_subject();

    let set = engine
        .get_fact_set::<CounterSignatureSubjectFact>(&subject)
        .unwrap();
    match set {
        TrustFactSet::Missing { reason } => {
            assert!(reason.contains("ProducerFailed:empty_msg"));
            // Empty string trims to empty → no appended error text.
            assert!(!reason.contains("ProducerFailed:empty_msg:"));
        }
        other => panic!("expected Missing, got {other:?}"),
    }
}

#[test]
fn counter_sig_multiple_distinct_sigs_from_single_resolver() {
    let cose_bytes = simple_cose_bytes();
    let cs1: Arc<dyn CounterSignature> = Arc::new(SimpleCounterSignature {
        raw: Arc::from(b"sig-a".as_slice()),
        protected: true,
    });
    let cs2: Arc<dyn CounterSignature> = Arc::new(SimpleCounterSignature {
        raw: Arc::from(b"sig-b".as_slice()),
        protected: false,
    });

    let engine = engine_with_parsed_and_resolvers(
        &cose_bytes,
        vec![Arc::new(SuccessResolver {
            sigs: vec![cs1, cs2],
        })],
    );
    let subject = message_subject();

    let subjects = engine
        .get_facts::<CounterSignatureSubjectFact>(&subject)
        .unwrap();
    assert_eq!(2, subjects.len());
    assert!(subjects[0].is_protected_header);
    assert!(!subjects[1].is_protected_header);

    let signing_keys = engine
        .get_facts::<CounterSignatureSigningKeySubjectFact>(&subject)
        .unwrap();
    assert_eq!(2, signing_keys.len());

    // Two distinct raw bytes → two UnknownCounterSignatureBytesFact entries (no dedup).
    let unknowns = engine
        .get_facts::<UnknownCounterSignatureBytesFact>(&subject)
        .unwrap();
    assert_eq!(2, unknowns.len());
}

// ===========================================================================
// Content-type resolution edge cases
// ===========================================================================

#[test]
fn content_type_empty_text_header_produces_no_fact() {
    let cose_bytes = build_cose_sign1(
        &[(1, CborValue::I64(-7)), (3, CborValue::Text("   "))],
        &[],
        Some(b"payload"),
    );
    let engine = engine_with_parsed(&cose_bytes);
    let subject = message_subject();

    let ct = engine.get_fact_set::<ContentTypeFact>(&subject).unwrap();
    match ct {
        TrustFactSet::Available(v) => assert!(
            v.is_empty(),
            "whitespace-only text should yield no ContentTypeFact"
        ),
        other => panic!("expected Available(empty), got {other:?}"),
    }
}

#[test]
fn content_type_bytes_header_valid_utf8_is_used() {
    let cose_bytes = build_cose_sign1(
        &[
            (1, CborValue::I64(-7)),
            (3, CborValue::Bytes(b"application/cbor".to_vec())),
        ],
        &[],
        Some(b"payload"),
    );
    let engine = engine_with_parsed(&cose_bytes);
    let subject = message_subject();

    let ct = engine.get_facts::<ContentTypeFact>(&subject).unwrap();
    assert_eq!(1, ct.len());
    assert_eq!("application/cbor", ct[0].content_type);
}

#[test]
fn content_type_bytes_header_invalid_utf8_produces_no_fact() {
    let cose_bytes = build_cose_sign1(
        &[
            (1, CborValue::I64(-7)),
            (3, CborValue::Bytes(vec![0xFF, 0xFE])),
        ],
        &[],
        Some(b"payload"),
    );
    let engine = engine_with_parsed(&cose_bytes);
    let subject = message_subject();

    let ct = engine.get_fact_set::<ContentTypeFact>(&subject).unwrap();
    match ct {
        TrustFactSet::Available(v) => assert!(
            v.is_empty(),
            "invalid UTF-8 bytes should yield no ContentTypeFact"
        ),
        other => panic!("expected Available(empty), got {other:?}"),
    }
}

#[test]
fn content_type_bytes_header_whitespace_only_produces_no_fact() {
    let cose_bytes = build_cose_sign1(
        &[
            (1, CborValue::I64(-7)),
            (3, CborValue::Bytes(b"  ".to_vec())),
        ],
        &[],
        Some(b"payload"),
    );
    let engine = engine_with_parsed(&cose_bytes);
    let subject = message_subject();

    let ct = engine.get_fact_set::<ContentTypeFact>(&subject).unwrap();
    match ct {
        TrustFactSet::Available(v) => assert!(
            v.is_empty(),
            "whitespace-only UTF-8 bytes should yield no ContentTypeFact"
        ),
        other => panic!("expected Available(empty), got {other:?}"),
    }
}

#[test]
fn content_type_integer_header_produces_no_fact_without_envelope_marker() {
    // Content-Type as integer without envelope marker → get_header_text returns None.
    let cose_bytes = build_cose_sign1(
        &[(1, CborValue::I64(-7)), (3, CborValue::I64(50))],
        &[],
        Some(b"payload"),
    );
    let engine = engine_with_parsed(&cose_bytes);
    let subject = message_subject();

    let ct = engine.get_fact_set::<ContentTypeFact>(&subject).unwrap();
    match ct {
        TrustFactSet::Available(v) => assert!(v.is_empty()),
        other => panic!("expected Available(empty), got {other:?}"),
    }
}

#[test]
fn content_type_preimage_from_unprotected_when_envelope_marker_in_protected() {
    // Envelope marker (258) in protected, preimage content-type (259) in unprotected.
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

#[test]
fn content_type_integer_preimage_from_unprotected() {
    let cose_bytes = build_cose_sign1(
        &[(1, CborValue::I64(-7)), (258, CborValue::I64(1))],
        &[(259, CborValue::I64(99))],
        Some(b"payload"),
    );
    let engine = engine_with_parsed(&cose_bytes);
    let subject = message_subject();

    let ct = engine.get_facts::<ContentTypeFact>(&subject).unwrap();
    assert_eq!(1, ct.len());
    assert_eq!("coap/99", ct[0].content_type);
}

#[test]
fn content_type_cose_hash_v_case_insensitive_strip() {
    let cose_bytes = build_cose_sign1(
        &[
            (1, CborValue::I64(-7)),
            (3, CborValue::Text("application/xml+COSE-HASH-V")),
        ],
        &[],
        Some(b"payload"),
    );
    let engine = engine_with_parsed(&cose_bytes);
    let subject = message_subject();

    let ct = engine.get_facts::<ContentTypeFact>(&subject).unwrap();
    assert_eq!(1, ct.len());
    assert_eq!("application/xml", ct[0].content_type);
}

#[test]
fn content_type_hash_legacy_case_insensitive_strip() {
    let cose_bytes = build_cose_sign1(
        &[
            (1, CborValue::I64(-7)),
            (3, CborValue::Text("application/xml+Hash-SHA512")),
        ],
        &[],
        Some(b"payload"),
    );
    let engine = engine_with_parsed(&cose_bytes);
    let subject = message_subject();

    let ct = engine.get_facts::<ContentTypeFact>(&subject).unwrap();
    assert_eq!(1, ct.len());
    assert_eq!("application/xml", ct[0].content_type);
}

#[test]
fn content_type_only_cose_hash_v_suffix_returns_none() {
    // Content type is ONLY "+cose-hash-v" → after stripping it's empty → returns None.
    let cose_bytes = build_cose_sign1(
        &[
            (1, CborValue::I64(-7)),
            (3, CborValue::Text("+cose-hash-v")),
        ],
        &[],
        Some(b"payload"),
    );
    let engine = engine_with_parsed(&cose_bytes);
    let subject = message_subject();

    let ct = engine.get_fact_set::<ContentTypeFact>(&subject).unwrap();
    match ct {
        TrustFactSet::Available(v) => assert!(v.is_empty()),
        other => panic!("expected Available(empty), got {other:?}"),
    }
}

#[test]
fn content_type_only_hash_legacy_suffix_returns_none() {
    // Content type is ONLY "+hash-sha256" → after stripping it's empty → returns None.
    let cose_bytes = build_cose_sign1(
        &[
            (1, CborValue::I64(-7)),
            (3, CborValue::Text("+hash-sha256")),
        ],
        &[],
        Some(b"payload"),
    );
    let engine = engine_with_parsed(&cose_bytes);
    let subject = message_subject();

    let ct = engine.get_fact_set::<ContentTypeFact>(&subject).unwrap();
    match ct {
        TrustFactSet::Available(v) => assert!(v.is_empty()),
        other => panic!("expected Available(empty), got {other:?}"),
    }
}

// ===========================================================================
// CWT claims from Map — text-keyed well-known claims
// ===========================================================================

#[test]
fn cwt_claims_map_text_keyed_claims_iss_sub_aud() {
    let p = EverParseCborProvider;
    let mut enc = p.encoder();

    // { 15: { "iss": "my-issuer", "sub": "my-subject", "aud": "my-audience" } }
    enc.encode_map(1).unwrap();
    enc.encode_i64(15).unwrap();

    enc.encode_map(3).unwrap();
    enc.encode_tstr("iss").unwrap();
    enc.encode_tstr("my-issuer").unwrap();
    enc.encode_tstr("sub").unwrap();
    enc.encode_tstr("my-subject").unwrap();
    enc.encode_tstr("aud").unwrap();
    enc.encode_tstr("my-audience").unwrap();

    let phdr = enc.into_bytes();
    let cose_bytes = build_cose_sign1_with_raw_protected(&phdr, Some(b"payload"));
    let engine = engine_with_parsed(&cose_bytes);
    let subject = message_subject();

    let fact = match engine.get_fact_set::<CwtClaimsFact>(&subject).unwrap() {
        TrustFactSet::Available(v) => v.into_iter().next().expect("one CwtClaimsFact"),
        other => panic!("expected Available, got {other:?}"),
    };

    assert_eq!(fact.iss.as_deref(), Some("my-issuer"));
    assert_eq!(fact.sub.as_deref(), Some("my-subject"));
    assert_eq!(fact.aud.as_deref(), Some("my-audience"));
    assert!(fact.raw_claims_text.contains_key("iss"));
    assert!(fact.raw_claims_text.contains_key("sub"));
    assert!(fact.raw_claims_text.contains_key("aud"));
}

#[test]
fn cwt_claims_map_text_keyed_claims_exp_nbf_iat() {
    let p = EverParseCborProvider;
    let mut enc = p.encoder();

    // { 15: { "exp": 2000000000, "nbf": 1900000000, "iat": 1950000000 } }
    enc.encode_map(1).unwrap();
    enc.encode_i64(15).unwrap();

    enc.encode_map(3).unwrap();
    enc.encode_tstr("exp").unwrap();
    enc.encode_i64(2_000_000_000).unwrap();
    enc.encode_tstr("nbf").unwrap();
    enc.encode_i64(1_900_000_000).unwrap();
    enc.encode_tstr("iat").unwrap();
    enc.encode_i64(1_950_000_000).unwrap();

    let phdr = enc.into_bytes();
    let cose_bytes = build_cose_sign1_with_raw_protected(&phdr, Some(b"payload"));
    let engine = engine_with_parsed(&cose_bytes);
    let subject = message_subject();

    let fact = match engine.get_fact_set::<CwtClaimsFact>(&subject).unwrap() {
        TrustFactSet::Available(v) => v.into_iter().next().expect("one CwtClaimsFact"),
        other => panic!("expected Available, got {other:?}"),
    };

    assert_eq!(fact.exp, Some(2_000_000_000));
    assert_eq!(fact.nbf, Some(1_900_000_000));
    assert_eq!(fact.iat, Some(1_950_000_000));
    assert!(fact.raw_claims_text.contains_key("exp"));
    assert!(fact.raw_claims_text.contains_key("nbf"));
    assert!(fact.raw_claims_text.contains_key("iat"));
}

// ===========================================================================
// encode_value_recursive — complex type coverage
// ===========================================================================

#[test]
fn cwt_claims_map_handles_array_value_encoding() {
    let p = EverParseCborProvider;
    let mut enc = p.encoder();

    // { 15: { 500: [1, "two", true] } }
    enc.encode_map(1).unwrap();
    enc.encode_i64(15).unwrap();
    enc.encode_map(1).unwrap();
    enc.encode_i64(500).unwrap();
    enc.encode_array(3).unwrap();
    enc.encode_i64(1).unwrap();
    enc.encode_tstr("two").unwrap();
    enc.encode_bool(true).unwrap();

    let phdr = enc.into_bytes();
    let cose_bytes = build_cose_sign1_with_raw_protected(&phdr, Some(b"payload"));
    let engine = engine_with_parsed(&cose_bytes);
    let subject = message_subject();

    let fact = match engine.get_fact_set::<CwtClaimsFact>(&subject).unwrap() {
        TrustFactSet::Available(v) => v.into_iter().next().expect("one CwtClaimsFact"),
        other => panic!("expected Available, got {other:?}"),
    };

    // Array is not a scalar type.
    assert!(!fact.scalar_claims.contains_key(&500));
    // Raw claim bytes should be present (encode_value_recursive Array branch).
    assert!(fact.raw_claims.contains_key(&500));
}

#[test]
fn cwt_claims_map_handles_nested_map_value_encoding() {
    let p = EverParseCborProvider;
    let mut enc = p.encoder();

    // { 15: { 501: { 10: "inner" } } }
    enc.encode_map(1).unwrap();
    enc.encode_i64(15).unwrap();
    enc.encode_map(1).unwrap();
    enc.encode_i64(501).unwrap();
    enc.encode_map(1).unwrap();
    enc.encode_i64(10).unwrap();
    enc.encode_tstr("inner").unwrap();

    let phdr = enc.into_bytes();
    let cose_bytes = build_cose_sign1_with_raw_protected(&phdr, Some(b"payload"));
    let engine = engine_with_parsed(&cose_bytes);
    let subject = message_subject();

    let fact = match engine.get_fact_set::<CwtClaimsFact>(&subject).unwrap() {
        TrustFactSet::Available(v) => v.into_iter().next().expect("one CwtClaimsFact"),
        other => panic!("expected Available, got {other:?}"),
    };

    assert!(!fact.scalar_claims.contains_key(&501));
    assert!(fact.raw_claims.contains_key(&501));
}

#[test]
fn cwt_claims_map_handles_tagged_value_encoding() {
    let p = EverParseCborProvider;
    let mut enc = p.encoder();

    // { 15: { 502: tag(1, 1700000000) } }
    enc.encode_map(1).unwrap();
    enc.encode_i64(15).unwrap();
    enc.encode_map(1).unwrap();
    enc.encode_i64(502).unwrap();
    enc.encode_tag(1).unwrap();
    enc.encode_i64(1_700_000_000).unwrap();

    let phdr = enc.into_bytes();
    let cose_bytes = build_cose_sign1_with_raw_protected(&phdr, Some(b"payload"));
    let engine = engine_with_parsed(&cose_bytes);
    let subject = message_subject();

    let fact = match engine.get_fact_set::<CwtClaimsFact>(&subject).unwrap() {
        TrustFactSet::Available(v) => v.into_iter().next().expect("one CwtClaimsFact"),
        other => panic!("expected Available, got {other:?}"),
    };

    assert!(!fact.scalar_claims.contains_key(&502));
    assert!(fact.raw_claims.contains_key(&502));
}

#[test]
fn cwt_claims_map_handles_bool_and_null_encoding() {
    let p = EverParseCborProvider;
    let mut enc = p.encoder();

    // { 15: { 600: true, 601: null } }
    enc.encode_map(1).unwrap();
    enc.encode_i64(15).unwrap();
    enc.encode_map(2).unwrap();

    enc.encode_i64(600).unwrap();
    enc.encode_bool(true).unwrap();

    enc.encode_i64(601).unwrap();
    enc.encode_null().unwrap();

    let phdr = enc.into_bytes();
    let cose_bytes = build_cose_sign1_with_raw_protected(&phdr, Some(b"payload"));
    let engine = engine_with_parsed(&cose_bytes);
    let subject = message_subject();

    let fact = match engine.get_fact_set::<CwtClaimsFact>(&subject).unwrap() {
        TrustFactSet::Available(v) => v.into_iter().next().expect("one CwtClaimsFact"),
        other => panic!("expected Available, got {other:?}"),
    };

    // Bool should be a scalar claim.
    assert!(matches!(
        fact.scalar_claims.get(&600),
        Some(CwtClaimScalar::Bool(true))
    ));
    // Null is not a scalar, but raw bytes are present.
    assert!(!fact.scalar_claims.contains_key(&601));
    assert!(fact.raw_claims.contains_key(&601));
}

#[test]
fn cwt_claims_map_handles_map_with_text_key_encoding() {
    let p = EverParseCborProvider;
    let mut enc = p.encoder();

    // { 15: { 700: { "text_key": 42 } } }
    // Exercises Map branch with Text key in encode_value_recursive.
    enc.encode_map(1).unwrap();
    enc.encode_i64(15).unwrap();
    enc.encode_map(1).unwrap();
    enc.encode_i64(700).unwrap();
    enc.encode_map(1).unwrap();
    enc.encode_tstr("text_key").unwrap();
    enc.encode_i64(42).unwrap();

    let phdr = enc.into_bytes();
    let cose_bytes = build_cose_sign1_with_raw_protected(&phdr, Some(b"payload"));
    let engine = engine_with_parsed(&cose_bytes);
    let subject = message_subject();

    let fact = match engine.get_fact_set::<CwtClaimsFact>(&subject).unwrap() {
        TrustFactSet::Available(v) => v.into_iter().next().expect("one CwtClaimsFact"),
        other => panic!("expected Available, got {other:?}"),
    };

    assert!(fact.raw_claims.contains_key(&700));
}

// ===========================================================================
// get_header_text / get_header_int edge cases
// ===========================================================================

#[test]
fn get_header_int_returns_integer_preimage_content_type() {
    // Exercises get_header_int path for preimage content type (label 259).
    let cose_bytes = build_cose_sign1(
        &[
            (1, CborValue::I64(-7)),
            (258, CborValue::I64(1)),
            (259, CborValue::I64(0)),
        ],
        &[],
        Some(b"payload"),
    );
    let engine = engine_with_parsed(&cose_bytes);
    let subject = message_subject();

    let ct = engine.get_facts::<ContentTypeFact>(&subject).unwrap();
    assert_eq!(1, ct.len());
    assert_eq!("coap/0", ct[0].content_type);
}

#[test]
fn content_type_from_unprotected_bytes_utf8() {
    // Content-type as bytes in unprotected header (get_header_text Bytes branch on unprotected).
    let cose_bytes = build_cose_sign1(
        &[(1, CborValue::I64(-7))],
        &[(3, CborValue::Bytes(b"text/html".to_vec()))],
        Some(b"payload"),
    );
    let engine = engine_with_parsed(&cose_bytes);
    let subject = message_subject();

    let ct = engine.get_facts::<ContentTypeFact>(&subject).unwrap();
    assert_eq!(1, ct.len());
    assert_eq!("text/html", ct[0].content_type);
}
