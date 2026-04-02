// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Tests for `produce_cwt_claims_from_bytes()` — the code path triggered when
//! CWT claims (label 15) are stored as `CoseHeaderValue::Raw(bytes)` in the
//! protected header.  Parsing always decodes maps to `CoseHeaderValue::Map`,
//! so we parse a minimal message and then *replace* label 15 with a `Raw`
//! variant to exercise the raw-bytes code path.

use cbor_primitives::{CborEncoder, CborProvider};
use cbor_primitives_everparse::EverParseCborProvider;
use cose_sign1_primitives::{CoseHeaderLabel, CoseHeaderValue, CoseSign1Message};
use cose_sign1_validation::fluent::*;
use cose_sign1_validation_primitives::facts::{TrustFactEngine, TrustFactSet};
use cose_sign1_validation_primitives::subject::TrustSubject;
use std::sync::Arc;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Build a minimal COSE_Sign1 byte sequence with an empty protected header.
fn build_minimal_cose_sign1() -> Vec<u8> {
    let p = EverParseCborProvider;
    let mut enc = p.encoder();
    enc.encode_array(4).unwrap();
    // protected: empty map as bstr
    let mut inner = p.encoder();
    inner.encode_map(0).unwrap();
    enc.encode_bstr(&inner.into_bytes()).unwrap();
    // unprotected: empty map
    enc.encode_map(0).unwrap();
    // payload
    enc.encode_bstr(b"test").unwrap();
    // signature
    enc.encode_bstr(b"sig").unwrap();
    enc.into_bytes()
}

/// Encode a CBOR map from `(key, value)` pairs and return the raw bytes.
/// Keys and values are encoded with the provided closures.
fn encode_cwt_raw<F>(count: usize, encode_pairs: F) -> Vec<u8>
where
    F: FnOnce(&mut <EverParseCborProvider as CborProvider>::Encoder),
{
    let p = EverParseCborProvider;
    let mut enc = p.encoder();
    enc.encode_map(count).unwrap();
    encode_pairs(&mut enc);
    enc.into_bytes()
}

/// Parse a minimal COSE message, inject `CoseHeaderValue::Raw(cwt_raw)` at
/// label 15, and build an engine from it.
fn engine_with_raw_cwt(cwt_raw: Vec<u8>) -> TrustFactEngine {
    let cose_bytes = build_minimal_cose_sign1();
    let mut parsed = CoseSign1Message::parse(&cose_bytes).unwrap();

    parsed.protected.insert(
        CoseHeaderLabel::Int(15),
        CoseHeaderValue::Raw(cwt_raw.into()),
    );

    let producer = Arc::new(CoseSign1MessageFactProducer::new());
    TrustFactEngine::new(vec![producer])
        .with_cose_sign1_bytes(Arc::from(cose_bytes.into_boxed_slice()))
        .with_cose_sign1_message(Arc::new(parsed))
}

fn message_subject() -> TrustSubject {
    TrustSubject::message(b"seed")
}

fn extract_cwt_fact(engine: &TrustFactEngine, subject: &TrustSubject) -> Arc<CwtClaimsFact> {
    match engine.get_fact_set::<CwtClaimsFact>(subject).unwrap() {
        TrustFactSet::Available(v) => v.into_iter().next().expect("one CwtClaimsFact"),
        other => panic!("expected Available, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// 1. All well-known integer claims (iss=1, sub=2, aud=3, exp=4, nbf=5, iat=6)
// ---------------------------------------------------------------------------

#[test]
fn raw_cwt_all_wellknown_int_claims() {
    let cwt_raw = encode_cwt_raw(6, |enc| {
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
    });

    let engine = engine_with_raw_cwt(cwt_raw);
    let subject = message_subject();
    let fact = extract_cwt_fact(&engine, &subject);

    assert_eq!(fact.iss.as_deref(), Some("issuer"));
    assert_eq!(fact.sub.as_deref(), Some("subject"));
    assert_eq!(fact.aud.as_deref(), Some("audience"));
    assert_eq!(fact.exp, Some(1_700_000_000));
    assert_eq!(fact.nbf, Some(1_600_000_000));
    assert_eq!(fact.iat, Some(1_650_000_000));

    assert!(matches!(fact.scalar_claims.get(&1), Some(CwtClaimScalar::Str(s)) if s == "issuer"));
    assert!(matches!(
        fact.scalar_claims.get(&4),
        Some(CwtClaimScalar::I64(1_700_000_000))
    ));
}

// ---------------------------------------------------------------------------
// 2. Text-keyed well-known claims
// ---------------------------------------------------------------------------

#[test]
fn raw_cwt_text_keyed_wellknown_claims() {
    let p = EverParseCborProvider;
    let mut enc = p.encoder();
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
    let cwt_raw = enc.into_bytes();

    let engine = engine_with_raw_cwt(cwt_raw);
    let subject = message_subject();
    let fact = extract_cwt_fact(&engine, &subject);

    assert_eq!(fact.iss.as_deref(), Some("txt-issuer"));
    assert_eq!(fact.sub.as_deref(), Some("txt-subject"));
    assert_eq!(fact.aud.as_deref(), Some("txt-audience"));
    assert_eq!(fact.exp, Some(2_000_000_000));
    assert_eq!(fact.nbf, Some(1_900_000_000));
    assert_eq!(fact.iat, Some(1_950_000_000));

    assert!(fact.raw_claims_text.contains_key("iss"));
    assert!(fact.raw_claims_text.contains_key("exp"));
}

// ---------------------------------------------------------------------------
// 3. Bool values in raw CWT
// ---------------------------------------------------------------------------

#[test]
fn raw_cwt_bool_values() {
    let cwt_raw = encode_cwt_raw(2, |enc| {
        enc.encode_i64(100).unwrap();
        enc.encode_bool(true).unwrap();
        enc.encode_i64(101).unwrap();
        enc.encode_bool(false).unwrap();
    });

    let engine = engine_with_raw_cwt(cwt_raw);
    let subject = message_subject();
    let fact = extract_cwt_fact(&engine, &subject);

    assert!(matches!(
        fact.scalar_claims.get(&100),
        Some(CwtClaimScalar::Bool(true))
    ));
    assert!(matches!(
        fact.scalar_claims.get(&101),
        Some(CwtClaimScalar::Bool(false))
    ));
    assert!(fact.raw_claims.contains_key(&100));
    assert!(fact.raw_claims.contains_key(&101));
}

// ---------------------------------------------------------------------------
// 4. Non-standard integer keys (fallback paths)
// ---------------------------------------------------------------------------

#[test]
fn raw_cwt_nonstandard_int_keys() {
    let cwt_raw = encode_cwt_raw(2, |enc| {
        enc.encode_i64(999).unwrap();
        enc.encode_tstr("val999").unwrap();
        enc.encode_i64(1000).unwrap();
        enc.encode_i64(42).unwrap();
    });

    let engine = engine_with_raw_cwt(cwt_raw);
    let subject = message_subject();
    let fact = extract_cwt_fact(&engine, &subject);

    assert!(fact.iss.is_none());
    assert!(fact.sub.is_none());
    assert!(fact.aud.is_none());
    assert!(fact.exp.is_none());
    assert!(fact.nbf.is_none());
    assert!(fact.iat.is_none());

    assert!(matches!(fact.scalar_claims.get(&999), Some(CwtClaimScalar::Str(s)) if s == "val999"));
    assert!(matches!(
        fact.scalar_claims.get(&1000),
        Some(CwtClaimScalar::I64(42))
    ));
    assert!(fact.raw_claims.contains_key(&999));
    assert!(fact.raw_claims.contains_key(&1000));
}

// ---------------------------------------------------------------------------
// 5. Decode error — truncated / corrupt bytes
// ---------------------------------------------------------------------------

#[test]
fn raw_cwt_key_decode_error() {
    // A valid map header for 2 entries, but only 1 byte of key data follows,
    // which is a truncated CBOR item.
    let cwt_raw = vec![0xA2, 0x18]; // map(2), then truncated uint8 key

    let engine = engine_with_raw_cwt(cwt_raw);
    let subject = message_subject();

    let claims = engine.get_fact_set::<CwtClaimsFact>(&subject).unwrap();
    match claims {
        TrustFactSet::Error { message } => {
            assert!(
                message.contains("cwt_claim_key_decode_failed"),
                "unexpected error message: {message}"
            );
        }
        other => panic!("expected Error for key decode, got {other:?}"),
    }
}

#[test]
fn raw_cwt_value_decode_error() {
    // map(1), key = int(1), then truncated value
    let p = EverParseCborProvider;
    let mut enc = p.encoder();
    enc.encode_map(1).unwrap();
    enc.encode_i64(1).unwrap();
    let mut bytes = enc.into_bytes();
    // Append a truncated uint8 value (0x18 requires one more byte)
    bytes.push(0x18);

    let engine = engine_with_raw_cwt(bytes);
    let subject = message_subject();

    let claims = engine.get_fact_set::<CwtClaimsFact>(&subject).unwrap();
    match claims {
        TrustFactSet::Error { message } => {
            assert!(
                message.contains("cwt_claim_value_decode_failed"),
                "unexpected error message: {message}"
            );
        }
        other => panic!("expected Error for value decode, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// 6. Indefinite-length map
// ---------------------------------------------------------------------------

#[test]
fn raw_cwt_indefinite_map_not_supported() {
    // CBOR indefinite-length map: 0xBF ... 0xFF
    let cwt_raw = vec![0xBF, 0xFF]; // indefinite map, break

    let engine = engine_with_raw_cwt(cwt_raw);
    let subject = message_subject();

    let claims = engine.get_fact_set::<CwtClaimsFact>(&subject).unwrap();
    match claims {
        TrustFactSet::Error { message } => {
            assert!(
                message.contains("indefinite map not supported"),
                "unexpected error message: {message}"
            );
        }
        other => panic!("expected Error for indefinite map, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// 7. Map decode error (not a map at all)
// ---------------------------------------------------------------------------

#[test]
fn raw_cwt_map_decode_error() {
    // CBOR text string "hello" — not a map
    let p = EverParseCborProvider;
    let mut enc = p.encoder();
    enc.encode_tstr("hello").unwrap();
    let cwt_raw = enc.into_bytes();

    let engine = engine_with_raw_cwt(cwt_raw);
    let subject = message_subject();

    let claims = engine.get_fact_set::<CwtClaimsFact>(&subject).unwrap();
    match claims {
        TrustFactSet::Error { message } => {
            assert!(
                message.contains("cwt_claims_map_decode_failed"),
                "unexpected error message: {message}"
            );
        }
        other => panic!("expected Error for map decode, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// 8. Mixed int and text keys
// ---------------------------------------------------------------------------

#[test]
fn raw_cwt_mixed_int_and_text_keys() {
    let p = EverParseCborProvider;
    let mut enc = p.encoder();
    enc.encode_map(3).unwrap();
    enc.encode_i64(1).unwrap();
    enc.encode_tstr("issuer").unwrap();
    enc.encode_tstr("custom").unwrap();
    enc.encode_i64(77).unwrap();
    enc.encode_i64(999).unwrap();
    enc.encode_tstr("val999").unwrap();
    let cwt_raw = enc.into_bytes();

    let engine = engine_with_raw_cwt(cwt_raw);
    let subject = message_subject();
    let fact = extract_cwt_fact(&engine, &subject);

    assert_eq!(fact.iss.as_deref(), Some("issuer"));
    assert!(fact.raw_claims.contains_key(&1));
    assert!(fact.raw_claims.contains_key(&999));
    assert!(fact.raw_claims_text.contains_key("custom"));
}

// ---------------------------------------------------------------------------
// 9. Only i64 values (no string values) — i64 scalar path
// ---------------------------------------------------------------------------

#[test]
fn raw_cwt_only_i64_values() {
    let cwt_raw = encode_cwt_raw(3, |enc| {
        enc.encode_i64(10).unwrap();
        enc.encode_i64(100).unwrap();
        enc.encode_i64(11).unwrap();
        enc.encode_i64(200).unwrap();
        enc.encode_i64(12).unwrap();
        enc.encode_i64(300).unwrap();
    });

    let engine = engine_with_raw_cwt(cwt_raw);
    let subject = message_subject();
    let fact = extract_cwt_fact(&engine, &subject);

    assert!(matches!(
        fact.scalar_claims.get(&10),
        Some(CwtClaimScalar::I64(100))
    ));
    assert!(matches!(
        fact.scalar_claims.get(&11),
        Some(CwtClaimScalar::I64(200))
    ));
    assert!(matches!(
        fact.scalar_claims.get(&12),
        Some(CwtClaimScalar::I64(300))
    ));
    assert!(fact.iss.is_none());
}

// ---------------------------------------------------------------------------
// 10. CWT claims MAP with Bool value (encode_value_recursive Bool path)
// ---------------------------------------------------------------------------

#[test]
fn cwt_claims_map_with_bool_value_encode_recursive() {
    let cose_bytes = build_minimal_cose_sign1();
    let mut parsed = CoseSign1Message::parse(&cose_bytes).unwrap();

    // Insert CWT claims as a Map with a Bool value
    parsed.protected.insert(
        CoseHeaderLabel::Int(15),
        CoseHeaderValue::Map(vec![(
            CoseHeaderLabel::Int(100),
            CoseHeaderValue::Bool(true),
        )]),
    );

    let producer = Arc::new(CoseSign1MessageFactProducer::new());
    let engine = TrustFactEngine::new(vec![producer])
        .with_cose_sign1_bytes(Arc::from(cose_bytes.into_boxed_slice()))
        .with_cose_sign1_message(Arc::new(parsed));
    let subject = message_subject();
    let fact = extract_cwt_fact(&engine, &subject);

    assert!(matches!(
        fact.scalar_claims.get(&100),
        Some(CwtClaimScalar::Bool(true))
    ));
    assert!(fact.raw_claims.contains_key(&100));
}

// ---------------------------------------------------------------------------
// 11. CWT claims MAP with Null value (encode_value_recursive Null path)
// ---------------------------------------------------------------------------

#[test]
fn cwt_claims_map_with_null_value_encode_recursive() {
    let cose_bytes = build_minimal_cose_sign1();
    let mut parsed = CoseSign1Message::parse(&cose_bytes).unwrap();

    parsed.protected.insert(
        CoseHeaderLabel::Int(15),
        CoseHeaderValue::Map(vec![(CoseHeaderLabel::Int(300), CoseHeaderValue::Null)]),
    );

    let producer = Arc::new(CoseSign1MessageFactProducer::new());
    let engine = TrustFactEngine::new(vec![producer])
        .with_cose_sign1_bytes(Arc::from(cose_bytes.into_boxed_slice()))
        .with_cose_sign1_message(Arc::new(parsed));
    let subject = message_subject();
    let fact = extract_cwt_fact(&engine, &subject);

    assert!(!fact.scalar_claims.contains_key(&300));
    assert!(fact.raw_claims.contains_key(&300));
}

// ---------------------------------------------------------------------------
// 12. CWT claims MAP with Raw(bytes) value (encode_value_recursive Raw path)
// ---------------------------------------------------------------------------

#[test]
fn cwt_claims_map_with_raw_value_encode_recursive() {
    let cose_bytes = build_minimal_cose_sign1();
    let mut parsed = CoseSign1Message::parse(&cose_bytes).unwrap();

    // Encode a small CBOR integer as raw bytes
    let p = EverParseCborProvider;
    let mut raw_enc = p.encoder();
    raw_enc.encode_i64(42).unwrap();
    let raw_bytes = raw_enc.into_bytes();

    parsed.protected.insert(
        CoseHeaderLabel::Int(15),
        CoseHeaderValue::Map(vec![(
            CoseHeaderLabel::Int(400),
            CoseHeaderValue::Raw(raw_bytes.into()),
        )]),
    );

    let producer = Arc::new(CoseSign1MessageFactProducer::new());
    let engine = TrustFactEngine::new(vec![producer])
        .with_cose_sign1_bytes(Arc::from(cose_bytes.into_boxed_slice()))
        .with_cose_sign1_message(Arc::new(parsed));
    let subject = message_subject();
    let fact = extract_cwt_fact(&engine, &subject);

    // Raw variant is not extractable as a scalar string, i64, or bool
    assert!(!fact.scalar_claims.contains_key(&400));
    assert!(fact.raw_claims.contains_key(&400));
}

// ---------------------------------------------------------------------------
// 13. CWT claims MAP with Uint(n) where n <= i64::MAX (extract_i64 Uint path)
// ---------------------------------------------------------------------------

#[test]
fn cwt_claims_map_with_uint_value_extract_i64() {
    let cose_bytes = build_minimal_cose_sign1();
    let mut parsed = CoseSign1Message::parse(&cose_bytes).unwrap();

    parsed.protected.insert(
        CoseHeaderLabel::Int(15),
        CoseHeaderValue::Map(vec![(
            CoseHeaderLabel::Int(4),
            CoseHeaderValue::Uint(12345),
        )]),
    );

    let producer = Arc::new(CoseSign1MessageFactProducer::new());
    let engine = TrustFactEngine::new(vec![producer])
        .with_cose_sign1_bytes(Arc::from(cose_bytes.into_boxed_slice()))
        .with_cose_sign1_message(Arc::new(parsed));
    let subject = message_subject();
    let fact = extract_cwt_fact(&engine, &subject);

    assert_eq!(fact.exp, Some(12345));
    assert!(matches!(
        fact.scalar_claims.get(&4),
        Some(CwtClaimScalar::I64(12345))
    ));
}

// ---------------------------------------------------------------------------
// 14. CWT claims with non-Map/non-Raw value (e.g., Int(42) for label 15)
//     — tests the `_ => mark_error` path at line 193
// ---------------------------------------------------------------------------

#[test]
fn cwt_claims_not_map_not_raw_marks_error() {
    let cose_bytes = build_minimal_cose_sign1();
    let mut parsed = CoseSign1Message::parse(&cose_bytes).unwrap();

    // Set label 15 to a scalar Int — neither Map nor Raw
    parsed
        .protected
        .insert(CoseHeaderLabel::Int(15), CoseHeaderValue::Int(42));

    let producer = Arc::new(CoseSign1MessageFactProducer::new());
    let engine = TrustFactEngine::new(vec![producer])
        .with_cose_sign1_bytes(Arc::from(cose_bytes.into_boxed_slice()))
        .with_cose_sign1_message(Arc::new(parsed));
    let subject = message_subject();

    // CwtClaimsPresentFact should still be true
    let present = match engine
        .get_fact_set::<CwtClaimsPresentFact>(&subject)
        .unwrap()
    {
        TrustFactSet::Available(v) => v.into_iter().next().expect("one CwtClaimsPresentFact"),
        other => panic!("expected Available, got {other:?}"),
    };
    assert!(present.present);

    // CwtClaimsFact should be Error
    let claims = engine.get_fact_set::<CwtClaimsFact>(&subject).unwrap();
    match claims {
        TrustFactSet::Error { message } => {
            assert!(
                message.contains("CwtClaimsValueNotMap"),
                "unexpected error message: {message}"
            );
        }
        other => panic!("expected Error for CwtClaimsValueNotMap, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// Additional: CwtClaimsPresentFact is true when Raw CWT is present
// ---------------------------------------------------------------------------

#[test]
fn raw_cwt_claims_present_fact_is_true() {
    let cwt_raw = encode_cwt_raw(1, |enc| {
        enc.encode_i64(1).unwrap();
        enc.encode_tstr("issuer").unwrap();
    });

    let engine = engine_with_raw_cwt(cwt_raw);
    let subject = message_subject();

    let present = match engine
        .get_fact_set::<CwtClaimsPresentFact>(&subject)
        .unwrap()
    {
        TrustFactSet::Available(v) => v.into_iter().next().expect("one CwtClaimsPresentFact"),
        other => panic!("expected Available, got {other:?}"),
    };
    assert!(present.present);
}
