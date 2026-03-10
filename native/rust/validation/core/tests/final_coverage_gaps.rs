// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Coverage tests targeting specific uncovered lines in:
//! - `message_fact_producer.rs`: Undefined/Float in encode_value_recursive (330-331),
//!   text-keyed custom CWT claim fallthrough (451), get_header_int non-Int branch (618)
//! - `message_facts.rs`: require_cwt_claim missing claim returns false (417)
//! - `indirect_signature.rs`: header_i64 Uint branch (90),
//!   legacy content-type without +hash-* extension (296-299)

use cbor_primitives::{CborEncoder, CborProvider};
use cbor_primitives_everparse::EverParseCborProvider;
use cose_sign1_primitives::{CoseHeaderLabel, CoseHeaderValue, CoseSign1Message};
use cose_sign1_validation::fluent::*;
use cose_sign1_validation_test_utils::SimpleTrustPack;
use cose_sign1_validation_primitives::facts::{TrustFactEngine, TrustFactSet};
use cose_sign1_validation_primitives::subject::TrustSubject;
use sha2::Digest;
use std::sync::Arc;

// ---------------------------------------------------------------------------
// Shared helpers (same pattern as existing tests)
// ---------------------------------------------------------------------------

struct AlwaysTrueVerifier;

impl CryptoVerifier for AlwaysTrueVerifier {
    fn algorithm(&self) -> i64 {
        -7
    }
    
    fn verify(&self, _data: &[u8], _signature: &[u8]) -> Result<bool, CryptoError> {
        Ok(true)
    }
}

struct AlwaysTrueKeyResolver;

impl CoseKeyResolver for AlwaysTrueKeyResolver {
    fn resolve(
        &self,
        _message: &cose_sign1_validation_primitives::CoseSign1Message,
        _options: &CoseSign1ValidationOptions,
    ) -> CoseKeyResolutionResult {
        CoseKeyResolutionResult::success(Arc::new(AlwaysTrueVerifier))
    }
}

fn build_minimal_cose_sign1() -> Vec<u8> {
    let p = EverParseCborProvider;
    let mut enc = p.encoder();
    enc.encode_array(4).unwrap();
    let mut inner = p.encoder();
    inner.encode_map(0).unwrap();
    enc.encode_bstr(&inner.into_bytes()).unwrap();
    enc.encode_map(0).unwrap();
    enc.encode_bstr(b"test").unwrap();
    enc.encode_bstr(b"sig").unwrap();
    enc.into_bytes()
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

fn engine_with_injected_headers(
    headers: Vec<(CoseHeaderLabel, CoseHeaderValue)>,
) -> (TrustFactEngine, Vec<u8>) {
    let cose_bytes = build_minimal_cose_sign1();
    let mut parsed = CoseSign1Message::parse(&cose_bytes).unwrap();

    for (label, value) in headers {
        parsed.protected.headers_mut().insert(label, value);
    }

    let producer = Arc::new(CoseSign1MessageFactProducer::new());
    let engine = TrustFactEngine::new(vec![producer])
        .with_cose_sign1_bytes(Arc::from(cose_bytes.clone().into_boxed_slice()))
        .with_cose_sign1_message(Arc::new(parsed));

    (engine, cose_bytes)
}

fn build_validator(
    detached_payload: Option<Vec<u8>>,
) -> CoseSign1Validator {
    let trust_packs: Vec<Arc<dyn CoseSign1TrustPack>> = vec![Arc::new(
        SimpleTrustPack::no_facts("always_true_key")
            .with_cose_key_resolver(Arc::new(AlwaysTrueKeyResolver)),
    )];

    let bundled = TrustPlanBuilder::new(trust_packs)
        .for_message(|m| m.allow_all())
        .compile()
        .unwrap();

    CoseSign1Validator::new(bundled).with_options(|o| {
        if let Some(p) = detached_payload {
            o.detached_payload = Some(Payload::Bytes(p));
        }
    })
}

fn build_protected_header(
    map_len: usize,
    entries: impl FnOnce(&mut cbor_primitives_everparse::EverParseEncoder),
) -> Vec<u8> {
    let p = EverParseCborProvider;
    let mut enc = p.encoder();
    enc.encode_map(map_len).unwrap();
    entries(&mut enc);
    enc.into_bytes()
}

fn build_cose_sign1(protected: &[u8], payload: &[u8]) -> Vec<u8> {
    let p = EverParseCborProvider;
    let mut enc = p.encoder();
    enc.encode_array(4).unwrap();
    enc.encode_bstr(protected).unwrap();
    enc.encode_map(0).unwrap();
    enc.encode_bstr(payload).unwrap();
    enc.encode_bstr(b"sig").unwrap();
    enc.into_bytes()
}

// ---------------------------------------------------------------------------
// Item 3: encode_value_recursive Undefined and Float branches (lines 330-331)
// ---------------------------------------------------------------------------

#[test]
fn cwt_claims_map_with_undefined_value_encode_recursive() {
    let (engine, _) = engine_with_injected_headers(vec![(
        CoseHeaderLabel::Int(15),
        CoseHeaderValue::Map(vec![(
            CoseHeaderLabel::Int(200),
            CoseHeaderValue::Undefined,
        )]),
    )]);

    let subject = message_subject();
    let fact = extract_cwt_fact(&engine, &subject);

    // Undefined is not extractable as a scalar
    assert!(!fact.scalar_claims.contains_key(&200));
    // But it should be present in raw_claims
    assert!(fact.raw_claims.contains_key(&200));
}

#[test]
fn cwt_claims_map_with_float_value_encode_recursive() {
    let (engine, _) = engine_with_injected_headers(vec![(
        CoseHeaderLabel::Int(15),
        CoseHeaderValue::Map(vec![(
            CoseHeaderLabel::Int(201),
            CoseHeaderValue::Float(3.14),
        )]),
    )]);

    let subject = message_subject();
    let fact = extract_cwt_fact(&engine, &subject);

    // Float encoding is not supported by EverParseEncoder, so encode_value_to_bytes
    // returns None and the key is NOT inserted into raw_claims.
    // The important thing is that line 331 (encode_f64 branch) was executed.
    assert!(!fact.scalar_claims.contains_key(&201));
    assert!(!fact.raw_claims.contains_key(&201));
}

// ---------------------------------------------------------------------------
// Item 4: text-keyed custom claim in Raw CWT (line 451)
//   Text key that doesn't match iss/sub/aud/exp/nbf/iat falls through
// ---------------------------------------------------------------------------

#[test]
fn raw_cwt_text_keyed_custom_claim_falls_through() {
    let p = EverParseCborProvider;
    let mut enc = p.encoder();
    enc.encode_map(2).unwrap();
    enc.encode_tstr("custom_claim").unwrap();
    enc.encode_tstr("custom_value").unwrap();
    enc.encode_tstr("another_key").unwrap();
    enc.encode_i64(42).unwrap();
    let cwt_raw = enc.into_bytes();

    let cose_bytes = build_minimal_cose_sign1();
    let mut parsed = CoseSign1Message::parse(&cose_bytes).unwrap();
    parsed.protected.headers_mut().insert(
        CoseHeaderLabel::Int(15),
        CoseHeaderValue::Raw(cwt_raw),
    );

    let producer = Arc::new(CoseSign1MessageFactProducer::new());
    let engine = TrustFactEngine::new(vec![producer])
        .with_cose_sign1_bytes(Arc::from(cose_bytes.into_boxed_slice()))
        .with_cose_sign1_message(Arc::new(parsed));

    let subject = message_subject();
    let fact = extract_cwt_fact(&engine, &subject);

    // Well-known fields should be None
    assert!(fact.iss.is_none());
    assert!(fact.sub.is_none());
    assert!(fact.aud.is_none());
    assert!(fact.exp.is_none());
    assert!(fact.nbf.is_none());
    assert!(fact.iat.is_none());

    // Custom text keys should be in raw_claims_text
    assert!(fact.raw_claims_text.contains_key("custom_claim"));
    assert!(fact.raw_claims_text.contains_key("another_key"));
}

// ---------------------------------------------------------------------------
// Item 5: get_header_int non-Int value at content_type label 3 (line 618)
// ---------------------------------------------------------------------------

#[test]
fn get_header_int_returns_none_for_text_value_at_content_type() {
    let (engine, _) = engine_with_injected_headers(vec![
        (
            CoseHeaderLabel::Int(3),
            CoseHeaderValue::Text("hello".to_string()),
        ),
    ]);

    let subject = message_subject();

    // ContentTypeFact should still be produced (from get_header_text path)
    let ct = match engine.get_fact_set::<ContentTypeFact>(&subject).unwrap() {
        TrustFactSet::Available(v) => v.into_iter().next(),
        _ => None,
    };

    // The text value at label 3 is read as content_type text,
    // but get_header_int for label 3 returns None (line 618).
    // ContentTypeFact should have the text value.
    assert!(ct.is_some());
}

// ---------------------------------------------------------------------------
// Item 6: require_cwt_claim with missing claim returns false (line 417)
// ---------------------------------------------------------------------------

#[test]
fn require_cwt_claim_returns_false_for_missing_claim() {
    // Build a message with CWT claims that does NOT contain claim 999.
    let (_engine, cose_bytes) = engine_with_injected_headers(vec![(
        CoseHeaderLabel::Int(15),
        CoseHeaderValue::Map(vec![(
            CoseHeaderLabel::Int(1),
            CoseHeaderValue::Text("issuer".to_string()),
        )]),
    )]);

    // Build a trust plan requiring claim 999 (which doesn't exist).
    let trust_packs: Vec<Arc<dyn CoseSign1TrustPack>> = vec![Arc::new(
        SimpleTrustPack::no_facts("always_true_key")
            .with_cose_key_resolver(Arc::new(AlwaysTrueKeyResolver)),
    )];

    let bundled = TrustPlanBuilder::new(trust_packs)
        .for_message(|m| m.require_cwt_claim(999i64, |_| true))
        .compile()
        .unwrap();

    let validator = CoseSign1Validator::new(bundled);

    let result = validator
        .validate_bytes(
            EverParseCborProvider,
            Arc::from(cose_bytes.into_boxed_slice()),
        )
        .unwrap();

    // The claim doesn't exist, so require_cwt_claim's closure returns false → denied
    assert!(!result.overall.is_valid());
}

// ---------------------------------------------------------------------------
// Item 7: header_i64 Uint branch (line 90) via CoseHashEnvelope detection
//   Put Uint value at label 258 (COSE_HASH_ENVELOPE_PAYLOAD_HASH_ALG)
// ---------------------------------------------------------------------------

#[test]
fn header_i64_uint_branch_via_cose_hash_envelope() {
    let artifact = Arc::<[u8]>::from(b"payload data".to_vec().into_boxed_slice());
    let expected_hash = sha2::Sha256::digest(artifact.as_ref()).to_vec();

    // Build protected header with:
    // - alg = -7 (label 1)
    // - COSE_HASH_ENVELOPE_PAYLOAD_HASH_ALG (label 258) = Uint(-16 as sha256 id)
    //   We use -16 for sha256 in COSE Hash Envelope
    let cose_bytes = build_minimal_cose_sign1();
    let mut parsed = CoseSign1Message::parse(&cose_bytes).unwrap();

    parsed.protected.headers_mut().insert(
        CoseHeaderLabel::Int(1),
        CoseHeaderValue::Int(-7),
    );
    // Use Uint variant to trigger the Uint branch of header_i64.
    // SHA-256 alg id in negative form won't fit as Uint; use a dummy value
    // that represents a valid hash alg. Actually, header_i64 just returns
    // the i64 conversion. Let's set it so detect_indirect_signature_kind
    // returns CoseHashEnvelope. We need protected.get(&258).is_some() => true.
    // Then header_i64(protected, 258) hits the Uint branch and returns Some(alg_raw).
    // alg_raw is then matched against known hash alg IDs.
    // SHA-256 negative COSE label = -16. But Uint can't represent negative.
    // We can use a Uint that doesn't match any known alg, to test the Uint branch
    // is exercised even if the alg lookup fails.
    parsed.protected.headers_mut().insert(
        CoseHeaderLabel::Int(258),
        CoseHeaderValue::Uint(42u64),
    );
    parsed.payload = Some(expected_hash.into());

    let producer = Arc::new(CoseSign1MessageFactProducer::new());
    let engine = TrustFactEngine::new(vec![producer])
        .with_cose_sign1_bytes(Arc::from(cose_bytes.into_boxed_slice()))
        .with_cose_sign1_message(Arc::new(parsed));

    // Trigger fact production which runs the indirect signature validator
    let subject = message_subject();
    let _ = engine.get_fact_set::<ContentTypeFact>(&subject);
}

#[test]
fn header_i64_uint_branch_via_full_validation() {
    let artifact = b"payload".to_vec();
    let expected_hash = sha2::Sha256::digest(&artifact).to_vec();

    // Protected header: alg=-7, label 258 = Uint(42) to trigger Uint branch of header_i64
    let hdr = build_protected_header(2, |enc| {
        enc.encode_i64(1).unwrap();
        enc.encode_i64(-7).unwrap();
        // Label 258 as Uint (not Int) to exercise header_i64 Uint branch
        enc.encode_i64(258).unwrap();
        // Encode a CBOR uint value: major type 0, value 42
        enc.encode_u64(42).unwrap();
    });

    let cose = build_cose_sign1(&hdr, &expected_hash);
    let v = build_validator(Some(artifact));
    let result = v
        .validate_bytes(EverParseCborProvider, Arc::from(cose.into_boxed_slice()))
        .unwrap();

    // The Uint(42) doesn't map to a known hash algorithm, so validation should fail
    // at the post-signature level, but the header_i64 Uint path is exercised.
    assert!(result.post_signature_policy.is_failure() || result.overall.is_failure());
}

// ---------------------------------------------------------------------------
// Item 8: Legacy content-type without +hash-* extension (lines 296-299)
//   Need HASH_LEGACY.is_match(ct) => true but HASH_LEGACY.captures(ct) => None
//   HASH_LEGACY = (?i)\+hash-([\w_]+)
//   is_match returns true if there's a +hash- substring anywhere
//   captures returns None if the capture group ([\w_]+) doesn't match
//   Actually, if is_match returns true then captures will always have a match.
//   So the only way to reach lines 296-299 is if content_type is Some after
//   detect_indirect_signature_kind returns LegacyHashExtension, but then
//   HASH_LEGACY.captures fails on the full string. But detect already checks
//   HASH_LEGACY.is_match... So this path can only be hit if content_type changes
//   between detect and the match arm. Actually, in the code:
//     let ct = content_type.unwrap_or_default();
//   So if content_type was None, ct="" and captures returns None.
//   But detect_indirect_signature_kind returns None if content_type is None
//   (because of `let ct = content_type?;`).
//
//   Wait: detect gets `content_type: Option<&str>` from the same variable.
//   So if detect returned LegacyHashExtension, content_type was Some(ct) and
//   HASH_LEGACY.is_match(ct) was true. Then in the match arm, we do
//   `let ct = content_type.unwrap_or_default()` and `HASH_LEGACY.captures(&ct)`.
//   Since is_match was true, captures will also match. So lines 296-299 ARE
//   unreachable unless the regex has different behavior for captures vs is_match.
//
//   Actually wait, the regex `(?i)\+hash-([\w_]+)` captures group 1. The code does:
//     .and_then(|c| c.get(1).map(|m| m.as_str().to_string()))
//   If the regex matches but group 1 is empty? No, [\w_]+ requires at least one char.
//   So group 1 always exists if there's a match. This means lines 296-299 are
//   unreachable. Skip.
// ---------------------------------------------------------------------------

// NOTE: Item 8 (lines 296-299) is unreachable dead code — the legacy hash
// regex path can only be entered if HASH_LEGACY.is_match() returned true in
// detect_indirect_signature_kind, which means HASH_LEGACY.captures() will also
// succeed. No test can cover this path.

// ---------------------------------------------------------------------------
// Additional: require_cwt_claim with text key for missing claim
// ---------------------------------------------------------------------------

#[test]
fn require_cwt_claim_text_key_missing_returns_false() {
    let (_, cose_bytes) = engine_with_injected_headers(vec![(
        CoseHeaderLabel::Int(15),
        CoseHeaderValue::Map(vec![(
            CoseHeaderLabel::Int(1),
            CoseHeaderValue::Text("issuer".to_string()),
        )]),
    )]);

    let trust_packs: Vec<Arc<dyn CoseSign1TrustPack>> = vec![Arc::new(
        SimpleTrustPack::no_facts("always_true_key")
            .with_cose_key_resolver(Arc::new(AlwaysTrueKeyResolver)),
    )];

    // Require text-keyed claim "nonexistent" which doesn't exist
    let bundled = TrustPlanBuilder::new(trust_packs)
        .for_message(|m| m.require_cwt_claim("nonexistent", |_| true))
        .compile()
        .unwrap();

    let validator = CoseSign1Validator::new(bundled);
    let result = validator
        .validate_bytes(
            EverParseCborProvider,
            Arc::from(cose_bytes.into_boxed_slice()),
        )
        .unwrap();

    assert!(!result.overall.is_valid());
}
