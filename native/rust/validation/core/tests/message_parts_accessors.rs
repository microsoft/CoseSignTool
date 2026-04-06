// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Tests for `CoseSign1MessagePartsFact` accessor methods and
//! `CwtClaimsFact::claim_value_text`, covering lines that are otherwise DA:x,0.

use cbor_primitives::{CborEncoder, CborProvider};
use cbor_primitives_everparse::EverParseCborProvider;
use cose_sign1_primitives::CoseSign1Message;
use cose_sign1_validation::fluent::{CoseSign1MessagePartsFact, CwtClaimsFact};
use std::collections::BTreeMap;
use std::sync::Arc;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Build a minimal COSE_Sign1 array with a single protected-header entry
/// (alg = -7), an empty unprotected map, the given payload, and a dummy
/// signature.
fn build_cose_bytes(payload: Option<&[u8]>) -> Vec<u8> {
    let p = EverParseCborProvider;

    // protected header: { 1: -7 }
    let mut phdr = p.encoder();
    phdr.encode_map(1).unwrap();
    phdr.encode_i64(1).unwrap();
    phdr.encode_i64(-7).unwrap();
    let phdr_bytes = phdr.into_bytes();

    let mut enc = p.encoder();
    enc.encode_array(4).unwrap();
    enc.encode_bstr(&phdr_bytes).unwrap();
    enc.encode_map(0).unwrap(); // unprotected (empty)
    match payload {
        Some(pl) => enc.encode_bstr(pl).unwrap(),
        None => enc.encode_null().unwrap(),
    }
    enc.encode_bstr(b"sig").unwrap();
    enc.into_bytes()
}

fn parse_message(cose_bytes: &[u8]) -> CoseSign1Message {
    CoseSign1Message::parse(cose_bytes).expect("parse")
}

// ---------------------------------------------------------------------------
// CoseSign1MessagePartsFact — embedded payload
// ---------------------------------------------------------------------------

#[test]
fn accessors_with_embedded_payload() {
    let payload = b"hello world";
    let cose_bytes = build_cose_bytes(Some(payload));
    let msg = parse_message(&cose_bytes);
    let fact = CoseSign1MessagePartsFact::new(Arc::new(msg));

    // protected_header_bytes: should be non-empty CBOR bytes
    let phdr_bytes = fact.protected_header_bytes();
    assert!(
        !phdr_bytes.is_empty(),
        "protected header bytes must not be empty"
    );

    // protected_headers: should contain label 1 (alg)
    let phdr_map = fact.protected_headers();
    assert!(
        phdr_map
            .get(&cose_sign1_primitives::CoseHeaderLabel::Int(1))
            .is_some(),
        "protected headers must contain alg label (1)"
    );

    // unprotected: should be empty
    let unprot = fact.unprotected();
    assert!(unprot.is_empty(), "unprotected headers should be empty");

    // payload: should match what we embedded
    let pl = fact.payload();
    assert_eq!(pl, Some(payload.as_slice()));

    // signature: should be b"sig"
    assert_eq!(fact.signature(), b"sig");

    // message: should round-trip through the accessor
    let msg_ref = fact.message();
    assert_eq!(msg_ref.signature(), b"sig");

    // message_arc: should return a cloned Arc
    let msg_arc = fact.message_arc();
    assert_eq!(msg_arc.signature(), b"sig");
    assert_eq!(msg_arc.payload().as_deref(), Some(payload.as_slice()));
}

// ---------------------------------------------------------------------------
// CoseSign1MessagePartsFact — detached (null) payload
// ---------------------------------------------------------------------------

#[test]
fn accessors_with_detached_payload() {
    let cose_bytes = build_cose_bytes(None);
    let msg = parse_message(&cose_bytes);
    let fact = CoseSign1MessagePartsFact::new(Arc::new(msg));

    // payload must be None for a detached message
    assert!(fact.payload().is_none(), "detached payload must be None");

    // The other accessors should still work
    assert!(!fact.protected_header_bytes().is_empty());
    assert!(!fact.protected_headers().is_empty());
    assert!(fact.unprotected().is_empty());
    assert_eq!(fact.signature(), b"sig");
    assert_eq!(fact.message().signature(), b"sig");
    assert!(fact.message_arc().payload().is_none());
}

// ---------------------------------------------------------------------------
// CwtClaimsFact::claim_value_text — present and missing keys
// ---------------------------------------------------------------------------

#[test]
fn claim_value_text_returns_some_for_existing_key() {
    let p = EverParseCborProvider;
    let mut enc = p.encoder();
    enc.encode_i64(42).unwrap();
    let raw_bytes: Arc<[u8]> = Arc::from(enc.into_bytes().into_boxed_slice());

    let mut raw_claims_text = BTreeMap::new();
    raw_claims_text.insert("my_claim".into(), raw_bytes);

    let fact = CwtClaimsFact {
        scalar_claims: BTreeMap::new(),
        raw_claims: BTreeMap::new(),
        raw_claims_text,
        iss: None,
        sub: None,
        aud: None,
        exp: None,
        nbf: None,
        iat: None,
    };

    let result = fact.claim_value_text("my_claim");
    assert!(
        result.is_some(),
        "claim_value_text should return Some for an existing key"
    );
}

#[test]
fn claim_value_text_returns_none_for_missing_key() {
    let fact = CwtClaimsFact {
        scalar_claims: BTreeMap::new(),
        raw_claims: BTreeMap::new(),
        raw_claims_text: BTreeMap::new(),
        iss: None,
        sub: None,
        aud: None,
        exp: None,
        nbf: None,
        iat: None,
    };

    let result = fact.claim_value_text("nonexistent");
    assert!(
        result.is_none(),
        "claim_value_text should return None for a missing key"
    );
}
