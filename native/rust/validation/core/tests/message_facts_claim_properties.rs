// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use cbor_primitives::{CborEncoder, CborProvider};
use cbor_primitives_everparse::EverParseCborProvider;
use cose_sign1_validation::fluent::{
    ContentTypeFact, CwtClaimScalar, CwtClaimsFact, CwtClaimsPresentFact,
    DetachedPayloadPresentFact,
};
use cose_sign1_validation_primitives::fact_properties::{FactProperties, FactValue};
use std::collections::BTreeMap;
use std::sync::Arc;

fn encode_cbor_i64(n: i64) -> Arc<[u8]> {
    let p = EverParseCborProvider;
    let mut enc = p.encoder();
    enc.encode_i64(n).unwrap();
    Arc::from(enc.into_bytes().into_boxed_slice())
}

fn encode_cbor_text(s: &str) -> Arc<[u8]> {
    let p = EverParseCborProvider;
    let mut enc = p.encoder();
    enc.encode_tstr(s).unwrap();
    Arc::from(enc.into_bytes().into_boxed_slice())
}

/// Exercise `CwtClaimsFact::get_property` with all standard claims set to `Some`.
#[test]
fn cwt_claims_get_property_all_some() {
    let fact = CwtClaimsFact {
        scalar_claims: BTreeMap::new(),
        raw_claims: BTreeMap::new(),
        raw_claims_text: BTreeMap::new(),
        iss: Some("my-issuer".to_string()),
        sub: Some("my-subject".to_string()),
        aud: Some("my-audience".to_string()),
        exp: Some(1_700_000_000),
        nbf: Some(1_600_000_000),
        iat: Some(1_650_000_000),
    };

    assert!(matches!(
        fact.get_property("iss"),
        Some(FactValue::Str(s)) if s.as_ref() == "my-issuer"
    ));
    assert!(matches!(
        fact.get_property("sub"),
        Some(FactValue::Str(s)) if s.as_ref() == "my-subject"
    ));
    assert!(matches!(
        fact.get_property("aud"),
        Some(FactValue::Str(s)) if s.as_ref() == "my-audience"
    ));
    assert_eq!(fact.get_property("exp"), Some(FactValue::I64(1_700_000_000)));
    assert_eq!(fact.get_property("nbf"), Some(FactValue::I64(1_600_000_000)));
    assert_eq!(fact.get_property("iat"), Some(FactValue::I64(1_650_000_000)));
}

/// Exercise `CwtClaimsFact::get_property` with all standard claims set to `None`.
#[test]
fn cwt_claims_get_property_all_none() {
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

    assert_eq!(fact.get_property("iss"), None);
    assert_eq!(fact.get_property("sub"), None);
    assert_eq!(fact.get_property("aud"), None);
    assert_eq!(fact.get_property("exp"), None);
    assert_eq!(fact.get_property("nbf"), None);
    assert_eq!(fact.get_property("iat"), None);
}

/// Exercise the `claim_` prefix path with all three scalar variants plus edge cases.
#[test]
fn cwt_claims_get_property_claim_prefix_all_variants() {
    let mut scalar_claims = BTreeMap::new();
    scalar_claims.insert(10, CwtClaimScalar::Str("text-value".to_string()));
    scalar_claims.insert(20, CwtClaimScalar::I64(42));
    scalar_claims.insert(30, CwtClaimScalar::Bool(false));

    let fact = CwtClaimsFact {
        scalar_claims,
        raw_claims: BTreeMap::new(),
        raw_claims_text: BTreeMap::new(),
        iss: None,
        sub: None,
        aud: None,
        exp: None,
        nbf: None,
        iat: None,
    };

    // Str variant via claim_ prefix
    assert!(matches!(
        fact.get_property("claim_10"),
        Some(FactValue::Str(s)) if s.as_ref() == "text-value"
    ));

    // I64 variant via claim_ prefix
    assert_eq!(fact.get_property("claim_20"), Some(FactValue::I64(42)));

    // Bool variant via claim_ prefix
    assert_eq!(fact.get_property("claim_30"), Some(FactValue::Bool(false)));

    // Valid numeric label that does not exist in scalar_claims
    assert_eq!(fact.get_property("claim_999"), None);

    // Non-numeric suffix after claim_ prefix
    assert_eq!(fact.get_property("claim_abc"), None);

    // Empty suffix after claim_ prefix
    assert_eq!(fact.get_property("claim_"), None);

    // Completely unknown property name
    assert_eq!(fact.get_property("unknown"), None);
}

/// `claim_value_i64` returns `None` for a missing label.
#[test]
fn cwt_claims_claim_value_i64_missing_key() {
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

    assert!(fact.claim_value_i64(999).is_none());
}

/// `claim_value_i64` returns `Some` for a present label and the bytes round-trip.
#[test]
fn cwt_claims_claim_value_i64_present_key() {
    let mut raw_claims = BTreeMap::new();
    raw_claims.insert(7, encode_cbor_i64(777));

    let fact = CwtClaimsFact {
        scalar_claims: BTreeMap::new(),
        raw_claims,
        raw_claims_text: BTreeMap::new(),
        iss: None,
        sub: None,
        aud: None,
        exp: None,
        nbf: None,
        iat: None,
    };

    let raw = fact.claim_value_i64(7).expect("label 7 should be present");
    use cbor_primitives::CborDecoder;
    let mut d = EverParseCborProvider.decoder(raw.as_bytes());
    assert_eq!(d.decode_i64().ok(), Some(777));
}

/// `claim_value_text` returns `None` for a missing key.
#[test]
fn cwt_claims_claim_value_text_missing_key() {
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

    assert!(fact.claim_value_text("no-such-key").is_none());
}

/// `claim_value_text` returns `Some` for a present key and the bytes round-trip.
#[test]
fn cwt_claims_claim_value_text_present_key() {
    let mut raw_claims_text = BTreeMap::new();
    raw_claims_text.insert("mykey".to_string(), encode_cbor_text("myval"));

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

    let raw = fact.claim_value_text("mykey").expect("key should be present");
    use cbor_primitives::CborDecoder;
    let mut d = EverParseCborProvider.decoder(raw.as_bytes());
    assert_eq!(
        d.decode_tstr().ok().map(|s| s.to_string()).as_deref(),
        Some("myval")
    );
}

/// `ContentTypeFact::get_property` returns the content type for the known property
/// and `None` for unknown names.
#[test]
fn content_type_fact_get_property() {
    let fact = ContentTypeFact {
        content_type: "application/json".to_string(),
    };

    assert!(matches!(
        fact.get_property("content_type"),
        Some(FactValue::Str(s)) if s.as_ref() == "application/json"
    ));
    assert_eq!(fact.get_property("unknown"), None);
}

/// `DetachedPayloadPresentFact::get_property` returns the correct bool for both
/// `true` and `false`, and `None` for unknown names.
#[test]
fn detached_payload_present_fact_get_property() {
    let present = DetachedPayloadPresentFact { present: true };
    assert_eq!(present.get_property("present"), Some(FactValue::Bool(true)));
    assert_eq!(present.get_property("other"), None);

    let absent = DetachedPayloadPresentFact { present: false };
    assert_eq!(absent.get_property("present"), Some(FactValue::Bool(false)));
}

/// `CwtClaimsPresentFact::get_property` returns the correct bool for both values.
#[test]
fn cwt_claims_present_fact_get_property() {
    let yes = CwtClaimsPresentFact { present: true };
    assert_eq!(yes.get_property("present"), Some(FactValue::Bool(true)));
    assert_eq!(yes.get_property("other"), None);

    let no = CwtClaimsPresentFact { present: false };
    assert_eq!(no.get_property("present"), Some(FactValue::Bool(false)));
}

/// Negative claim labels work with the `claim_` prefix (e.g. `claim_-1`).
#[test]
fn cwt_claims_get_property_negative_label() {
    let mut scalar_claims = BTreeMap::new();
    scalar_claims.insert(-1, CwtClaimScalar::I64(99));

    let fact = CwtClaimsFact {
        scalar_claims,
        raw_claims: BTreeMap::new(),
        raw_claims_text: BTreeMap::new(),
        iss: None,
        sub: None,
        aud: None,
        exp: None,
        nbf: None,
        iat: None,
    };

    assert_eq!(fact.get_property("claim_-1"), Some(FactValue::I64(99)));
}
