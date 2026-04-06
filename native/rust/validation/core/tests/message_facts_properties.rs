// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use cbor_primitives::{CborEncoder, CborProvider};
use cbor_primitives_everparse::EverParseCborProvider;
use cose_sign1_validation::fluent::{CwtClaimScalar, CwtClaimsFact, RawCbor};
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

#[test]
fn cbor_value_reader_decode_is_best_effort() {
    let bytes = encode_cbor_i64(123);
    let r = RawCbor::new(bytes.as_ref());

    use cbor_primitives::{CborDecoder, CborProvider};
    let provider = cbor_primitives_everparse::EverParseCborProvider;
    let mut d = provider.decoder(r.as_bytes());
    assert_eq!(d.decode_i64().ok(), Some(123));
}

#[test]
fn cwt_claims_fact_property_accessors_cover_standard_and_scalar_claims() {
    let mut scalar_claims = BTreeMap::new();
    scalar_claims.insert(42, CwtClaimScalar::I64(7));
    scalar_claims.insert(99, CwtClaimScalar::Bool(true));
    scalar_claims.insert(100, CwtClaimScalar::Str("hello".into()));

    let mut raw_claims = BTreeMap::new();
    raw_claims.insert(6, encode_cbor_i64(555));

    let mut raw_claims_text = BTreeMap::new();
    raw_claims_text.insert("custom".into(), encode_cbor_text("v"));

    let fact = CwtClaimsFact {
        scalar_claims,
        raw_claims,
        raw_claims_text,
        iss: Some("issuer".into()),
        sub: None,
        aud: Some("aud".into()),
        exp: Some(1),
        nbf: None,
        iat: Some(2),
    };

    assert!(matches!(
        fact.get_property("iss"),
        Some(FactValue::Str(s)) if s.as_ref() == "issuer"
    ));
    assert_eq!(fact.get_property("sub"), None);
    assert!(matches!(
        fact.get_property("aud"),
        Some(FactValue::Str(s)) if s.as_ref() == "aud"
    ));
    assert_eq!(fact.get_property("exp"), Some(FactValue::I64(1)));
    assert_eq!(fact.get_property("nbf"), None);
    assert_eq!(fact.get_property("iat"), Some(FactValue::I64(2)));

    assert_eq!(fact.get_property("claim_42"), Some(FactValue::I64(7)));
    assert_eq!(fact.get_property("claim_99"), Some(FactValue::Bool(true)));
    assert!(matches!(
        fact.get_property("claim_100"),
        Some(FactValue::Str(s)) if s.as_ref() == "hello"
    ));

    assert_eq!(fact.get_property("claim_not_an_int"), None);
    assert_eq!(fact.get_property("nope"), None);

    use cbor_primitives::{CborDecoder, CborProvider};
    let provider = cbor_primitives_everparse::EverParseCborProvider;

    let mut d1 = provider.decoder(fact.claim_value_i64(6).unwrap().as_bytes());
    assert_eq!(d1.decode_i64().ok(), Some(555));

    let mut d2 = provider.decoder(fact.claim_value_text("custom").unwrap().as_bytes());
    assert_eq!(
        d2.decode_tstr().ok().map(|s| s.to_string()).as_deref(),
        Some("v")
    );

    assert_eq!(fact.claim_value_text("missing"), None);
}
