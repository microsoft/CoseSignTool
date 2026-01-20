// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use cose_sign1_validation::fluent::{CborValueReader, CwtClaimScalar, CwtClaimsFact};
use cose_sign1_validation_trust::fact_properties::{FactProperties, FactValue};
use std::collections::BTreeMap;
use std::sync::Arc;
use tinycbor::{Encode, Encoder};

fn encode_cbor_i64(n: i64) -> Arc<[u8]> {
    let mut buf = vec![0u8; 32];
    let buf_len = buf.len();
    let mut enc = Encoder(buf.as_mut_slice());
    n.encode(&mut enc).unwrap();
    let used = buf_len - enc.0.len();
    buf.truncate(used);
    Arc::from(buf.into_boxed_slice())
}

fn encode_cbor_text(s: &str) -> Arc<[u8]> {
    let mut buf = vec![0u8; 64];
    let buf_len = buf.len();
    let mut enc = Encoder(buf.as_mut_slice());
    s.encode(&mut enc).unwrap();
    let used = buf_len - enc.0.len();
    buf.truncate(used);
    Arc::from(buf.into_boxed_slice())
}

#[test]
fn cbor_value_reader_decode_is_best_effort() {
    let bytes = encode_cbor_i64(123);
    let r = CborValueReader::new(bytes.as_ref());
    assert_eq!(r.decode::<i64>(), Some(123));
}

#[test]
fn cwt_claims_fact_property_accessors_cover_standard_and_scalar_claims() {
    let mut scalar_claims = BTreeMap::new();
    scalar_claims.insert(42, CwtClaimScalar::I64(7));
    scalar_claims.insert(99, CwtClaimScalar::Bool(true));
    scalar_claims.insert(100, CwtClaimScalar::Str("hello".to_string()));

    let mut raw_claims = BTreeMap::new();
    raw_claims.insert(6, encode_cbor_i64(555));

    let mut raw_claims_text = BTreeMap::new();
    raw_claims_text.insert("custom".to_string(), encode_cbor_text("v"));

    let fact = CwtClaimsFact {
        scalar_claims,
        raw_claims,
        raw_claims_text,
        iss: Some("issuer".to_string()),
        sub: None,
        aud: Some("aud".to_string()),
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

    assert_eq!(fact.claim_value_i64(6).unwrap().decode::<i64>(), Some(555));
    assert_eq!(
        fact.claim_value_text("custom")
            .unwrap()
            .decode::<String>()
            .as_deref(),
        Some("v")
    );
    assert_eq!(fact.claim_value_text("missing"), None);
}
