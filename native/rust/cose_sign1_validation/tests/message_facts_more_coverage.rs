// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use cose_sign1_validation::fluent::{
    ContentTypeFact, ContentTypeWhereExt, CounterSignatureEnvelopeIntegrityFact, CwtClaimScalar,
    CwtClaimsFact, CwtClaimsPresentFact, CwtClaimsPresentWhereExt, CwtClaimsWhereExt,
    DetachedPayloadPresentFact, DetachedPayloadPresentWhereExt, MessageScopeRulesExt,
    TrustPlanBuilder,
};
use cose_sign1_validation_trust::fact_properties::{FactProperties, FactValue};
use std::collections::BTreeMap;
use std::sync::Arc;

#[test]
fn message_facts_fluent_helpers_build_and_compile() {
    // This intentionally does not evaluate the plan; it just ensures we execute the fluent
    // helper methods and the typed conversions they rely on.
    let _bundled = TrustPlanBuilder::new(vec![])
        .for_message(|m| {
            m.require::<DetachedPayloadPresentFact>(|w| w.require_detached_payload_present())
                .and()
                .require::<DetachedPayloadPresentFact>(|w| w.require_detached_payload_absent())
                .and()
                .require::<ContentTypeFact>(|w| w.content_type_non_empty())
                .and()
                .require::<ContentTypeFact>(|w| w.content_type_eq("application/example"))
                .and()
                .require::<CwtClaimsPresentFact>(|w| w.require_cwt_claims_present())
                .and()
                .require::<CwtClaimsPresentFact>(|w| w.require_cwt_claims_absent())
                .and()
                .require::<CwtClaimsFact>(|w| {
                    w.iss_eq("issuer").sub_eq("subject").aud_eq("audience")
                })
                .and()
                // Exercise both numeric and text keys.
                .require_cwt_claim(6i64, |r| r.decode::<i64>().is_some())
                .and()
                .require_cwt_claim("custom", |r| r.decode::<String>().is_some())
        })
        .compile()
        .expect("message-only plan should compile");
}

#[test]
fn message_fact_properties_cover_expected_branches() {
    let detached = DetachedPayloadPresentFact { present: true };
    assert_eq!(detached.get_property("present"), Some(FactValue::Bool(true)));
    assert_eq!(detached.get_property("nope"), None);

    let ct = ContentTypeFact {
        content_type: "text/plain".to_string(),
    };
    assert!(matches!(
        ct.get_property("content_type"),
        Some(FactValue::Str(s)) if s.as_ref() == "text/plain"
    ));
    assert_eq!(ct.get_property("nope"), None);

    let cwt_present = CwtClaimsPresentFact { present: false };
    assert_eq!(
        cwt_present.get_property("present"),
        Some(FactValue::Bool(false))
    );
    assert_eq!(cwt_present.get_property("nope"), None);

    let mut scalar_claims = BTreeMap::new();
    scalar_claims.insert(42, CwtClaimScalar::I64(7));

    let fact = CwtClaimsFact {
        scalar_claims,
        raw_claims: BTreeMap::new(),
        raw_claims_text: BTreeMap::new(),
        iss: Some("issuer".to_string()),
        sub: None,
        aud: None,
        exp: None,
        nbf: None,
        iat: None,
    };

    assert!(matches!(
        fact.get_property("iss"),
        Some(FactValue::Str(s)) if s.as_ref() == "issuer"
    ));
    assert_eq!(fact.get_property("sub"), None);
    assert_eq!(fact.get_property("claim_42"), Some(FactValue::I64(7)));
    assert_eq!(fact.get_property("claim_not_an_int"), None);

    let integrity = CounterSignatureEnvelopeIntegrityFact {
        sig_structure_intact: true,
        details: Some("x".to_string()),
    };
    assert_eq!(
        integrity.get_property("sig_structure_intact"),
        Some(FactValue::Bool(true))
    );
    assert_eq!(integrity.get_property("nope"), None);

    // Touch Arc usage so the import isn't dead and matches the crate's typical fact storage.
    let _ = Arc::new(fact);
}
