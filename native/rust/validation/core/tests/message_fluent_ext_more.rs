// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use cbor_primitives::{CborEncoder, CborProvider};
use cbor_primitives_everparse::EverParseCborProvider;
use cose_sign1_validation::fluent::{
    ContentTypeFact, CwtClaimsFact, CwtClaimsPresentFact, DetachedPayloadPresentFact,
    MessageScopeRulesExt as _,
};
use cose_sign1_validation_primitives::error::TrustError;
use cose_sign1_validation_primitives::evaluation_options::TrustEvaluationOptions;
use cose_sign1_validation_primitives::facts::{
    FactKey, TrustFactContext, TrustFactEngine, TrustFactProducer,
};
use cose_sign1_validation_primitives::fluent::TrustPlanBuilder;
use cose_sign1_validation_primitives::subject::TrustSubject;
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

struct MessageFactsProducer;

impl TrustFactProducer for MessageFactsProducer {
    fn name(&self) -> &'static str {
        "message_facts_producer"
    }

    fn produce(&self, ctx: &mut TrustFactContext<'_>) -> Result<(), TrustError> {
        if ctx.subject().kind != "Message" {
            for k in self.provides() {
                ctx.mark_produced(*k);
            }
            return Ok(());
        }

        ctx.observe(ContentTypeFact {
            content_type: "application/json".into(),
        })?;
        ctx.observe(DetachedPayloadPresentFact { present: false })?;
        ctx.observe(CwtClaimsPresentFact { present: true })?;

        let mut raw_claims = BTreeMap::new();
        raw_claims.insert(1, encode_cbor_text("issuer.example")); // iss (label 1)
        raw_claims.insert(6, encode_cbor_i64(123)); // iat (label 6)

        let mut raw_claims_text = BTreeMap::new();
        raw_claims_text.insert("custom".into(), encode_cbor_text("ok"));

        ctx.observe(CwtClaimsFact {
            scalar_claims: BTreeMap::new(),
            raw_claims,
            raw_claims_text,
            iss: Some("issuer.example".into()),
            sub: None,
            aud: None,
            exp: None,
            nbf: None,
            iat: Some(123),
        })?;

        for k in self.provides() {
            ctx.mark_produced(*k);
        }

        Ok(())
    }

    fn provides(&self) -> &'static [FactKey] {
        static PROVIDED: std::sync::OnceLock<Vec<FactKey>> = std::sync::OnceLock::new();
        PROVIDED
            .get_or_init(|| {
                vec![
                    FactKey::of::<ContentTypeFact>(),
                    FactKey::of::<DetachedPayloadPresentFact>(),
                    FactKey::of::<CwtClaimsPresentFact>(),
                    FactKey::of::<CwtClaimsFact>(),
                ]
            })
            .as_slice()
    }
}

#[test]
fn message_fact_fluent_extensions_build_and_evaluate() {
    let engine = TrustFactEngine::new(vec![Arc::new(MessageFactsProducer)]);
    let subject = TrustSubject::message(b"seed");

    // Build a plan using the message-fact extension methods.
    let plan = TrustPlanBuilder::new().for_message(|m| {
        m.require_content_type_eq("application/json")
            .and()
            .require_content_type_non_empty()
            .and()
            .require_detached_payload_absent()
            .and()
            .require_cwt_claims_present()
            .and()
            // numeric key form (exercises CwtClaimKey::from(i64))
            .require_cwt_claim(6i64, |r| {
                use cbor_primitives::CborDecoder;
                let provider = cbor_primitives_everparse::EverParseCborProvider;
                let mut d = provider.decoder(r.as_bytes());
                d.decode_i64().ok() == Some(123)
            })
            .and()
            // text key form (exercises CwtClaimKey::from(&str))
            .require_cwt_claim("custom", |r| {
                use cbor_primitives::CborDecoder;
                let provider = cbor_primitives_everparse::EverParseCborProvider;
                let mut d = provider.decoder(r.as_bytes());
                d.decode_tstr().ok().map(|s| s.to_string())
            } == Some("ok".to_string()))
    });

    let compiled = plan.compile();
    let decision = compiled
        .evaluate(&engine, &subject, &TrustEvaluationOptions::default())
        .expect("plan evaluation");

    assert!(decision.is_trusted);
}
