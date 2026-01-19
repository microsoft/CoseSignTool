// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use cose_sign1_validation_trust::facts::{
    FactKey, TrustFactContext, TrustFactEngine, TrustFactProducer,
};
use cose_sign1_validation_trust::policy::TrustPolicyBuilder;
use cose_sign1_validation_trust::rules::FnRule;
use cose_sign1_validation_trust::subject::TrustSubject;
use cose_sign1_validation_trust::TrustDecision;
use once_cell::sync::Lazy;
use std::sync::Arc;

#[derive(Debug)]
struct ExampleFact {
    pub value: String,
}

struct ExampleProducer;

impl TrustFactProducer for ExampleProducer {
    fn name(&self) -> &'static str {
        "ExampleProducer"
    }

    fn produce(
        &self,
        ctx: &mut TrustFactContext<'_>,
    ) -> Result<(), cose_sign1_validation_trust::error::TrustError> {
        // Only produce this fact when it is requested.
        if ctx.requested_fact().type_id == FactKey::of::<ExampleFact>().type_id {
            ctx.observe(ExampleFact {
                value: "hello".to_string(),
            })?;
        }

        for k in self.provides() {
            ctx.mark_produced(*k);
        }
        Ok(())
    }

    fn provides(&self) -> &'static [FactKey] {
        static PROVIDED: Lazy<[FactKey; 1]> = Lazy::new(|| [FactKey::of::<ExampleFact>()]);
        &*PROVIDED
    }
}

fn main() {
    let policy = TrustPolicyBuilder::new()
        .require_fact(FactKey::of::<ExampleFact>())
        .add_trust_source(Arc::new(FnRule::new(
            "trust_if_example_fact_present",
            |engine: &TrustFactEngine, subject: &TrustSubject| {
                let facts = engine.get_facts::<ExampleFact>(subject)?;
                if facts.is_empty() {
                    Ok(TrustDecision::denied(vec![
                        "Missing ExampleFact".to_string()
                    ]))
                } else {
                    let _ = facts.iter().map(|f| f.value.len()).sum::<usize>();
                    Ok(TrustDecision::trusted_reason("ExampleFactPresent"))
                }
            },
        )))
        .build();

    let plan = policy.compile();

    let engine = TrustFactEngine::new(vec![Arc::new(ExampleProducer)]);
    let subject = TrustSubject::message(b"seed");

    let decision = plan
        .evaluate(&engine, &subject, &Default::default())
        .expect("trust evaluation failed");

    println!("decision: {:?}", decision);
}
