// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use cose_sign1_validation::fluent::{
    CoseSign1TrustPack, CoseSign1Validator, CounterSignatureSigningKeySubjectFact,
    CounterSignatureSubjectFact, OnEmptyBehavior, TrustPlanBuilder,
};
use cose_sign1_validation_trust::error::TrustError;
use cose_sign1_validation_trust::fact_properties::{FactProperties, FactValue};
use cose_sign1_validation_trust::facts::{FactKey, TrustFactContext, TrustFactEngine, TrustFactProducer};
use cose_sign1_validation_trust::fluent::HasTrustSubject;
use cose_sign1_validation_trust::field::Field;
use cose_sign1_validation_trust::subject::TrustSubject;
use std::sync::Arc;

#[derive(Debug, Clone)]
struct MarkerFact {
    ok: bool,
}

impl FactProperties for MarkerFact {
    fn get_property<'a>(&'a self, name: &str) -> Option<FactValue<'a>> {
        match name {
            "ok" => Some(FactValue::Bool(self.ok)),
            _ => None,
        }
    }
}

#[derive(Clone)]
struct MarkerProducer;

impl TrustFactProducer for MarkerProducer {
    fn name(&self) -> &'static str {
        "marker_producer"
    }

    fn provides(&self) -> &'static [FactKey] {
        static ONCE: std::sync::OnceLock<Vec<FactKey>> = std::sync::OnceLock::new();
        ONCE.get_or_init(|| {
            vec![
                FactKey::of::<CounterSignatureSubjectFact>(),
                FactKey::of::<CounterSignatureSigningKeySubjectFact>(),
                FactKey::of::<MarkerFact>(),
            ]
        })
        .as_slice()
    }

    fn produce(&self, ctx: &mut TrustFactContext<'_>) -> Result<(), TrustError> {
        let requested = ctx.requested_fact();

        if requested == FactKey::of::<CounterSignatureSubjectFact>() {
            if ctx.subject().kind == "Message" {
                let cs = TrustSubject::counter_signature(ctx.subject(), b"cs1");
                ctx.observe(CounterSignatureSubjectFact {
                    subject: cs,
                    is_protected_header: false,
                })?;
            }
            ctx.mark_produced(FactKey::of::<CounterSignatureSubjectFact>());
            return Ok(());
        }

        if requested == FactKey::of::<CounterSignatureSigningKeySubjectFact>() {
            if ctx.subject().kind == "Message" {
                let cs = TrustSubject::counter_signature(ctx.subject(), b"cs1");
                let cs_key = TrustSubject::counter_signature_signing_key(&cs);
                ctx.observe(CounterSignatureSigningKeySubjectFact {
                    subject: cs_key,
                    is_protected_header: false,
                })?;
            }
            ctx.mark_produced(FactKey::of::<CounterSignatureSigningKeySubjectFact>());
            return Ok(());
        }

        if requested == FactKey::of::<MarkerFact>() {
            // Provide the marker fact for both counter-signature subjects.
            if ctx.subject().kind == "CounterSignature" || ctx.subject().kind == "CounterSignatureSigningKey" {
                ctx.observe(MarkerFact { ok: true })?;
            }
            ctx.mark_produced(FactKey::of::<MarkerFact>());
            return Ok(());
        }

        Ok(())
    }
}

#[derive(Clone)]
struct MarkerPack;

impl CoseSign1TrustPack for MarkerPack {
    fn name(&self) -> &'static str {
        "MarkerPack"
    }

    fn fact_producer(&self) -> Arc<dyn TrustFactProducer> {
        Arc::new(MarkerProducer)
    }

    fn default_trust_plan(&self) -> Option<cose_sign1_validation_trust::plan::CompiledTrustPlan> {
        // Default plan exercises counter-signature scope; this is used via `CoseSign1Validator::new`.
        let bundled = TrustPlanBuilder::new(vec![Arc::new(self.clone())])
            .for_counter_signature(|cs| {
                cs.on_empty(OnEmptyBehavior::Allow)
                    .require::<MarkerFact>(|w| w.r#true(Field::new("ok")))
            })
            .compile()
            .expect("marker plan should compile");

        Some(bundled.plan().clone())
    }
}

#[test]
fn trust_plan_builder_scopes_evaluate_and_cover_subject_derivation() {
    let packs: Vec<Arc<dyn CoseSign1TrustPack>> = vec![Arc::new(MarkerPack)];

    // Exercise wrapper builder composition and both counter-signature scope helpers.
    let bundled = TrustPlanBuilder::new(packs.clone())
        .and()
        .for_counter_signature(|cs| {
            cs.on_empty(OnEmptyBehavior::Deny)
                .require::<MarkerFact>(|w| w.r#true(Field::new("ok")))
        })
        .or()
        .and_group(|g| {
            g.for_counter_signature_signing_key(|cs| {
                cs.on_empty(OnEmptyBehavior::Allow)
                    .require::<MarkerFact>(|w| w.r#true(Field::new("ok")))
            })
        })
        .compile()
        .expect("plan compiles");

    // Evaluate with a local engine to ensure the scopes enumerate derived subjects.
    let producers: Vec<Arc<dyn TrustFactProducer>> = packs.iter().map(|p| p.fact_producer()).collect();
    let engine = TrustFactEngine::new(producers);
    let message = TrustSubject::message(b"seed");

    let (decision, _audit) = bundled
        .plan()
        .evaluate_with_audit(&engine, &message, &Default::default())
        .expect("evaluate");
    assert!(decision.is_trusted);

    // Touch bundle accessors.
    let _ = bundled.trust_packs();
}

#[test]
fn validator_new_from_packs_invokes_from_parts_validation() {
    let packs: Vec<Arc<dyn CoseSign1TrustPack>> = vec![Arc::new(MarkerPack)];

    // This uses the pack's default plan and exercises `CoseSign1CompiledTrustPlan::from_parts(...)`.
    let _v = CoseSign1Validator::new(packs);
}

#[test]
fn has_trust_subject_impls_return_inner_subject() {
    let msg = TrustSubject::message(b"seed");
    let cs = TrustSubject::counter_signature(&msg, b"cs");
    let cs_key = TrustSubject::counter_signature_signing_key(&cs);
    let primary_key = TrustSubject::primary_signing_key(&msg);

    let cs_fact = CounterSignatureSubjectFact {
        subject: cs.clone(),
        is_protected_header: false,
    };
    let cs_key_fact = CounterSignatureSigningKeySubjectFact {
        subject: cs_key.clone(),
        is_protected_header: false,
    };
    let primary_fact = cose_sign1_validation::fluent::PrimarySigningKeySubjectFact {
        subject: primary_key.clone(),
    };

    assert_eq!(cs_fact.trust_subject().id, cs.id);
    assert_eq!(cs_key_fact.trust_subject().id, cs_key.id);
    assert_eq!(primary_fact.trust_subject().id, primary_key.id);
}
