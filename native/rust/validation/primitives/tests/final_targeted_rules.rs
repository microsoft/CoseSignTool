// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Targeted coverage tests for uncovered lines in `cose_sign1_validation_primitives::rules`.
//!
//! Covers:
//! - AllOf::evaluate with denied inner rule (line 128)
//! - AnyOf::evaluate with all denied (line 168) and trusted shortcut (line 196)
//! - Not::evaluate both branches (line 196)
//! - require_any with Missing/Error (lines 264, 266)
//! - require_fact_property with Missing/Error (lines 501, 503)
//! - require_fact_matches with Missing/Error (lines 554, 556)
//! - require_fact_matches_with_missing_behavior Allow/Deny branches (lines 599, 601)
//! - require_facts_match with error left/right and missing right (lines 695-699, 778)
//! - AuditedRule (line 778)

use cose_sign1_validation_primitives::audit::TrustDecisionAuditBuilder;
use cose_sign1_validation_primitives::decision::TrustDecision;
use cose_sign1_validation_primitives::error::TrustError;
use cose_sign1_validation_primitives::fact_properties::{
    FactProperties, FactValue, FactValueOwned,
};
use cose_sign1_validation_primitives::facts::{
    FactKey, TrustFactContext, TrustFactEngine, TrustFactProducer,
};
use cose_sign1_validation_primitives::rules::{
    all_of, allow_all, any_of, not, not_with_reason, require_any, require_fact_bool,
    require_fact_matches, require_fact_matches_with_missing_behavior, require_fact_property,
    require_fact_property_eq, require_fact_str_non_empty, require_facts_match, AuditedRule,
    FactSelector, MissingBehavior, PropertyPredicate,
};
// TrustRule trait is needed in scope for .evaluate() on Arc<dyn TrustRule>
#[allow(unused_imports)]
use cose_sign1_validation_primitives::rules::TrustRule;
use cose_sign1_validation_primitives::subject::TrustSubject;
use std::borrow::Cow;
use std::sync::{Arc, Mutex};

// ---------------------------------------------------------------------------
// Fact types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
struct Alpha {
    id: String,
    name: String,
    active: bool,
    count: i64,
}

impl FactProperties for Alpha {
    fn get_property<'a>(&'a self, prop: &str) -> Option<FactValue<'a>> {
        match prop {
            "id" => Some(FactValue::Str(Cow::Borrowed(&self.id))),
            "name" => Some(FactValue::Str(Cow::Borrowed(&self.name))),
            "active" => Some(FactValue::Bool(self.active)),
            "count" => Some(FactValue::I64(self.count)),
            _ => None,
        }
    }
}

#[derive(Debug, Clone)]
struct Beta {
    id: String,
    label: String,
}

impl FactProperties for Beta {
    fn get_property<'a>(&'a self, prop: &str) -> Option<FactValue<'a>> {
        match prop {
            "id" => Some(FactValue::Str(Cow::Borrowed(&self.id))),
            "label" => Some(FactValue::Str(Cow::Borrowed(&self.label))),
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------
// Producers
// ---------------------------------------------------------------------------

struct AlphaBetaProducer {
    alpha: Option<Alpha>,
    beta: Option<Beta>,
}

impl TrustFactProducer for AlphaBetaProducer {
    fn name(&self) -> &'static str {
        "alpha_beta"
    }

    fn provides(&self) -> &'static [FactKey] {
        static ONCE: std::sync::OnceLock<Vec<FactKey>> = std::sync::OnceLock::new();
        ONCE.get_or_init(|| vec![FactKey::of::<Alpha>(), FactKey::of::<Beta>()])
            .as_slice()
    }

    fn produce(&self, ctx: &mut TrustFactContext<'_>) -> Result<(), TrustError> {
        if ctx.requested_fact() == FactKey::of::<Alpha>() {
            if let Some(ref a) = self.alpha {
                ctx.observe(a.clone())?;
            }
            ctx.mark_produced(FactKey::of::<Alpha>());
        }
        if ctx.requested_fact() == FactKey::of::<Beta>() {
            if let Some(ref b) = self.beta {
                ctx.observe(b.clone())?;
            }
            ctx.mark_produced(FactKey::of::<Beta>());
        }
        Ok(())
    }
}

struct MissingAlphaProducer;

impl TrustFactProducer for MissingAlphaProducer {
    fn name(&self) -> &'static str {
        "missing_alpha"
    }

    fn provides(&self) -> &'static [FactKey] {
        static ONCE: std::sync::OnceLock<Vec<FactKey>> = std::sync::OnceLock::new();
        ONCE.get_or_init(|| vec![FactKey::of::<Alpha>(), FactKey::of::<Beta>()])
            .as_slice()
    }

    fn produce(&self, ctx: &mut TrustFactContext<'_>) -> Result<(), TrustError> {
        if ctx.requested_fact() == FactKey::of::<Alpha>() {
            ctx.mark_missing::<Alpha>("AlphaNotAvailable");
            ctx.mark_produced(FactKey::of::<Alpha>());
        }
        if ctx.requested_fact() == FactKey::of::<Beta>() {
            ctx.mark_missing::<Beta>("BetaNotAvailable");
            ctx.mark_produced(FactKey::of::<Beta>());
        }
        Ok(())
    }
}

struct ErrorAlphaProducer;

impl TrustFactProducer for ErrorAlphaProducer {
    fn name(&self) -> &'static str {
        "error_alpha"
    }

    fn provides(&self) -> &'static [FactKey] {
        static ONCE: std::sync::OnceLock<Vec<FactKey>> = std::sync::OnceLock::new();
        ONCE.get_or_init(|| vec![FactKey::of::<Alpha>(), FactKey::of::<Beta>()])
            .as_slice()
    }

    fn produce(&self, ctx: &mut TrustFactContext<'_>) -> Result<(), TrustError> {
        if ctx.requested_fact() == FactKey::of::<Alpha>() {
            ctx.mark_error::<Alpha>("AlphaError".to_string());
            ctx.mark_produced(FactKey::of::<Alpha>());
        }
        if ctx.requested_fact() == FactKey::of::<Beta>() {
            ctx.mark_error::<Beta>("BetaError".to_string());
            ctx.mark_produced(FactKey::of::<Beta>());
        }
        Ok(())
    }
}

fn id_selector() -> impl Fn(&TrustSubject) -> TrustSubject + Send + Sync + 'static {
    |s: &TrustSubject| s.clone()
}

fn make_engine(producer: impl TrustFactProducer + 'static) -> TrustFactEngine {
    TrustFactEngine::new(vec![Arc::new(producer)])
}

fn subject() -> TrustSubject {
    TrustSubject::message(b"test-subject")
}

// ====================================================================
// AllOf (line 128): one denied -> all denied
// ====================================================================

#[test]
fn all_of_one_denied_returns_denied() {
    let engine = make_engine(AlphaBetaProducer {
        alpha: Some(Alpha {
            id: "1".into(),
            name: "a".into(),
            active: true,
            count: 5,
        }),
        beta: None,
    });

    let rule = all_of(
        "all",
        vec![
            allow_all("pass"),
            require_any::<Alpha, _, _>(
                "need_alpha_false",
                id_selector(),
                |a: &Alpha| a.active == false,
                "not inactive",
            ),
        ],
    );

    let decision = rule.evaluate(&engine, &subject()).unwrap();
    assert!(
        !decision.is_trusted,
        "AllOf should deny when inner rule denies"
    );
    assert!(!decision.reasons.is_empty());
}

#[test]
fn all_of_all_pass() {
    let engine = make_engine(AlphaBetaProducer {
        alpha: Some(Alpha {
            id: "1".into(),
            name: "a".into(),
            active: true,
            count: 5,
        }),
        beta: None,
    });

    let rule = all_of("all_pass", vec![allow_all("p1"), allow_all("p2")]);

    let decision = rule.evaluate(&engine, &subject()).unwrap();
    assert!(decision.is_trusted);
}

// ====================================================================
// AnyOf (line 168): all denied -> denied with reasons
// ====================================================================

#[test]
fn any_of_all_denied() {
    let engine = make_engine(AlphaBetaProducer {
        alpha: Some(Alpha {
            id: "1".into(),
            name: "a".into(),
            active: false,
            count: 5,
        }),
        beta: None,
    });

    let rule = any_of(
        "any",
        vec![
            require_any::<Alpha, _, _>(
                "need_active",
                id_selector(),
                |a: &Alpha| a.count > 100,
                "count too low",
            ),
            require_any::<Alpha, _, _>(
                "need_id_2",
                id_selector(),
                |a: &Alpha| a.id == "2",
                "wrong id",
            ),
        ],
    );

    let decision = rule.evaluate(&engine, &subject()).unwrap();
    assert!(!decision.is_trusted, "AnyOf should deny when all deny");
}

#[test]
fn any_of_one_passes() {
    let engine = make_engine(AlphaBetaProducer {
        alpha: Some(Alpha {
            id: "1".into(),
            name: "a".into(),
            active: true,
            count: 5,
        }),
        beta: None,
    });

    let rule = any_of(
        "any_pass",
        vec![
            require_any::<Alpha, _, _>(
                "need_active",
                id_selector(),
                |a: &Alpha| a.active,
                "not active",
            ),
            require_any::<Alpha, _, _>(
                "need_id_99",
                id_selector(),
                |a: &Alpha| a.id == "99",
                "wrong",
            ),
        ],
    );

    let decision = rule.evaluate(&engine, &subject()).unwrap();
    assert!(decision.is_trusted, "AnyOf should trust when one passes");
}

#[test]
fn any_of_empty_rules_denies() {
    let engine = make_engine(AlphaBetaProducer {
        alpha: None,
        beta: None,
    });
    let rule = any_of("empty", vec![]);
    let decision = rule.evaluate(&engine, &subject()).unwrap();
    assert!(!decision.is_trusted, "Empty AnyOf should deny");
}

// ====================================================================
// Not (line 196): invert decisions
// ====================================================================

#[test]
fn not_inverts_trusted_to_denied() {
    let engine = make_engine(AlphaBetaProducer {
        alpha: None,
        beta: None,
    });
    let rule = not("not_pass", allow_all("inner_pass"));
    let decision = rule.evaluate(&engine, &subject()).unwrap();
    assert!(!decision.is_trusted, "Not should deny when inner trusts");
}

#[test]
fn not_inverts_denied_to_trusted() {
    let engine = make_engine(MissingAlphaProducer);
    let inner =
        require_any::<Alpha, _, _>("need_alpha", id_selector(), |_: &Alpha| true, "no alpha");
    let rule = not("not_deny", inner);
    let decision = rule.evaluate(&engine, &subject()).unwrap();
    assert!(decision.is_trusted, "Not should trust when inner denies");
}

#[test]
fn not_with_reason_gives_custom_reason() {
    let engine = make_engine(AlphaBetaProducer {
        alpha: None,
        beta: None,
    });
    let rule = not_with_reason("not_custom", allow_all("inner"), "custom deny reason");
    let decision = rule.evaluate(&engine, &subject()).unwrap();
    assert!(!decision.is_trusted);
    assert!(decision
        .reasons
        .iter()
        .any(|r| r.contains("custom deny reason")));
}

// ====================================================================
// require_any with Missing (line 264) and Error (line 266)
// ====================================================================

#[test]
fn require_any_missing_fact_denies() {
    let engine = make_engine(MissingAlphaProducer);
    let rule = require_any::<Alpha, _, _>(
        "need_alpha",
        id_selector(),
        |_: &Alpha| true,
        "alpha missing",
    );
    let decision = rule.evaluate(&engine, &subject()).unwrap();
    assert!(!decision.is_trusted, "Missing fact should deny");
}

#[test]
fn require_any_error_fact_denies() {
    let engine = make_engine(ErrorAlphaProducer);
    let rule =
        require_any::<Alpha, _, _>("need_alpha", id_selector(), |_: &Alpha| true, "alpha error");
    let decision = rule.evaluate(&engine, &subject()).unwrap();
    assert!(!decision.is_trusted, "Error fact should deny");
}

// ====================================================================
// require_fact_property with Missing/Error (lines 501, 503)
// ====================================================================

#[test]
fn require_fact_property_missing_denies() {
    let engine = make_engine(MissingAlphaProducer);
    let rule = require_fact_property::<Alpha, _>(
        "prop_missing",
        id_selector(),
        FactSelector::first(),
        "name",
        PropertyPredicate::StrNonEmpty,
        "missing alpha",
    );
    let decision = rule.evaluate(&engine, &subject()).unwrap();
    assert!(!decision.is_trusted);
}

#[test]
fn require_fact_property_error_denies() {
    let engine = make_engine(ErrorAlphaProducer);
    let rule = require_fact_property::<Alpha, _>(
        "prop_error",
        id_selector(),
        FactSelector::first(),
        "name",
        PropertyPredicate::StrNonEmpty,
        "error alpha",
    );
    let decision = rule.evaluate(&engine, &subject()).unwrap();
    assert!(!decision.is_trusted);
}

#[test]
fn require_fact_property_no_matching_fact_denies() {
    let engine = make_engine(AlphaBetaProducer {
        alpha: Some(Alpha {
            id: "1".into(),
            name: "a".into(),
            active: true,
            count: 5,
        }),
        beta: None,
    });
    let rule = require_fact_property::<Alpha, _>(
        "prop_no_match",
        id_selector(),
        FactSelector::first().where_eq("id", FactValueOwned::String("99".into())),
        "name",
        PropertyPredicate::StrNonEmpty,
        "no match",
    );
    let decision = rule.evaluate(&engine, &subject()).unwrap();
    assert!(!decision.is_trusted);
}

#[test]
fn require_fact_property_missing_property_denies() {
    let engine = make_engine(AlphaBetaProducer {
        alpha: Some(Alpha {
            id: "1".into(),
            name: "a".into(),
            active: true,
            count: 5,
        }),
        beta: None,
    });
    let rule = require_fact_property::<Alpha, _>(
        "prop_no_prop",
        id_selector(),
        FactSelector::first(),
        "nonexistent_prop",
        PropertyPredicate::StrNonEmpty,
        "no prop",
    );
    let decision = rule.evaluate(&engine, &subject()).unwrap();
    assert!(!decision.is_trusted);
}

// ====================================================================
// require_fact_matches with Missing/Error (lines 554, 556)
// ====================================================================

#[test]
fn require_fact_matches_missing_denies() {
    let engine = make_engine(MissingAlphaProducer);
    let rule = require_fact_matches::<Alpha, _>(
        "matches_missing",
        id_selector(),
        FactSelector::first(),
        "missing alpha",
    );
    let decision = rule.evaluate(&engine, &subject()).unwrap();
    assert!(!decision.is_trusted);
}

#[test]
fn require_fact_matches_error_denies() {
    let engine = make_engine(ErrorAlphaProducer);
    let rule = require_fact_matches::<Alpha, _>(
        "matches_error",
        id_selector(),
        FactSelector::first(),
        "error alpha",
    );
    let decision = rule.evaluate(&engine, &subject()).unwrap();
    assert!(!decision.is_trusted);
}

#[test]
fn require_fact_matches_no_match_denies() {
    let engine = make_engine(AlphaBetaProducer {
        alpha: Some(Alpha {
            id: "1".into(),
            name: "a".into(),
            active: true,
            count: 5,
        }),
        beta: None,
    });
    let rule = require_fact_matches::<Alpha, _>(
        "matches_no_match",
        id_selector(),
        FactSelector::first().where_eq("id", FactValueOwned::String("nonexistent".into())),
        "no match",
    );
    let decision = rule.evaluate(&engine, &subject()).unwrap();
    assert!(!decision.is_trusted);
}

#[test]
fn require_fact_matches_match_trusts() {
    let engine = make_engine(AlphaBetaProducer {
        alpha: Some(Alpha {
            id: "1".into(),
            name: "a".into(),
            active: true,
            count: 5,
        }),
        beta: None,
    });
    let rule = require_fact_matches::<Alpha, _>(
        "matches_ok",
        id_selector(),
        FactSelector::first().where_eq("id", FactValueOwned::String("1".into())),
        "should match",
    );
    let decision = rule.evaluate(&engine, &subject()).unwrap();
    assert!(decision.is_trusted);
}

// ====================================================================
// require_fact_matches_with_missing_behavior (lines 599, 601, 614-621)
// ====================================================================

#[test]
fn require_fact_matches_with_missing_allow_trusts() {
    let engine = make_engine(MissingAlphaProducer);
    let rule = require_fact_matches_with_missing_behavior::<Alpha, _>(
        "missing_allow",
        id_selector(),
        FactSelector::first(),
        MissingBehavior::Allow,
        "allow missing",
    );
    let decision = rule.evaluate(&engine, &subject()).unwrap();
    assert!(decision.is_trusted, "MissingBehavior::Allow should trust");
}

#[test]
fn require_fact_matches_with_missing_deny_denies() {
    let engine = make_engine(MissingAlphaProducer);
    let rule = require_fact_matches_with_missing_behavior::<Alpha, _>(
        "missing_deny",
        id_selector(),
        FactSelector::first(),
        MissingBehavior::Deny,
        "deny missing",
    );
    let decision = rule.evaluate(&engine, &subject()).unwrap();
    assert!(!decision.is_trusted, "MissingBehavior::Deny should deny");
}

#[test]
fn require_fact_matches_with_missing_no_match_allow() {
    let engine = make_engine(AlphaBetaProducer {
        alpha: Some(Alpha {
            id: "1".into(),
            name: "a".into(),
            active: true,
            count: 5,
        }),
        beta: None,
    });
    let rule = require_fact_matches_with_missing_behavior::<Alpha, _>(
        "no_match_allow",
        id_selector(),
        FactSelector::first().where_eq("id", FactValueOwned::String("999".into())),
        MissingBehavior::Allow,
        "allow no match",
    );
    let decision = rule.evaluate(&engine, &subject()).unwrap();
    assert!(decision.is_trusted, "No match + Allow => trusted");
}

#[test]
fn require_fact_matches_with_missing_no_match_deny() {
    let engine = make_engine(AlphaBetaProducer {
        alpha: Some(Alpha {
            id: "1".into(),
            name: "a".into(),
            active: true,
            count: 5,
        }),
        beta: None,
    });
    let rule = require_fact_matches_with_missing_behavior::<Alpha, _>(
        "no_match_deny",
        id_selector(),
        FactSelector::first().where_eq("id", FactValueOwned::String("999".into())),
        MissingBehavior::Deny,
        "deny no match",
    );
    let decision = rule.evaluate(&engine, &subject()).unwrap();
    assert!(!decision.is_trusted, "No match + Deny => denied");
}

// ====================================================================
// require_facts_match (lines 695-699, 729-738, 741-750)
// ====================================================================

#[test]
fn require_facts_match_both_available_and_matching() {
    let engine = make_engine(AlphaBetaProducer {
        alpha: Some(Alpha {
            id: "1".into(),
            name: "shared".into(),
            active: true,
            count: 5,
        }),
        beta: Some(Beta {
            id: "1".into(),
            label: "shared".into(),
        }),
    });
    let rule = require_facts_match::<Alpha, Beta, _>(
        "match_ok",
        id_selector(),
        FactSelector::first(),
        FactSelector::first(),
        vec![("id", "id")],
        MissingBehavior::Deny,
        "mismatch",
    );
    let decision = rule.evaluate(&engine, &subject()).unwrap();
    assert!(decision.is_trusted);
}

#[test]
fn require_facts_match_property_mismatch_denies() {
    let engine = make_engine(AlphaBetaProducer {
        alpha: Some(Alpha {
            id: "1".into(),
            name: "a".into(),
            active: true,
            count: 5,
        }),
        beta: Some(Beta {
            id: "2".into(),
            label: "b".into(),
        }),
    });
    let rule = require_facts_match::<Alpha, Beta, _>(
        "match_mismatch",
        id_selector(),
        FactSelector::first(),
        FactSelector::first(),
        vec![("id", "id")],
        MissingBehavior::Deny,
        "ids differ",
    );
    let decision = rule.evaluate(&engine, &subject()).unwrap();
    assert!(!decision.is_trusted);
}

#[test]
fn require_facts_match_left_missing_denies() {
    let engine = make_engine(MissingAlphaProducer);
    let rule = require_facts_match::<Alpha, Beta, _>(
        "match_left_missing",
        id_selector(),
        FactSelector::first(),
        FactSelector::first(),
        vec![("id", "id")],
        MissingBehavior::Deny,
        "left missing",
    );
    let decision = rule.evaluate(&engine, &subject()).unwrap();
    assert!(!decision.is_trusted);
}

#[test]
fn require_facts_match_left_error_denies() {
    let engine = make_engine(ErrorAlphaProducer);
    let rule = require_facts_match::<Alpha, Beta, _>(
        "match_left_error",
        id_selector(),
        FactSelector::first(),
        FactSelector::first(),
        vec![("id", "id")],
        MissingBehavior::Deny,
        "left error",
    );
    let decision = rule.evaluate(&engine, &subject()).unwrap();
    assert!(!decision.is_trusted);
}

#[test]
fn require_facts_match_right_missing_allow() {
    let engine = make_engine(AlphaBetaProducer {
        alpha: Some(Alpha {
            id: "1".into(),
            name: "a".into(),
            active: true,
            count: 5,
        }),
        beta: None, // Beta not observed -> Missing
    });
    let rule = require_facts_match::<Alpha, Beta, _>(
        "match_right_missing_allow",
        id_selector(),
        FactSelector::first(),
        FactSelector::first(),
        vec![("id", "id")],
        MissingBehavior::Allow,
        "right missing ok",
    );
    let decision = rule.evaluate(&engine, &subject()).unwrap();
    // Right missing + Allow behavior
    // Note: depends on whether "no facts" vs "missing" - with our producer,
    // Beta is produced (mark_produced called) but no facts, so it's Available([])
    // which means select_fact returns None, and missing_right=Allow -> trusted
    assert!(decision.is_trusted);
}

#[test]
fn require_facts_match_right_missing_deny() {
    let engine = make_engine(AlphaBetaProducer {
        alpha: Some(Alpha {
            id: "1".into(),
            name: "a".into(),
            active: true,
            count: 5,
        }),
        beta: None,
    });
    let rule = require_facts_match::<Alpha, Beta, _>(
        "match_right_missing_deny",
        id_selector(),
        FactSelector::first(),
        FactSelector::first(),
        vec![("id", "id")],
        MissingBehavior::Deny,
        "right missing deny",
    );
    let decision = rule.evaluate(&engine, &subject()).unwrap();
    assert!(!decision.is_trusted);
}

#[test]
fn require_facts_match_left_no_property_denies() {
    let engine = make_engine(AlphaBetaProducer {
        alpha: Some(Alpha {
            id: "1".into(),
            name: "a".into(),
            active: true,
            count: 5,
        }),
        beta: Some(Beta {
            id: "1".into(),
            label: "b".into(),
        }),
    });
    let rule = require_facts_match::<Alpha, Beta, _>(
        "match_no_prop",
        id_selector(),
        FactSelector::first(),
        FactSelector::first(),
        vec![("nonexistent", "id")],
        MissingBehavior::Deny,
        "left prop missing",
    );
    let decision = rule.evaluate(&engine, &subject()).unwrap();
    assert!(!decision.is_trusted);
}

#[test]
fn require_facts_match_right_no_property_denies() {
    let engine = make_engine(AlphaBetaProducer {
        alpha: Some(Alpha {
            id: "1".into(),
            name: "a".into(),
            active: true,
            count: 5,
        }),
        beta: Some(Beta {
            id: "1".into(),
            label: "b".into(),
        }),
    });
    let rule = require_facts_match::<Alpha, Beta, _>(
        "match_right_no_prop",
        id_selector(),
        FactSelector::first(),
        FactSelector::first(),
        vec![("id", "nonexistent")],
        MissingBehavior::Deny,
        "right prop missing",
    );
    let decision = rule.evaluate(&engine, &subject()).unwrap();
    assert!(!decision.is_trusted);
}

// ====================================================================
// require_fact_bool (convenience wrapper)
// ====================================================================

#[test]
fn require_fact_bool_true_trusts() {
    let engine = make_engine(AlphaBetaProducer {
        alpha: Some(Alpha {
            id: "1".into(),
            name: "a".into(),
            active: true,
            count: 5,
        }),
        beta: None,
    });
    let rule = require_fact_bool::<Alpha, _>(
        "bool_true",
        id_selector(),
        FactSelector::first(),
        "active",
        true,
        "not active",
    );
    let decision = rule.evaluate(&engine, &subject()).unwrap();
    assert!(decision.is_trusted);
}

#[test]
fn require_fact_bool_mismatch_denies() {
    let engine = make_engine(AlphaBetaProducer {
        alpha: Some(Alpha {
            id: "1".into(),
            name: "a".into(),
            active: false,
            count: 5,
        }),
        beta: None,
    });
    let rule = require_fact_bool::<Alpha, _>(
        "bool_mismatch",
        id_selector(),
        FactSelector::first(),
        "active",
        true,
        "not active",
    );
    let decision = rule.evaluate(&engine, &subject()).unwrap();
    assert!(!decision.is_trusted);
}

// ====================================================================
// require_fact_str_non_empty
// ====================================================================

#[test]
fn require_fact_str_non_empty_trusts() {
    let engine = make_engine(AlphaBetaProducer {
        alpha: Some(Alpha {
            id: "1".into(),
            name: "hello".into(),
            active: true,
            count: 5,
        }),
        beta: None,
    });
    let rule = require_fact_str_non_empty::<Alpha, _>(
        "str_nonempty",
        id_selector(),
        FactSelector::first(),
        "name",
        "name empty",
    );
    let decision = rule.evaluate(&engine, &subject()).unwrap();
    assert!(decision.is_trusted);
}

#[test]
fn require_fact_str_non_empty_empty_denies() {
    let engine = make_engine(AlphaBetaProducer {
        alpha: Some(Alpha {
            id: "1".into(),
            name: "".into(),
            active: true,
            count: 5,
        }),
        beta: None,
    });
    let rule = require_fact_str_non_empty::<Alpha, _>(
        "str_empty",
        id_selector(),
        FactSelector::first(),
        "name",
        "name empty",
    );
    let decision = rule.evaluate(&engine, &subject()).unwrap();
    assert!(!decision.is_trusted);
}

// ====================================================================
// require_fact_property_eq
// ====================================================================

#[test]
fn require_fact_property_eq_match_trusts() {
    let engine = make_engine(AlphaBetaProducer {
        alpha: Some(Alpha {
            id: "1".into(),
            name: "x".into(),
            active: true,
            count: 42,
        }),
        beta: None,
    });
    let rule = require_fact_property_eq::<Alpha, _>(
        "eq_match",
        id_selector(),
        FactSelector::first(),
        "count",
        FactValueOwned::I64(42),
        "wrong count",
    );
    let decision = rule.evaluate(&engine, &subject()).unwrap();
    assert!(decision.is_trusted);
}

#[test]
fn require_fact_property_eq_mismatch_denies() {
    let engine = make_engine(AlphaBetaProducer {
        alpha: Some(Alpha {
            id: "1".into(),
            name: "x".into(),
            active: true,
            count: 99,
        }),
        beta: None,
    });
    let rule = require_fact_property_eq::<Alpha, _>(
        "eq_mismatch",
        id_selector(),
        FactSelector::first(),
        "count",
        FactValueOwned::I64(42),
        "wrong count",
    );
    let decision = rule.evaluate(&engine, &subject()).unwrap();
    assert!(!decision.is_trusted);
}

// ====================================================================
// AuditedRule (line 778)
// ====================================================================

#[test]
fn audited_rule_records_evaluation() {
    let engine = make_engine(AlphaBetaProducer {
        alpha: None,
        beta: None,
    });
    let audit_builder = Arc::new(Mutex::new(TrustDecisionAuditBuilder::default()));
    let inner = allow_all("audited_inner");
    let rule = AuditedRule::new(inner, audit_builder.clone());

    let decision = rule.evaluate(&engine, &subject()).unwrap();
    assert!(decision.is_trusted);

    let builder = std::mem::take(&mut *audit_builder.lock().unwrap());
    let audit = builder.build();
    assert!(
        !audit.events().is_empty(),
        "Audit should record the evaluation"
    );
}

#[test]
fn audited_rule_records_denial() {
    let engine = make_engine(MissingAlphaProducer);
    let audit_builder = Arc::new(Mutex::new(TrustDecisionAuditBuilder::default()));
    let inner =
        require_any::<Alpha, _, _>("need_alpha", id_selector(), |_: &Alpha| true, "no alpha");
    let rule = AuditedRule::new(inner, audit_builder.clone());

    let decision = rule.evaluate(&engine, &subject()).unwrap();
    assert!(!decision.is_trusted);

    let builder = std::mem::take(&mut *audit_builder.lock().unwrap());
    let audit = builder.build();
    assert!(!audit.events().is_empty());
}
