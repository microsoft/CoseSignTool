// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Additional coverage tests for rule combinators focusing on edge cases.

use cose_sign1_validation_primitives::facts::TrustFactEngine;
use cose_sign1_validation_primitives::rules::{all_of, any_of, not, allow_all};
use cose_sign1_validation_primitives::subject::TrustSubject;

#[test]
fn any_of_with_all_failing_rules() {
    let subject = TrustSubject::root("Message", b"seed");
    let engine = TrustFactEngine::new(vec![]);

    // Create multiple deny rules using not(allow_all)
    let deny1 = not("deny1", allow_all("allow1"));
    let deny2 = not("deny2", allow_all("allow2"));
    let deny3 = not("deny3", allow_all("allow3"));

    // any_of should fail when all rules fail
    let rule = any_of("any_all_fail", vec![deny1, deny2, deny3]);
    let decision = rule.evaluate(&engine, &subject).unwrap();
    
    assert!(!decision.is_trusted);
    // Should have collected reasons from all failing rules
    assert!(decision.reasons.len() >= 3);
}

#[test]
fn not_with_nested_combinators() {
    let subject = TrustSubject::root("Message", b"seed");
    let engine = TrustFactEngine::new(vec![]);

    // Nested: not(all_of([allow, deny])) should trust (because all_of fails)
    let inner_all_of = all_of("inner_all_of", vec![
        allow_all("allow"),
        not("deny", allow_all("inner_allow")),
    ]);
    
    let negated_rule = not("not_all_of", inner_all_of);
    let decision = negated_rule.evaluate(&engine, &subject).unwrap();
    
    assert!(decision.is_trusted);
}

#[test]
fn deeply_nested_combinators() {
    let subject = TrustSubject::root("Message", b"seed");
    let engine = TrustFactEngine::new(vec![]);

    // Deep nesting: any_of([not(deny), all_of([allow, allow])])
    let not_deny = not("not_deny", not("inner_deny", allow_all("inner_allow")));
    let all_allows = all_of("all_allows", vec![
        allow_all("allow1"),
        allow_all("allow2"),
    ]);
    
    let complex_rule = any_of("complex", vec![not_deny, all_allows]);
    let decision = complex_rule.evaluate(&engine, &subject).unwrap();
    
    assert!(decision.is_trusted);
}

#[test]
fn all_of_with_one_failing_rule() {
    let subject = TrustSubject::root("Message", b"seed");
    let engine = TrustFactEngine::new(vec![]);

    // all_of should fail if any rule fails
    let rule = all_of("mixed_all_of", vec![
        allow_all("allow1"),
        allow_all("allow2"),
        not("deny1", allow_all("inner_allow")), // This one fails
        allow_all("allow3"),
    ]);
    
    let decision = rule.evaluate(&engine, &subject).unwrap();
    assert!(!decision.is_trusted);
    // Should have the reason from the failing rule
    assert!(!decision.reasons.is_empty());
}

#[test]
fn any_of_short_circuits_on_first_success() {
    let subject = TrustSubject::root("Message", b"seed");
    let engine = TrustFactEngine::new(vec![]);

    // any_of should succeed as soon as it finds a trusting rule
    let rule = any_of("short_circuit", vec![
        not("deny1", allow_all("inner1")),
        allow_all("allow1"), // This should make it succeed
        not("deny2", allow_all("inner2")), // This should not be evaluated
    ]);
    
    let decision = rule.evaluate(&engine, &subject).unwrap();
    assert!(decision.is_trusted);
    // No deny reasons should be collected since it short-circuited
    assert!(decision.reasons.is_empty());
}