// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Coverage tests for `cose_sign1_validation_primitives::error::TrustError` Display implementation.

use cose_sign1_validation_primitives::error::TrustError;

#[test]
fn trust_error_display_fact_production() {
    let error = TrustError::FactProduction("test error message".to_string());
    let display = format!("{}", error);
    assert_eq!(display, "fact production failed: test error message");
}

#[test]
fn trust_error_display_rule_evaluation() {
    let error = TrustError::RuleEvaluation("rule failed".to_string());
    let display = format!("{}", error);
    assert_eq!(display, "rule evaluation failed: rule failed");
}

#[test]
fn trust_error_display_deadline_exceeded() {
    let error = TrustError::DeadlineExceeded;
    let display = format!("{}", error);
    assert_eq!(display, "deadline exceeded");
}

#[test]
fn trust_error_implements_std_error() {
    let error = TrustError::FactProduction("test".to_string());
    let _error_trait: &dyn std::error::Error = &error;
    // Just verifying it compiles and can be used as std::error::Error
}
