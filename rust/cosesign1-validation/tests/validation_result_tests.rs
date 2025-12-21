// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Basic unit tests for `ValidationResult` helpers.

use cosesign1_validation::ValidationResult;

#[test]
fn validation_result_helpers_work() {
    let ok = ValidationResult::success("V", Default::default());
    assert!(ok.is_valid);

    let bad = ValidationResult::failure_message("V", "oops", Some("E".to_string()));
    assert!(!bad.is_valid);
    assert_eq!(bad.failures.len(), 1);
    assert_eq!(bad.failures[0].error_code.as_deref(), Some("E"));
}
