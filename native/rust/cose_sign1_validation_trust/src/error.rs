// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum TrustError {
    #[error("fact production failed: {0}")]
    FactProduction(String),

    #[error("rule evaluation failed: {0}")]
    RuleEvaluation(String),

    #[error("deadline exceeded")]
    DeadlineExceeded,
}
