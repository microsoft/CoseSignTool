// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#[derive(Debug)]
pub enum TrustError {
    FactProduction(String),
    RuleEvaluation(String),
    DeadlineExceeded,
}

impl std::fmt::Display for TrustError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::FactProduction(s) => write!(f, "fact production failed: {}", s),
            Self::RuleEvaluation(s) => write!(f, "rule evaluation failed: {}", s),
            Self::DeadlineExceeded => write!(f, "deadline exceeded"),
        }
    }
}

impl std::error::Error for TrustError {}
