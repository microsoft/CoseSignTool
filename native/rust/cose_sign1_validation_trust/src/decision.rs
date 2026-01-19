// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustDecision {
    pub is_trusted: bool,
    pub reasons: Vec<String>,
}

impl TrustDecision {
    pub fn trusted() -> Self {
        Self {
            is_trusted: true,
            reasons: Vec::new(),
        }
    }

    pub fn trusted_with(reasons: Vec<String>) -> Self {
        if reasons.is_empty() {
            return Self::trusted();
        }
        Self {
            is_trusted: true,
            reasons,
        }
    }

    pub fn trusted_reason(reason: impl Into<String>) -> Self {
        Self::trusted_with(vec![reason.into()])
    }

    pub fn denied(reasons: Vec<String>) -> Self {
        Self {
            is_trusted: false,
            reasons,
        }
    }
}
