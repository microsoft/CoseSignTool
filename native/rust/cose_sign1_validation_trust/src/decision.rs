// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

/// Outcome of trust evaluation for a subject.
///
/// `reasons` is a human-readable list intended for diagnostics and audit logs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustDecision {
    /// Whether the subject is trusted.
    pub is_trusted: bool,
    /// Diagnostic reasons (denials or trust reasons).
    pub reasons: Vec<String>,
}

impl TrustDecision {
    /// Trusted with no additional reasons.
    pub fn trusted() -> Self {
        Self {
            is_trusted: true,
            reasons: Vec::new(),
        }
    }

    /// Trusted with explicit reasons.
    pub fn trusted_with(reasons: Vec<String>) -> Self {
        if reasons.is_empty() {
            return Self::trusted();
        }
        Self {
            is_trusted: true,
            reasons,
        }
    }

    /// Trusted with a single diagnostic reason.
    pub fn trusted_reason(reason: impl Into<String>) -> Self {
        Self::trusted_with(vec![reason.into()])
    }

    /// Denied with explicit reasons.
    pub fn denied(reasons: Vec<String>) -> Self {
        Self {
            is_trusted: false,
            reasons,
        }
    }
}
