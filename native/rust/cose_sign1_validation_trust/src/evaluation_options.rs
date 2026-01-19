// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use std::time::Duration;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CoseHeaderLocation {
    Protected,
    Any,
}

impl Default for CoseHeaderLocation {
    fn default() -> Self {
        Self::Protected
    }
}

/// Options controlling trust evaluation behavior.
/// Mirrors V2's `CoseSign1.Validation.Trust.Plan.TrustEvaluationOptions`.
#[derive(Debug, Clone, Default)]
pub struct TrustEvaluationOptions {
    pub overall_timeout: Option<Duration>,
    pub per_fact_timeout: Option<Duration>,
    pub per_producer_timeout: Option<Duration>,

    /// When true, the validator should skip trust evaluation entirely while still
    /// performing cryptographic signature verification.
    pub bypass_trust: bool,
}
