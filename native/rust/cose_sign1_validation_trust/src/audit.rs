// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use crate::ids::SubjectId;
use crate::TrustDecision;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuditEvent {
    RuleEvaluated {
        subject: SubjectId,
        rule_name: &'static str,
        decision: TrustDecision,
    },
    FactObserved {
        subject: SubjectId,
        fact_type: &'static str,
    },
}

#[derive(Debug, Default, Clone)]
pub struct TrustDecisionAudit {
    events: Vec<AuditEvent>,
}

impl TrustDecisionAudit {
    pub fn events(&self) -> &[AuditEvent] {
        &self.events
    }
}

#[derive(Debug, Default)]
pub struct TrustDecisionAuditBuilder {
    audit: TrustDecisionAudit,
}

impl TrustDecisionAuditBuilder {
    pub fn push(&mut self, event: AuditEvent) {
        self.audit.events.push(event);
    }

    pub fn build(self) -> TrustDecisionAudit {
        self.audit
    }
}
