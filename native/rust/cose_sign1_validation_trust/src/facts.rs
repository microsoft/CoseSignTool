// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use crate::audit::{AuditEvent, TrustDecisionAudit, TrustDecisionAuditBuilder};
use crate::cose_sign1::CoseSign1ParsedMessage;
use crate::error::TrustError;
use crate::ids::SubjectId;
use crate::subject::TrustSubject;
use crate::{CoseHeaderLocation, TrustEvaluationOptions};
use parking_lot::Mutex;
use std::any::{Any, TypeId};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::{Duration, Instant};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TrustFactSet<T> {
    Available(Vec<Arc<T>>),
    Missing { reason: String },
    Error { message: String },
}

impl<T> TrustFactSet<T> {
    pub fn is_missing(&self) -> bool {
        matches!(self, TrustFactSet::Missing { .. })
    }

    pub fn as_available(&self) -> Option<&[Arc<T>]> {
        match self {
            TrustFactSet::Available(v) => Some(v.as_slice()),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FactKey {
    pub type_id: TypeId,
    pub name: &'static str,
}

impl FactKey {
    pub fn of<T: Any + Send + Sync>() -> Self {
        Self {
            type_id: TypeId::of::<T>(),
            name: std::any::type_name::<T>(),
        }
    }
}

pub trait TrustFactProducer: Send + Sync {
    fn name(&self) -> &'static str;

    /// Produce facts into the given context.
    fn produce(&self, ctx: &mut TrustFactContext<'_>) -> Result<(), TrustError>;

    /// Advertise which fact types this producer may create.
    fn provides(&self) -> &'static [FactKey];
}

#[derive(Clone)]
pub struct TrustFactContext<'a> {
    subject: &'a TrustSubject,
    engine: &'a TrustFactEngine,
    requested_fact: FactKey,
    per_fact_deadline: Option<Instant>,
    per_producer_deadline: Option<Instant>,
}

impl<'a> TrustFactContext<'a> {
    pub fn subject(&self) -> &TrustSubject {
        self.subject
    }

    pub fn requested_fact(&self) -> FactKey {
        self.requested_fact
    }

    pub fn cose_sign1_bytes(&self) -> Option<&[u8]> {
        self.engine.cose_sign1_bytes.as_deref()
    }

    pub fn cose_sign1_message(&self) -> Option<&CoseSign1ParsedMessage> {
        self.engine.cose_sign1_message.as_deref()
    }

    pub fn cose_header_location(&self) -> CoseHeaderLocation {
        self.engine.cose_header_location
    }

    pub fn deadline_exceeded(&self) -> bool {
        let now = Instant::now();

        let overall = self.engine.deadline.map(|d| now >= d).unwrap_or(false);
        let per_fact = self.per_fact_deadline.map(|d| now >= d).unwrap_or(false);
        let per_producer = self
            .per_producer_deadline
            .map(|d| now >= d)
            .unwrap_or(false);

        overall || per_fact || per_producer
    }

    pub fn observe<T: Any + Send + Sync>(&self, fact: T) -> Result<(), TrustError> {
        if self.deadline_exceeded() {
            return Err(TrustError::DeadlineExceeded);
        }
        self.engine.observe_fact(self.subject.id, fact);
        Ok(())
    }

    pub fn mark_missing<T: Any + Send + Sync>(&self, reason: impl Into<String>) {
        self.engine
            .mark_missing(self.subject.id, TypeId::of::<T>(), reason.into());
    }

    pub fn mark_error<T: Any + Send + Sync>(&self, message: impl Into<String>) {
        self.engine
            .mark_error(self.subject.id, TypeId::of::<T>(), message.into());
    }

    pub fn mark_produced(&self, key: FactKey) {
        self.engine.mark_produced(self.subject.id, key);
    }

    pub fn get_facts<T: Any + Send + Sync>(
        &self,
        subject: &TrustSubject,
    ) -> Result<Vec<Arc<T>>, TrustError> {
        self.engine.get_facts::<T>(subject)
    }

    pub fn get_fact_set<T: Any + Send + Sync>(
        &self,
        subject: &TrustSubject,
    ) -> Result<TrustFactSet<T>, TrustError> {
        self.engine.get_fact_set::<T>(subject)
    }
}

#[derive(Debug, Default)]
struct EngineState {
    facts: HashMap<SubjectId, HashMap<TypeId, Vec<Arc<dyn Any + Send + Sync>>>>,
    produced: HashSet<(SubjectId, TypeId)>,
    missing: HashMap<(SubjectId, TypeId), String>,
    errors: HashMap<(SubjectId, TypeId), String>,
}

pub struct TrustFactEngine {
    producers: Vec<Arc<dyn TrustFactProducer>>,
    state: Mutex<EngineState>,
    deadline: Option<Instant>,
    audit: Mutex<Option<TrustDecisionAuditBuilder>>,
    cose_sign1_bytes: Option<Arc<[u8]>>,
    cose_sign1_message: Option<Arc<CoseSign1ParsedMessage>>,
    cose_header_location: CoseHeaderLocation,
    per_fact_timeout: Option<Duration>,
    per_producer_timeout: Option<Duration>,
}

impl TrustFactEngine {
    pub fn new(producers: Vec<Arc<dyn TrustFactProducer>>) -> Self {
        Self {
            producers,
            state: Mutex::new(EngineState::default()),
            deadline: None,
            audit: Mutex::new(None),
            cose_sign1_bytes: None,
            cose_sign1_message: None,
            cose_header_location: CoseHeaderLocation::Protected,
            per_fact_timeout: None,
            per_producer_timeout: None,
        }
    }

    pub fn with_cose_sign1_bytes(mut self, bytes: Arc<[u8]>) -> Self {
        self.cose_sign1_bytes = Some(bytes);
        self
    }

    pub fn with_cose_sign1_message(mut self, message: Arc<CoseSign1ParsedMessage>) -> Self {
        self.cose_sign1_message = Some(message);
        self
    }

    pub fn with_cose_header_location(mut self, loc: CoseHeaderLocation) -> Self {
        self.cose_header_location = loc;
        self
    }

    pub fn with_evaluation_options(mut self, options: &TrustEvaluationOptions) -> Self {
        if let Some(timeout) = options.overall_timeout {
            self.deadline = Some(Instant::now() + timeout);
        }
        self.per_fact_timeout = options.per_fact_timeout;
        self.per_producer_timeout = options.per_producer_timeout;
        self
    }

    pub fn with_deadline(mut self, deadline: Instant) -> Self {
        self.deadline = Some(deadline);
        self
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.deadline = Some(Instant::now() + timeout);
        self
    }

    pub fn enable_audit(&self) {
        *self.audit.lock() = Some(TrustDecisionAuditBuilder::default());
    }

    pub fn take_audit(&self) -> Option<TrustDecisionAudit> {
        self.audit.lock().take().map(|b| b.build())
    }

    pub fn get_facts<T: Any + Send + Sync>(
        &self,
        subject: &TrustSubject,
    ) -> Result<Vec<Arc<T>>, TrustError> {
        match self.get_fact_set::<T>(subject)? {
            TrustFactSet::Available(v) => Ok(v),
            TrustFactSet::Missing { .. } => Ok(Vec::new()),
            TrustFactSet::Error { message } => Err(TrustError::FactProduction(message)),
        }
    }

    pub fn get_fact_set<T: Any + Send + Sync>(
        &self,
        subject: &TrustSubject,
    ) -> Result<TrustFactSet<T>, TrustError> {
        self.ensure_produced(subject, FactKey::of::<T>())?;

        let state = self.state.lock();
        if let Some(message) = state.errors.get(&(subject.id, TypeId::of::<T>())) {
            return Ok(TrustFactSet::Error {
                message: message.clone(),
            });
        }

        if let Some(reason) = state.missing.get(&(subject.id, TypeId::of::<T>())) {
            return Ok(TrustFactSet::Missing {
                reason: reason.clone(),
            });
        }

        let by_type = state
            .facts
            .get(&subject.id)
            .and_then(|m| m.get(&TypeId::of::<T>()));
        let Some(values) = by_type else {
            return Ok(TrustFactSet::Available(Vec::new()));
        };

        let mut out = Vec::with_capacity(values.len());
        for v in values {
            // SAFETY: fact vectors are inserted by TypeId.
            if let Ok(v) = v.clone().downcast::<T>() {
                out.push(v);
            }
        }
        Ok(TrustFactSet::Available(out))
    }

    pub fn has_fact<T: Any + Send + Sync>(
        &self,
        subject: &TrustSubject,
    ) -> Result<bool, TrustError> {
        Ok(!self.get_facts::<T>(subject)?.is_empty())
    }

    pub fn ensure_fact(&self, subject: &TrustSubject, key: FactKey) -> Result<(), TrustError> {
        self.ensure_produced(subject, key)
    }

    fn ensure_produced(&self, subject: &TrustSubject, key: FactKey) -> Result<(), TrustError> {
        if self.deadline.map(|d| Instant::now() >= d).unwrap_or(false) {
            return Err(TrustError::DeadlineExceeded);
        }

        {
            let state = self.state.lock();
            if state.produced.contains(&(subject.id, key.type_id)) {
                return Ok(());
            }
        }

        // Find all producers that may provide this fact type.
        let producers: Vec<_> = self
            .producers
            .iter()
            .filter(|p| p.provides().iter().any(|k| k.type_id == key.type_id))
            .cloned()
            .collect();

        let per_fact_deadline = self.per_fact_timeout.map(|t| Instant::now() + t);

        for producer in producers {
            let per_producer_deadline = self.per_producer_timeout.map(|t| Instant::now() + t);
            let mut ctx = TrustFactContext {
                subject,
                engine: self,
                requested_fact: key,
                per_fact_deadline,
                per_producer_deadline,
            };
            producer
                .produce(&mut ctx)
                .map_err(|e| TrustError::FactProduction(format!("{}: {}", producer.name(), e)))?;

            if ctx.deadline_exceeded() {
                return Err(TrustError::DeadlineExceeded);
            }
        }

        let mut state = self.state.lock();
        state.produced.insert((subject.id, key.type_id));
        Ok(())
    }

    fn mark_produced(&self, subject: SubjectId, key: FactKey) {
        let mut state = self.state.lock();
        state.produced.insert((subject, key.type_id));
    }

    fn mark_missing(&self, subject: SubjectId, type_id: TypeId, reason: String) {
        let mut state = self.state.lock();
        state.missing.insert((subject, type_id), reason);
    }

    fn mark_error(&self, subject: SubjectId, type_id: TypeId, message: String) {
        let mut state = self.state.lock();
        state.errors.insert((subject, type_id), message);
    }

    fn observe_fact<T: Any + Send + Sync>(&self, subject: SubjectId, fact: T) {
        let mut state = self.state.lock();
        let entry = state
            .facts
            .entry(subject)
            .or_default()
            .entry(TypeId::of::<T>())
            .or_default();
        entry.push(Arc::new(fact));

        if let Some(builder) = self.audit.lock().as_mut() {
            builder.push(AuditEvent::FactObserved {
                subject,
                fact_type: std::any::type_name::<T>(),
            });
        }
    }
}
