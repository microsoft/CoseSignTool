// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Fact production and caching.
//!
//! Trust rules evaluate over facts. Facts are produced lazily on demand:
//! - a plan requests a fact type
//! - the engine asks each registered producer to produce it (or mark missing/error)
//! - the engine caches observed facts per subject and fact type

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
    /// Facts are available (may be empty).
    Available(Vec<Arc<T>>),
    /// Fact type is missing for this subject (with an explanatory reason).
    Missing { reason: String },
    /// Fact production failed (message is intended for diagnostics).
    Error { message: String },
}

impl<T> TrustFactSet<T> {
    /// Returns `true` if this fact set is explicitly marked missing.
    pub fn is_missing(&self) -> bool {
        matches!(self, TrustFactSet::Missing { .. })
    }

    /// Returns the available facts, or `None` if the type was missing or errored.
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
    /// Creates a key for a concrete fact type.
    pub fn of<T: Any + Send + Sync>() -> Self {
        Self {
            type_id: TypeId::of::<T>(),
            name: std::any::type_name::<T>(),
        }
    }
}

/// Produces one or more fact types.
///
/// Producers should be deterministic and side-effect free when possible.
/// If expensive work is required (network, IO), respect deadlines via `ctx.deadline_exceeded()`.
pub trait TrustFactProducer: Send + Sync {
    /// Stable producer name for audit logs and diagnostics.
    fn name(&self) -> &'static str;

    /// Produce facts into the given context.
    fn produce(&self, ctx: &mut TrustFactContext<'_>) -> Result<(), TrustError>;

    /// Advertise which fact types this producer may create.
    fn provides(&self) -> &'static [FactKey];
}

/// Context passed to a fact producer.
///
/// Producers write facts using `observe` and must call `mark_produced` for the requested type.
#[derive(Clone)]
pub struct TrustFactContext<'a> {
    subject: &'a TrustSubject,
    engine: &'a TrustFactEngine,
    requested_fact: FactKey,
    per_fact_deadline: Option<Instant>,
    per_producer_deadline: Option<Instant>,
}

impl<'a> TrustFactContext<'a> {
    /// Subject currently being produced.
    pub fn subject(&self) -> &TrustSubject {
        self.subject
    }

    /// The fact type currently being requested.
    pub fn requested_fact(&self) -> FactKey {
        self.requested_fact
    }

    /// Raw COSE bytes, if provided by the caller.
    pub fn cose_sign1_bytes(&self) -> Option<&[u8]> {
        self.engine.cose_sign1_bytes.as_deref()
    }

    /// Parsed COSE message, if provided by the caller.
    pub fn cose_sign1_message(&self) -> Option<&CoseSign1ParsedMessage> {
        self.engine.cose_sign1_message.as_deref()
    }

    /// Which COSE header location rules should consult.
    pub fn cose_header_location(&self) -> CoseHeaderLocation {
        self.engine.cose_header_location
    }

    /// Returns true if the engine deadline has been exceeded.
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

    /// Record an observed fact for this subject.
    pub fn observe<T: Any + Send + Sync>(&self, fact: T) -> Result<(), TrustError> {
        if self.deadline_exceeded() {
            return Err(TrustError::DeadlineExceeded);
        }
        self.engine.observe_fact(self.subject.id, fact);
        Ok(())
    }

    /// Mark a fact type as missing for this subject.
    pub fn mark_missing<T: Any + Send + Sync>(&self, reason: impl Into<String>) {
        self.engine
            .mark_missing(self.subject.id, TypeId::of::<T>(), reason.into());
    }

    /// Mark a fact type as error for this subject.
    pub fn mark_error<T: Any + Send + Sync>(&self, message: impl Into<String>) {
        self.engine
            .mark_error(self.subject.id, TypeId::of::<T>(), message.into());
    }

    /// Mark a specific fact key as produced.
    pub fn mark_produced(&self, key: FactKey) {
        self.engine.mark_produced(self.subject.id, key);
    }

    /// Get facts for a subject, returning empty when missing.
    pub fn get_facts<T: Any + Send + Sync>(
        &self,
        subject: &TrustSubject,
    ) -> Result<Vec<Arc<T>>, TrustError> {
        self.engine.get_facts::<T>(subject)
    }

    /// Get facts for a subject, including missing/error information.
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

/// Fact engine responsible for:
/// - invoking producers on demand
/// - caching observed facts per subject/type
/// - enforcing deadlines/timeouts
/// - optionally collecting an audit trail
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
    /// Creates a new engine with a fixed set of fact producers.
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

    /// Provide the encoded COSE bytes to producers.
    pub fn with_cose_sign1_bytes(mut self, bytes: Arc<[u8]>) -> Self {
        self.cose_sign1_bytes = Some(bytes);
        self
    }

    /// Provide the parsed COSE message to producers.
    pub fn with_cose_sign1_message(mut self, message: Arc<CoseSign1ParsedMessage>) -> Self {
        self.cose_sign1_message = Some(message);
        self
    }

    /// Set the preferred COSE header location.
    pub fn with_cose_header_location(mut self, loc: CoseHeaderLocation) -> Self {
        self.cose_header_location = loc;
        self
    }

    /// Configure timeouts/deadlines from evaluation options.
    pub fn with_evaluation_options(mut self, options: &TrustEvaluationOptions) -> Self {
        if let Some(timeout) = options.overall_timeout {
            self.deadline = Some(Instant::now() + timeout);
        }
        self.per_fact_timeout = options.per_fact_timeout;
        self.per_producer_timeout = options.per_producer_timeout;
        self
    }

    /// Sets an absolute deadline after which fact production stops with `DeadlineExceeded`.
    pub fn with_deadline(mut self, deadline: Instant) -> Self {
        self.deadline = Some(deadline);
        self
    }

    /// Sets an overall timeout relative to now.
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.deadline = Some(Instant::now() + timeout);
        self
    }

    /// Enable audit collection for subsequent evaluations.
    pub fn enable_audit(&self) {
        *self.audit.lock() = Some(TrustDecisionAuditBuilder::default());
    }

    /// Take the current audit, if enabled.
    pub fn take_audit(&self) -> Option<TrustDecisionAudit> {
        self.audit.lock().take().map(|b| b.build())
    }

    /// Returns the available facts for a subject.
    ///
    /// If the fact type is missing, this returns an empty list. If production failed, this
    /// returns an error.
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

    /// Returns the fact set for a subject, including missing/error state.
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

    /// Returns `true` if at least one fact of the requested type exists for the subject.
    pub fn has_fact<T: Any + Send + Sync>(
        &self,
        subject: &TrustSubject,
    ) -> Result<bool, TrustError> {
        Ok(!self.get_facts::<T>(subject)?.is_empty())
    }

    /// Ensures a specific fact type has been produced for a subject.
    ///
    /// This does not guarantee that any facts exist; it only runs producers and caches a
    /// produced/missing/error state.
    pub fn ensure_fact(&self, subject: &TrustSubject, key: FactKey) -> Result<(), TrustError> {
        self.ensure_produced(subject, key)
    }

    /// Runs eligible producers for the requested fact type, once per subject/type.
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

    /// Marks a specific subject/type as produced.
    fn mark_produced(&self, subject: SubjectId, key: FactKey) {
        let mut state = self.state.lock();
        state.produced.insert((subject, key.type_id));
    }

    /// Marks a specific subject/type as missing.
    fn mark_missing(&self, subject: SubjectId, type_id: TypeId, reason: String) {
        let mut state = self.state.lock();
        state.missing.insert((subject, type_id), reason);
    }

    /// Marks a specific subject/type as errored.
    fn mark_error(&self, subject: SubjectId, type_id: TypeId, message: String) {
        let mut state = self.state.lock();
        state.errors.insert((subject, type_id), message);
    }

    /// Records an observed fact value for the subject and optionally emits an audit event.
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
