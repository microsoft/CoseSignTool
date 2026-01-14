# Trust contracts (work in progress)

This document tracks the incremental rollout of the TrustPlan / Facts + Rules trust model described in [V2/proposal.md](../../proposal.md).

## Current state

The default trust evaluation in `CoseSign1.Validation` is still the assertion-based `TrustPolicy` model.

## Contracts added (Step 3)

These types are the foundation for the upcoming trust engine:

- `TrustSubjectId`: a stable, content-addressed identifier (SHA-256) for a trust subject.
- `TrustIds`:
  - `MessageId` = SHA-256 of the entire encoded COSE_Sign1 bytes (including unprotected header).
  - `CounterSignatureId` = SHA-256 of the raw counter-signature structure bytes.
- `TrustSubject` / `TrustSubjectKind`: describes the entity being reasoned about (message, counter-signature, signing keys, etc.).
- `TrustFactSet<TFact>` / `TrustFactMissing`: models multi-valued facts with explicit missing-reason handling (no exception-driven control flow).
- `TrustEvaluationOptions`: budgets/limits and `BypassTrust` (bypass is implemented when the staged validator is wired to TrustPlan).

## What comes next

- Wire `CoseSign1Validator` trust stage to use `TrustPlan` (and honor `BypassTrust`).
- Introduce an auditable decision trace model (`TrustDecisionAudit`).

## Fact production (Step 4)

The package now includes a minimal, test-covered fact production layer:

- `TrustFactEngine`: per-validation memoization keyed by `(SubjectId, FactType)`.
- `IMultiTrustFactProducer`: producers advertise one or more fact types and are invoked by requested fact type.
- Producer-owned cross-validation caching is supported via `TrustFactContext.MemoryCache` and `TrustFactCacheKey` keyed by `{MessageId, SubjectId, FactType}`.
- Budgets/timeouts are modeled via `TrustEvaluationOptions` and result in explicit missing reasons (`TrustFactMissingCodes`).

## Rules + plan (Step 5)

The package now includes an initial rule layer and plan compilation surface:

- `TrustRule`: base type for rules.
- `TrustRules`: factory helpers for boolean combinators and quantifiers:
  - `And/Or/Not/Implies`
  - `AnyFact<TFact>(...)` with separate messages for missing vs predicate failure
- `OnEmptyBehavior`: controls how quantifiers behave when a fact set is available but empty.
- `TrustPlan`: a compiled plan consisting of a root rule plus an associated set of `IMultiTrustFactProducer` instances.
- `TrustPlan.CompileDefaults(IServiceProvider)`: builds a plan from DI using:
  - `ITrustPlanDefaultsProvider` (returns three fragments: constraints, sources, vetoes)
  - `IEnumerable<IMultiTrustFactProducer>` (fact producers available to the plan)

Status:
- These types are implemented and test-covered.
- They are not yet wired into the staged validator; the active trust stage remains `TrustPolicy` until the integration step lands.
