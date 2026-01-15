# Trust Contracts

This document describes the trust “contracts” used by the V2 **Facts + Rules** trust model.

## Current state

The staged validator (`CoseSign1Validator`) uses the Facts + Rules model as its active trust mechanism:

- Trust evaluation runs as **stage 2** (“Signing Key Trust”) and is evaluated using `CompiledTrustPlan`.
- `TrustEvaluationOptions.BypassTrust` is honored.
- Trust evaluation can produce a deterministic `TrustDecisionAudit` and attaches it to stage metadata.

See:

- [Trust Plan Deep Dive](../guides/trust-policy.md)
- [Audit and Replay](../guides/audit-and-replay.md)

## Core identifiers

These types establish stable identities for trust evaluation:

- `TrustSubjectId`: a stable, content-addressed identifier (SHA-256) for a trust subject.
- `TrustIds`:
  - `MessageId`: SHA-256 of the entire encoded COSE_Sign1 bytes (including unprotected header).
  - `CounterSignatureId`: SHA-256 of the raw counter-signature structure bytes.
- `TrustSubject` / `TrustSubjectKind`: the entity being reasoned about (message, signing key, counter-signature, etc.).

## Facts

Facts are produced lazily, on-demand during rule evaluation.

- `TrustFactSet<TFact>` / `TrustFactMissing`: multi-valued facts with explicit missing-reason handling.
- `IMultiTrustFactProducer`: a producer that can provide one or more fact types.
- `TrustFactEngine`: orchestrates fact production with per-validation memoization.

Budgets/timeouts and bypass behavior are modeled via `TrustEvaluationOptions`.

## Rules and plan

Rules are combined into a compiled plan:

- `TrustRule`: base type for rule evaluation.
- `TrustRules`: combinators and quantifiers (e.g., `And/Or/Not/Implies`, `AnyFact<TFact>(...)`).
- `CompiledTrustPlan`: root rule + available fact producers; the object evaluated by the validator trust stage.

Trust packs (`ITrustPack`) contribute secure-by-default plan fragments (constraints, trust sources, vetoes).

## Audit

Trust evaluation can generate a deterministic audit record:

- `TrustDecisionAudit`: schema version + message ID + subject + decision + rule-evaluation trace + fact observations.

The staged validator attaches `TrustDecisionAudit` to the trust stage metadata under the key `nameof(TrustDecisionAudit)`.
