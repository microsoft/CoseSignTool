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

## Document-driven trust policies

In addition to the code-driven Facts + Rules surface above, V2 supports loading a trust policy from a versioned text document. The same `CompiledTrustPlan` is the runtime; only the input path differs.

Architecture:

```
.coseTrustPolicy.json   ─┐
                         │   ICoseTrustPolicyFrontend<TDocument>
.coseTrustPolicy.rego   ─┤   (one per syntax — translates to IR)
                         │
                         ▼
              TrustPolicySpec  (canonical IR: serializable, deterministic)
                         │
                         ▼
              TrustPolicySpec.CompileFromSpec(IFactRegistry, IServiceProvider)
                         │
                         ▼
              CompiledTrustPlan  (existing — Facts + Rules evaluator)
```

The IR is the contract every frontend MUST produce. Two frontends ship today:

- `cose-tp-json/v1` — canonical reference frontend (JSON / JSONC).
- `cose-tp-rego/v1` — constrained-Rego subset for OPA-aligned shops; translates onto the same IR via the JSON frontend's walker, so byte-equality is a property of construction.

Override semantics (design decision D8): when the verify command receives `--trust-policy <path>`, the document is the **sole** source of trust requirements; pack defaults (`ITrustPack.GetDefaults()`) are bypassed. Pack fact producers remain registered so the document's `RequireFact` references resolve at evaluation time. Without `--trust-policy`, existing pack-default behaviour is unchanged.

The conformance contract every frontend MUST satisfy (8 properties: determinism, attribute fidelity, reject-untranslatable, bounded runtime, capability-aware, parameter substitution, schema validation, cross-frontend equivalence) is documented in the conformance package: [CoseSign1.Validation.TrustFrontends.Conformance/README.md](../../CoseSign1.Validation.TrustFrontends.Conformance/README.md).

For the full design rationale (D1–D11 decisions, IR shape, predicate language, parameter binding, audit provenance), see the eval doc that drove the implementation: [`eval-trust-policy-translation-contract.md`](https://github.com/microsoft/CoseSignTool/blob/users/jstatia/v2_clean_slate/V2/docs/architecture/eval-trust-policy-translation-contract.md) (when committed) or the project READMEs:

- [CoseSign1.Validation.Trust.PlanPolicy.Spec](../../CoseSign1.Validation.Trust.PlanPolicy.Spec/README.md) — the IR + canonical JSON serialiser
- [CoseSign1.Validation.TrustFrontends.Json](../../CoseSign1.Validation.TrustFrontends.Json/README.md) — JSON frontend grammar + diagnostic-code reference
- [CoseSign1.Validation.TrustFrontends.Rego](../../CoseSign1.Validation.TrustFrontends.Rego/README.md) — Rego accept-list / reject-list

Operator-facing usage is documented in the [Trust Plan Deep Dive guide](../guides/trust-policy.md#document-driven-trust-policy) and the [verify command reference](../cli/verify.md).

## Core identifiers

These types establish stable identities for trust evaluation:

- `TrustSubjectId`: a stable, content-addressed identifier (SHA-256) for a trust subject.
- `TrustIds`:
  - `MessageId`: SHA-256 of the entire encoded COSE_Sign1 bytes (including unprotected header).
  - `CounterSignatureId`: SHA-256 of the raw counter-signature structure bytes.
- `TrustSubject` / `TrustSubjectKind`: the entity being reasoned about (message, signing key, counter-signature, etc.).

In practice, counter-signature subjects are used to model receipt-like artifacts that are attached to a message (for example, MST transparency receipts) so policies can be expressed per-receipt.

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
