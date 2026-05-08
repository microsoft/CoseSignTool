# CoseSign1.Validation.Trust.PlanPolicy.Spec

Phase 1 of the trust-policy translation contract: a serializable, deterministic
data-record IR (`TrustPolicySpec`) for trust policies, plus a compiler that
lowers it onto the existing fluent `TrustPlanPolicy` builder without changing
that public surface.

The Spec is the canonical translation target every frontend (JSON, Rego, CEL)
must produce. The Spec is decoupled from the IR by design — frontends never
build a `TrustPlanPolicy` directly; they emit a `TrustPolicySpec` and the
compiler in this package produces the runtime plan.

This package does **not** ship a frontend. JSON arrives in Phase 2.

## Scope

- `TrustPolicySpec` discriminated union (sealed records, `[JsonPolymorphic]`).
- `FactPredicateSpec` hybrid (path+operator universal + property-assertion sugar).
- `ParameterRef` placeholder + `Bind(parameters)` post-parse pass.
- `IFactRegistry` interface + a temporary `StaticFactRegistry` (replaced by an
  attribute-driven registry in Phase 3).
- `TrustPolicySpecCompiler.Compile(spec, registry)` → `TrustPlanPolicy`.
- Canonical `System.Text.Json` round-trip with deterministic property + key
  ordering (the basis for D9's content-hash key).

## Out of scope (other phases)

- Reverse `TrustPlanPolicy` → `TrustPolicySpec` mapping (post-MVP).
- Attribute-driven `IFactRegistry` (Phase 3).
- JSON / Rego / CEL frontends (Phases 2 / 5a / 5b).

## Phase-1 ship contract

Phase 1 ships as an **internal IR** that enables Phase 2 (JSON frontend) and
Phase 4 (conformance suite). It is **not yet on the production COSE-verify
hot path** — consumers continue to use the existing fluent
`TrustPlanPolicy.Message / .PrimarySigningKey / .AnyCounterSignature` API
unchanged. Phase 4's CI-gated runtime conformance test (1 KB document → ≤ 10 ms
translation) is the production-readiness gate for the spec compiler.

The known per-evaluation `JsonNode` projection cost in
`PredicateLowerer.ProjectFact` is documented in the source and benchmarked at
the spec smoke level (see `PerformanceSmokeTests`); production-grade
optimisation (per-fact `ConditionalWeakTable` cache, expression-tree fast path
for simple `$.property` access) is reserved for Phase 4 once the conformance
suite is in place.

## Stability / SemVer

- The wire-format strings (discriminator names, JSON property names) declared in
  `ClassStrings.cs` are **frozen** as of this phase. Renaming any of them is a
  breaking change requiring a major version bump.
- The `[JsonPolymorphic]` discriminated union is closed: adding a new node type
  is a breaking change requiring a major version bump.
- `PredicateOperator` and the `TPX*` diagnostic-code namespace are
  **append-only** — new operators / new codes are minor-version additions.
- Fact ids carry an explicit `/v1` suffix (per design decision D2). Breaking
  shape changes ship as new ids (`x509-chain-trusted/v2`) rather than mutations.

