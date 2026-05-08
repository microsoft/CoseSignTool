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
