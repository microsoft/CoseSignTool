# CoseSign1.Validation.TrustFrontends.Conformance

Reusable conformance test suite that every CoseSignTool trust-policy frontend must pass to be ship-eligible. Implements the eight properties of §6.5.10 of the trust-policy translation contract.

## Why this package exists

A frontend is a translator from a user-authored document (`.coseTrustPolicy.json`, future `.rego`, future `.cel`) into the canonical `TrustPolicySpec` IR. The IR drives the trust validator at runtime; if a frontend produces non-deterministic, capability-blind, or unbounded translations, the security boundary of every consumer that loads its documents is degraded.

Per §6.5.10, frontends that fail any of the eight properties are **not ship-eligible**. This package is the gate. A new frontend (cose-tp-rego/v1, cose-tp-cel/v1, …) opts in by:

1. Adding a project reference to `CoseSign1.Validation.TrustFrontends.Conformance`.
2. Implementing `IConformanceFrontendAdapter<TDocument>` over its parsed-document type.
3. Deriving a sealed test fixture from `FrontendConformanceTestBase<TDocument>`; NUnit auto-discovers the inherited `[Test]` methods.
4. Shipping the canonical fixture set under `tests/conformance/fixtures/<frontend-id>/` (see *Fixture conventions* below).

That's it. The eight `Conformance_N_*` tests light up automatically and run as part of the frontend's existing `dotnet test` invocation.

## The eight ship-eligibility properties (§6.5.10)

| # | Property | What it asserts | Bug class it catches |
|---|----------|------------------|----------------------|
| 1 | **Determinism** | Translate `(doc, params)` 1000× → byte-identical canonical IR | Hash-key drift in the LRU translator cache; non-deterministic ordering of dictionary keys; latent re-emit of comments |
| 2 | **Attribute fidelity** | Every fact registered in `IFactRegistry` has a fixture for **both** D1 predicate forms (`property` shorthand AND universal `path+operator`); both compile cleanly; both agree on synthetic projections | A new fact is registered without a frontend example; a frontend silently downgrades the property-shorthand form to a no-op |
| 3 | **Reject untranslatable** | Free-text search, unknown fact ids, unsupported operators → Error diagnostic | A frontend "best-efforts" through nonsense, leaving the validator with a denied-by-default rule the author never intended |
| 4 | **Bounded runtime** | 1KB document, p99 ≤ 10 ms, mean ≤ 5 ms (statistical) | Schema-compilation regression; accidental O(n²) walk; lock-contention on a shared cache |
| 5 | **Capability-aware** | When `AvailableFacts` excludes a referenced id and `AllowUnknownFacts=false` → TPX200 | A frontend silently emits a fact reference the host can't resolve, surfacing as a denied rule at trust-eval time instead of at policy-load time |
| 6 | **Parameter substitution** | Same document + different `$param` values → different IRs | Parameter binding is a no-op; substitution corrupts a downstream cache key |
| 7 | **Schema validation** | Malformed document → diagnostic with non-null `SourceLocation` | Frontend swallows the parse exception; user has no way to navigate to the offending site |
| 8 | **Cross-frontend equivalence** | Same logical policy expressed in any pair of frontends → equal canonical IRs | A frontend silently encodes Rego-specific semantics into the IR that the JSON frontend never produces; an "equivalent" Rego policy actually denies what the JSON one allows |

## Architectural footing — Phase 4 (this package)

This package depends on `CoseSign1.Validation.Trust.PlanPolicy.Spec` for the IR types, the canonical-JSON serializer (the byte-equality oracle), and the attribute-driven fact registry (the source of truth for §6.5.10 #2's per-fact matrix).

> **Architectural note on `CoseSign1.Validation.Trust.Contracts`.** Phase 2 (frontend-json) anticipated extracting the frontend abstraction (`ICoseTrustPolicyFrontend<TDocument>`, `TrustPolicyTranslationContext/Result/Diagnostic`, `FactCapabilities`) into a no-deps `Trust.Contracts` project so the abstraction layer sits above the IR. Phase 4 evaluated the move and **deferred it** for one well-understood reason: `TrustPolicyTranslationResult.Spec` is typed as `TrustPolicySpec`, which itself sits at the bottom of a tall dependency stack (`Validation` core → `Certificates` → `Transparent.MST` through fact predicate composition). A clean Contracts project that has no Spec reference would require lifting the entire `TrustPolicySpec` discriminated-union surface (and its predicate / combinator / requirement subtrees, plus the canonical-JSON serializer) into the new project — a multi-day refactor touching ~30 source files and every consuming namespace. The reusable-conformance contract Phase 4 ships does not require the move (the conformance package's downstream consumers are test projects, which already reference Spec). The architectural cleanup is queued as a follow-up commit; landing it after Rego (Phase 5a) gives the new frontend a chance to validate the boundary placement before we lock it in.

## Fixture conventions

Each frontend ships its fixtures under a frontend-specific subfolder; the conformance package resolves them by **logical name**. The naming convention is captured in `ConformanceFixtureNaming`:

| Logical name | Purpose |
|--------------|---------|
| `facts/<fact-id-with-_-instead-of-/>.property` | Per-fact, property-assertion form (§6.5.10 #2). `is_trusted: true` shorthand for boolean facts; analogous shorthands for string / number / array facts. |
| `facts/<fact-id-with-_-instead-of-/>.path-operator` | Per-fact, universal path+operator form. `{operator: Equals, path: "$.is_trusted", value: true}` for the same logical predicate. |
| `untranslatable.free-text-search` | Document attempting full-text search over a fact value. |
| `untranslatable.unknown-fact` | References a fact id not in the registry. |
| `untranslatable.unknown-operator` | Uses an operator not in the closed `PredicateOperator` set. |
| `capability.missing-fact` | A well-formed fixture whose fact id is excluded from the host's `AvailableFacts`. |
| `schema.malformed` | Raw text that does not parse as the frontend's input language (e.g. unbalanced braces in JSON). |
| `schema.shape-violation` | Well-formed text that does not match the frontend's canonical schema. |
| `parametric.host-baseline` | Document with a `$param` reference (parameter `trusted_host`) used as the §6.5.10 #6 substitution exemplar. |
| `parametric.host-alternate` | A second parametric document, used to assert the binder isolates parameter scope. |
| `perf.representative-1kb` | A representative ≤ 1 KB document. The §6.5.10 #4 perf gate translates this 100× after warm-up and asserts p99 ≤ 10 ms / mean ≤ 5 ms. |
| `cross.canonical-policy` | A logical "trust the chain AND require an MST receipt" policy used as the cross-frontend equivalence pivot (§6.5.10 #8). When a second frontend opts in, its `cross.canonical-policy` MUST translate byte-equal to ours. |

Where a fixture is shipped as a file rather than an in-memory string, the canonical extension is `.coseTrustPolicy.json` for the JSON frontend; future frontends pick a stable extension (`.coseTrustPolicy.rego`, `.coseTrustPolicy.cel`, …) and document it in their own README.

## Adopting the suite

```csharp
[TestFixture]
public sealed class JsonFrontendConformanceTests
    : FrontendConformanceTestBase<JsonDocument>
{
    protected override IConformanceFrontendAdapter<JsonDocument> CreateAdapter()
        => new JsonConformanceAdapter();
}
```

NUnit will discover `Conformance_1_Determinism_…` through `Conformance_8_CrossFrontendEquivalence_…` automatically. The adapter's `ProvidedFixtureNames` set is asserted to contain every required logical name in `Conformance_2_AttributeFidelity_…`; an adapter that forgets to ship a fixture surfaces the omission as a test failure naming the missing logical name and fact id.

For cross-frontend pairs (Phase 5a Rego → JSON):

```csharp
[TestFixture]
public sealed class JsonRegoCrossEquivalenceTests
    : CrossFrontendEquivalenceTestBase<JsonDocument, RegoDocument>
{
    protected override IConformanceFrontendAdapter<JsonDocument> CreateAdapterA()
        => new JsonConformanceAdapter();

    protected override IConformanceFrontendAdapter<RegoDocument> CreateAdapterB()
        => new RegoConformanceAdapter();
}
```

## Failure-message philosophy

Every assertion message names the logical fixture, the failing property, and (where applicable) the rendered canonical IRs of both sides. CI agents that report a perf-gate failure include the full sample summary (mean, p99, min, max, n) so a developer can tell whether the regression is an outlier (raise n / re-run on a quieter agent) or a steady-state shift (real bug). The conformance package never prints "assertion failed" without context.

## Versioning

This package is **part of the trust-policy translation contract**. Backward-incompatible changes to the contract (new conformance properties, stricter assertions on existing properties, fixture-name renames) ship as a major-version bump and are coordinated with every dependent frontend's test project. Adding a new fact (which expands the §6.5.10 #2 matrix) is a minor bump — every frontend rebuilds against the new package and must add the new pair of fixtures before the next release.
