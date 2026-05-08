# `cose_sign1_trustfrontends_conformance`

Phase 4 (np-conformance) deliverable for the native Rust CoseSignTool
trust-policy port. Mirrors the .NET
`CoseSign1.Validation.TrustFrontends.Conformance` train delivery.

This crate ships a **reusable conformance test harness** that every shipping
CoseSign1 trust-policy frontend MUST pass to be ship-eligible. The contract
is the 8-property matrix from §6.5.10 of the eval doc.

## The 8-property contract

| #   | Property                     | What it locks                                                                                                           |
| --- | ---------------------------- | ----------------------------------------------------------------------------------------------------------------------- |
| 1   | **Determinism**              | Translating the same `(doc, params)` 1024× produces byte-identical canonical-IR JSON every time.                        |
| 2   | **Attribute fidelity**       | Every fact id the host registers has a per-fact fixture that translates to a `RequireFact { fact_id: <id> }` node.      |
| 3   | **Reject untranslatable**    | Documents reaching for free-text search, unknown fact ids, or unsupported operators surface `TPXxxx` `Error` diagnostics. |
| 4   | **Bounded runtime**          | A representative ≤1 KiB document translates with **p99 ≤ 10 ms** over a statistically meaningful sample.                |
| 5   | **Capability-aware**         | When `FactCapabilities` lacks a required fact id AND `allow_unknown_facts == false`, the translator emits `TPX200`.     |
| 6   | **Parameter substitution**   | The same parameterised document binds to different IRs under different parameter sets; the unbound spec retains `$param`. |
| 7   | **Schema validation**        | Malformed JSON surfaces `TPX001` with a `SourceLocation`; shape-violating documents surface `TPX100`.                   |
| 8   | **Cross-frontend equivalence** | Same logical policy in two frontends → byte-equal canonical-IR JSON. (`(json, json)` degenerate today; `(json, rego)` after Phase 5a.) |

A frontend that fails any property is **not ship-eligible** — anti-deferral
rule from the dispatch contract.

## How to opt a frontend in

Implement [`ConformanceAdapter`] for the new frontend in its own test crate:

```rust
use cose_sign1_trustfrontends_conformance::ConformanceAdapter;
use cose_sign1_trust_policy_spec::CoseTrustPolicyFrontend;
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

pub struct MyFrontendAdapter { /* ... */ }

impl ConformanceAdapter<MyDocument> for MyFrontendAdapter {
    fn create_frontend(&self) -> Box<dyn CoseTrustPolicyFrontend<MyDocument>> { /* ... */ }
    fn load_document(&self, path: &Path) -> MyDocument { /* ... */ }
    fn fixture_extension(&self) -> &'static str { "coseTrustPolicy.myext" }
    fn fixture_root(&self) -> PathBuf { /* points at this crate's fixtures/ */ }
    fn registered_fact_ids(&self) -> BTreeSet<String> { /* host's id set */ }
}
```

Drop fixtures into `fixtures/` (sibling to the existing JSON fixtures) and
call the per-property `run_conformance_*` functions inside `#[test]`
functions:

```rust
#[test]
fn property_1_determinism() {
    cose_sign1_trustfrontends_conformance::run_conformance_1_determinism(&MyFrontendAdapter::default());
}
```

For convenience, [`run_conformance_all`] wires every property in one call.

## Fixture layout

The fixture root for the JSON frontend lives under
`validation/trustfrontends/conformance/fixtures/`:

```text
fixtures/
├── per_fact/
│   ├── x509-chain-trusted--v1.coseTrustPolicy.json
│   ├── ... (one per registered fact)
│   └── unknown-counter-signature-bytes--v1.coseTrustPolicy.json
├── untranslatable/
│   ├── free_text_search.coseTrustPolicy.json
│   ├── unknown_fact.coseTrustPolicy.json
│   └── unknown_operator.coseTrustPolicy.json
├── capability/
│   └── missing_fact.coseTrustPolicy.json
├── schema/
│   ├── malformed_text.coseTrustPolicy.json
│   └── shape_violation.coseTrustPolicy.json
├── parametric/
│   ├── host_baseline.coseTrustPolicy.json
│   ├── host_baseline.params.json
│   ├── host_alternate.coseTrustPolicy.json
│   └── host_alternate.params.json
├── perf/
│   └── representative_1kb.coseTrustPolicy.json   (≤ 1 KiB)
└── cross/
    └── canonical_policy/
        ├── canonical_policy.coseTrustPolicy.json
        └── canonical_ir.expected.json            (cross-port golden)
```

### Fact-id filename encoding

Fact ids contain `/` (e.g. `x509-chain-trusted/v1`) which can't land in a
filesystem path on Windows. The harness encodes `/` as `--`. The pack regex
`^[a-z][a-z0-9-]*/v[0-9]+$` never produces two consecutive hyphens, so the
encoding is collision-free and round-trippable. See
[`fixtures::encode_fact_id_for_filename`].

### Why each property exists

- **#1 Determinism** catches frontend caches that smooth over
  hash-iteration-order non-determinism. The harness creates a fresh
  frontend per call so per-process LRU caches cannot mask the bug.
- **#2 Attribute fidelity** catches "we forgot to teach the frontend about
  this fact id". One missing fixture → one failing test, every time.
- **#3 Reject untranslatable** catches translators that "do the best they
  can" with malformed input. Trust policies must fail closed.
- **#4 Bounded runtime** catches the schema-validator-catastrophic-backtrack
  class of bugs. The 10 ms p99 target is tight enough to surface them.
- **#5 Capability-aware** catches "we shipped a fact reference our host
  cannot evaluate". Caught at translate time, not at first-real-trust-eval.
- **#6 Parameter substitution** catches translators that pre-bind eagerly
  (violating D5). Pre-bind specs MUST carry `$param` literals.
- **#7 Schema validation** catches missing-line/column tracking. Diagnostics
  without locations are unactionable.
- **#8 Cross-frontend equivalence** catches IR drift across frontends. The
  same logical policy must produce the same canonical IR regardless of how
  it was authored.

## Performance gate

§6.5.10 #4 requires p99 ≤ 10 ms over a representative ≤ 1 KiB document. The
crate ships two implementations:

- **Built-in** (always-on `#[test]`): hand-rolled
  `std::time::Instant` sampling, nearest-rank p99. Default
  `cargo test -p cose_sign1_trustfrontends_conformance` runs this.
- **Criterion** (opt-in via `--features criterion-perf`): richer reporting,
  regression history, HTML output. Default builds do not pull Criterion as
  a dependency.

Sample size ([`PERF_SAMPLE_COUNT`]) is 256 with [`PERF_WARMUP_COUNT`] = 16
warm-up runs. The first translate pays for the lazy `OnceLock` schema
compilation; we discard it.

### Why p99 ≤ 10 ms?

The .NET reference target is 10 ms p99 — set so a service authoring a trust
policy can re-evaluate per-request without budget concerns. The Rust target
matches verbatim. On slow CI agents the gate may flake ±1 ms; if real
production-tier hardware persistently misses 10 ms the gate is the right
forcing function — the JSON frontend should be tightened before relaxing the
target.

## Cross-port equivalence

Phase 2's `cross_port_schema.rs` (in the JSON frontend crate) asserts the
embedded `cose-tp/v1.json` schema is byte-equal to the .NET copy. Phase 4
adds a stronger lock: the **canonical-IR JSON** produced by the Rust JSON
frontend MUST match the committed `canonical_ir.expected.json` golden file
byte-for-byte after line-ending normalisation.

The golden was produced by the Rust frontend itself in Phase 4 (the .NET
frontend's JSON path is on the v2_clean_slate train). When the .NET frontend
ships, its conformance suite asserts byte-equality against the same fixture;
if the two diverge, one port has drifted and the diff is one git-blame away.

Cross-language IR equivalence (a Rust frontend producing the same canonical
IR as a Rego frontend on the same fixture) is enforced via §6.5.10 #8 once
Phase 5a (np-frontend-rego) lights up the second frontend.

To regenerate the golden after an intentional IR change:

```pwsh
cargo test -p cose_sign1_trustfrontends_conformance --test cross_port_canonical_ir regenerate_golden -- --ignored
```

## Coverage

Per Rust D11 amendment: this crate's coverage gate is 90 % per-crate. Run:

```pwsh
cd native/rust
.\collect-coverage.ps1 -Package cose_sign1_trustfrontends_conformance -FailUnderLines 90
```

## What this crate does NOT do

- Does NOT add a Rego frontend — Phase 5a (np-frontend-rego).
- Does NOT add an FFI surface — Phase 4.5 (np-ffi).
- Does NOT mutate prior phase APIs (`trust_policy_spec`,
  `trustfrontends_json`, `validation/primitives`).
- Does NOT enforce cross-language IR equivalence beyond the embedded golden;
  that's a separate workstream that lights up when both Rust + .NET
  frontends are in flight on the same train.

[`ConformanceAdapter`]: src/adapter.rs
[`run_conformance_all`]: src/harness.rs
[`fixtures::encode_fact_id_for_filename`]: src/fixtures.rs
[`PERF_SAMPLE_COUNT`]: src/perf.rs
[`PERF_WARMUP_COUNT`]: src/perf.rs
