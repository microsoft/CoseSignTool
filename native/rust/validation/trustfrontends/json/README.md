# cose_sign1_trustfrontends_json

Canonical reference frontend (`cose-tp-json/v1`) for CoseSign1 trust policies — Phase 2
of the native Rust trust-policy port. Mirrors the .NET
`CoseSign1.Validation.TrustFrontends.Json` deliverable: parses, JSON-Schema-validates,
and translates user-authored `.coseTrustPolicy.json` documents into a
`cose_sign1_trust_policy_spec::TrustPolicySpec`.

## What this crate ships

- An `ICoseTrustPolicyFrontend<serde_json::Value>` implementation: `CoseTpJsonFrontend`.
- The canonical JSON Schema for `cose-tp-json/v1`, embedded via `include_bytes!` so
  translation has no runtime filesystem or network dependency.
- A post-translate `bind(parameters)` step (re-exported from
  `cose_sign1_trust_policy_spec`) per design decision **D5**.
- An in-process LRU translator cache (`TranslatorCache`, default capacity 32) backed by
  `moka::sync::Cache` and keyed by `blake3` hashes per design decisions **R4 / R5 /
  D9**.

The frontend satisfies the eight translation guarantees of §6.5.4: determinism,
totality, attribute fidelity, reject-what-you-can't-translate, capability-aware, no code
execution, bounded runtime, schema-checked output.

## Frontend identity

| Property              | Value                                                                           |
|-----------------------|---------------------------------------------------------------------------------|
| Frontend ID           | `cose-tp-json/v1`                                                               |
| Media types           | `application/x-cose-trust-policy+json`, `application/x-cose-trust-policy+json5` |
| File extension        | `.coseTrustPolicy.json`                                                         |
| Schema URL            | `https://raw.githubusercontent.com/microsoft/CoseSignTool/main/V2/schemas/cose-tp/v1.json` |
| JSON Schema draft     | 2020-12                                                                         |
| Recursion-depth cap   | 64 (configurable via `CoseTpJsonOptions::max_depth`)                            |
| Cache capacity        | 32 (configurable via `CoseTpJsonOptions::cache_capacity`)                       |

## Quickstart — translate, bind, compile

```rust,ignore
use cose_sign1_trust_policy_spec::{bind, compile, HandRolledFactRegistry};
use cose_sign1_trustfrontends_json::{CoseTpJsonFrontend, TrustPolicyTranslationContext};
use std::collections::BTreeMap;

let frontend = CoseTpJsonFrontend::new();

// 1. Translate the document. Diagnostics carry stable TPXxxx codes.
let document_text = std::fs::read_to_string("trust.coseTrustPolicy.json")?;
let result = frontend.translate_text(
    &document_text,
    &TrustPolicyTranslationContext::empty(),
    Some("file:///etc/myapp/trust.coseTrustPolicy.json"),
);

if !result.is_success() {
    for d in &result.diagnostics {
        eprintln!("[{}] {}", d.code, d.message);
    }
    return Ok(());
}
let spec = result.spec.expect("is_success guarantees Some(spec)");

// 2. Bind any $param references.
let mut parameters = BTreeMap::new();
parameters.insert("trusted_log_hosts".into(), serde_json::json!(["dataplane.codetransparency.azure.net"]));
let bound = bind(spec, &parameters)?;

// 3. Compile against a fact registry assembled from the configured packs.
let registry = HandRolledFactRegistry::from_packs(&[
    cose_sign1_certificates::__cose_sign1_trust_facts(),
])?;
let plan = compile(&bound, &registry)?;
```

## Frontend grammar (`cose-tp-json/v1`)

```jsonc
{
  "$schema": "https://raw.githubusercontent.com/microsoft/CoseSignTool/main/V2/schemas/cose-tp/v1.json",
  "frontend": "cose-tp-json/v1",
  "primary_signing_key": {
    "all_of": [
      { "fact": "x509-chain-trusted/v1",          "predicate": { "is_trusted": true } },
      { "fact": "x509-cert-identity-allowed/v1",  "predicate": { "is_allowed": true } }
    ]
  },
  "any_counter_signature": {
    "on_empty": "deny",
    "all_of": [
      { "fact": "mst-receipt-trusted/v1", "predicate": { "is_trusted": true } }
    ]
  },
  "combinator": "and"
}
```

`combinator` controls how the `message` / `primary_signing_key` /
`any_counter_signature` scopes are combined when more than one is present (default
`and`).

## Diagnostic codes

| Code     | Meaning                                                                              |
|----------|--------------------------------------------------------------------------------------|
| `TPX001` | Document is not legal JSON (parser error). Carries `SourceLocation { line, column }`. |
| `TPX100` | JSON-Schema validation failure (one diagnostic per leaf error).                      |
| `TPX101` | `frontend` discriminator does not match `cose-tp-json/v1`.                           |
| `TPX200` | Unknown fact id (capability gating).                                                 |
| `TPX201` | Predicate fails the host-supplied per-fact predicate schema.                         |
| `TPX300` | Recursion-depth cap exceeded.                                                        |
| `TPX301` | Document node is structurally untranslatable (defensive — schema rejects first).     |
| `TPX400` | (Bind) `$param` reference is unbound and has no in-document `default`.               |

## Cross-port consistency (D7)

The embedded schema bytes are **byte-identical** (after platform line-ending
normalization to LF) to the .NET schema at `V2/schemas/cose-tp/v1.json`. Drift in
either copy is a CI gate failure: the `cross_port_schema` integration test diffs the
embedded copy against the .NET source via `git show`.

The frontend's `$id` deliberately points at `V2/schemas/cose-tp/v1.json` (the canonical
.NET-anchored location) — both ports load the schema from disk so the URL is metadata
only; users may declare either path in their document's `$schema` hint.

The blake3 cache key is internal-only and intentionally diverges from the .NET
implementation's SHA-256 (R5). Cache content is never serialized or sent across
process boundaries, so the hash-function difference does not break any cross-port
contract.

## Configuration

```rust,ignore
use cose_sign1_trustfrontends_json::{CoseTpJsonFrontend, CoseTpJsonOptions, TranslatorCache};

// Tighter recursion budget + larger cache.
let options = CoseTpJsonOptions::new()
    .with_max_depth(32)
    .with_cache_capacity(128);

let frontend = CoseTpJsonFrontend::with_options(options);
let cache = TranslatorCache::with_options(options).expect("non-zero capacity");
```

## CLI integration

The `CoseSignTool verify x509` command accepts `--trust-policy <path>` plus repeatable
`--trust-policy-param key=value`. When `--trust-policy` is supplied the CLI loads the
document via this crate, binds parameters, compiles to a `CompiledTrustPlan`, and
bypasses the pack's default trust plan (per design decision **D8**). Pack fact
producers stay registered so `RequireFact` references resolve.

## See also

- Design doc: `eval-trust-policy-translation-contract-rust.md` §6.5.5
- Phase 1 IR: `cose_sign1_trust_policy_spec`
- Phase 3 fact registry: `HandRolledFactRegistry::from_packs`
