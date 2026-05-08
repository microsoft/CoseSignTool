# cose_sign1_trustfrontends_rego

Constrained-Rego-subset frontend (`cose-tp-rego/v1`) for CoseSign1 trust
policies. Parses a small, closed Rego dialect and lowers it onto the
canonical `cose-tp-json/v1` shape; translation is then performed by reusing
the JSON frontend's schema validator + walker, so byte-equality with the
JSON IR for the same logical policy is a property of construction, not of
duplicated logic.

This is the Rust port of the .NET `CoseSign1.Validation.TrustFrontends.Rego`
deliverable (V2 train Phase 5a).

## Why a constrained subset (and not full Rego)

The original Rust port plan (decision **R2**, recorded in
`eval-trust-policy-translation-contract-rust.md`) recommended
[`regorus`](https://github.com/microsoft/regorus) — Microsoft's pure-Rust
Rego interpreter — as the parser substrate. Phase 5a re-evaluated that
choice against the actual surface §6.5.6 demands.

| Option | Cost | Verdict |
| --- | --- | --- |
| **A.** `regorus` partial-eval | Drag in `regorus` + transitive deps; configure HTTP / regex / file I/O / custom-builtin disable hooks; post-validate the residual against the same reject-list anyway | rejected |
| **B.** Hand-rolled parser over the §6.5.6 subset | ~1 KLoC, zero external deps, identical reject-list to .NET Phase 5a | **chosen** |
| **C.** Shell out to the `opa eval --partial` binary | Operator-installed dependency, IPC overhead, risk of arbitrary code execution | rejected |

The shape of "trust policy as data" is a tightly-bounded subset: object
literals, `input.<name>` parameter substitution, scalar literals, arrays.
A hand-rolled parser hits the requirements without a multi-MB dependency
or an ambient process. The .NET Phase 5a deliverable reached the same
conclusion under analogous constraints (no first-class .NET OPA
partial-eval library) and shipped a constrained-subset interpreter; the
Rust port lifts the same decision so cross-port telemetry, fixtures, and
diagnostic vocabulary stay aligned.

## Frontend identity

| Attribute | Value |
| --- | --- |
| Frontend id | `cose-tp-rego/v1` |
| Media type | `application/x-cose-trust-policy+rego` |
| File extension | `.coseTrustPolicy.rego` |
| Sniff prefix | `package cose_trust_policy` |

## Accept-list grammar

```text
module       := package_decl import* rule
package_decl := 'package' 'cose_trust_policy'
import       := 'import' 'future.keywords.in'                (the only allowed import)
rule         := 'policy' (':=' | '=') term
term         := object_literal | array_literal
              | string | number | bool | null
              | '-' number | input_ref
input_ref    := 'input' '.' ident ('.' ident)*
object_literal := '{' (string ':' term (',' string ':' term)*)? ','? '}'
array_literal  := '[' (term (',' term)*)? ','? ']'
```

- The `policy` rule body MUST be an object literal whose shape mirrors the
  `cose-tp-json/v1` schema (`primary_signing_key`, `any_counter_signature`,
  `message`, `combinator`, `all_of`, `any_of`, `not`, `implies`, `fact`,
  `predicate`, …). The vocabulary is identical between frontends — Rego
  authors do **not** translate property names; the frontend preserves them.
- `input.<name>` becomes the canonical `{"$param": "<name>"}` JSON node, so
  the post-translate `bind` pass binds Rego documents the same way it binds
  JSON ones.
- Strings use double quotes with the JSON escape set. Comments are
  `# … <eol>`.

## Reject-list (closed; per-cause TPX sub-codes)

| Construct | Code | Rejected because |
| --- | --- | --- |
| `http.*`, `regex.*`, `file.*`, `io.*`, `os.*`, `crypto.*`, `net.*`, `time.*`, `opa.*` | **TPX301** | side-effecting / network / filesystem builtins |
| `some`, `every`, `with`, `default`, `not`, `eval` | **TPX302** | unconstrained iteration / quantification |
| `data.<…>` | **TPX303** | only `input.<…>` is allowed; trust policies must be parameter-driven |
| Comprehensions `[x \| y]`, `{x \| y}`, `{k: v \| y}` | **TPX304** | unconstrained iteration over external data |
| Maximum nesting depth exceeded (cap 64) | **TPX305** | defense-in-depth against stack-exhaustion DoS |
| Maximum input size exceeded (cap 1 MiB) | **TPX306** | defense-in-depth against memory-exhaustion DoS |
| Lone surrogates / unescaped control chars | **TPX001** | UTF-16 well-formedness required for canonical IR |
| Multiple rules per package | **TPX005** | exactly one `policy := ...` rule per document |
| Wrong / missing `package` | **TPX002** | required boilerplate |
| Missing `policy` rule | **TPX003** | required rule |
| Forbidden `import` | **TPX004** | restricted to `future.keywords.in` |
| Catch-all unknown identifier / generic comprehension fallback | **TPX300** | construct unknown to the constrained subset |

The reject-list is **closed** — adding a new forbidden construct requires
a code change in `parser.rs` plus a fixture under
`fixtures/untranslatable/`.

The `TPX001`, `TPX100`, and `TPX200` codes are emitted by the JSON
frontend on the lowered tree; the Rego frontend never duplicates that
logic, so the diagnostic vocabulary is identical between frontends.

## Example document

```rego
# my-validation.coseTrustPolicy.rego
package cose_trust_policy

import future.keywords.in

policy := {
    "primary_signing_key": {
        "all_of": [
            {"fact": "x509-chain-trusted/v1",         "predicate": {"is_trusted": true}},
            {"fact": "x509-cert-identity-allowed/v1", "predicate": {"is_allowed": true}},
            {"fact": "x509-cert-eku/v1",
             "predicate": {
                 "operator": "Equals",
                 "path": "$.oid_value",
                 "value": "1.3.6.1.5.5.7.3.3"
             }}
        ]
    },
    "any_counter_signature": {
        "on_empty": "deny",
        "all_of": [
            {"fact": "mst-receipt-present/v1", "predicate": {"is_present": true}},
            {"fact": "mst-receipt-trusted/v1", "predicate": {"is_trusted": true}},
            {"fact": "mst-receipt-issuer-host/v1",
             "predicate": {
                 "operator": "Equals",
                 "path": "$.host",
                 "value": input.trusted_log_host
             }}
        ]
    },
    "combinator": "and"
}
```

## Testing your Rego policy outside CoseSignTool

The constrained subset is a syntactic fragment of OPA's Rego, so any
`.coseTrustPolicy.rego` document the CoseSignTool frontend accepts can be
lint-checked and unit-tested with the standard OPA toolchain:

```sh
opa fmt my-validation.coseTrustPolicy.rego
opa check my-validation.coseTrustPolicy.rego
opa test -v .
```

This is intentional: OPA shops keep their existing review pipeline, bundle /
data-feed mechanism, and editor integration. The CoseSignTool frontend is
a CI gate on top of that toolchain, not a replacement for it.

## Architecture

```
+----------------+    parse     +-----------+   lower    +--------------+
| .rego document |  ────────►   | RegoAST   |  ───────►  |  JsonValue   |
+----------------+              +-----------+            +-------+------+
                                                                 │ to_string
                                                                 ▼
                                                       +-------------------+
                                                       | CoseTpJsonFrontend|
                                                       |  (schema + walk)  |
                                                       +---------+---------+
                                                                 │
                                                                 ▼
                                                       +-------------------+
                                                       |  TrustPolicySpec  |
                                                       +-------------------+
```

The Rego frontend never executes user input. There is no `opa eval`, no
regorus, no shell-out. The parser walks tokens; the lowerer
pattern-matches AST nodes; the JSON frontend (audited under Phase 2 /
Phase 4) handles schema validation + IR construction.

## Cross-frontend equivalence (§6.5.10 #8)

Cross-frontend equivalence — the property that a logical policy expressed
in either frontend produces byte-identical canonical IR — is not just an
assertion the test suite makes; it is a structural property of the Rego
frontend's design. Since translation is performed by reusing the JSON
frontend's pipeline on a JSON tree the Rego lowerer materialised, the IR
from a Rego document is *literally* the IR the JSON frontend would
produce for the lowered tree.

The conformance crate's
`run_conformance_8_cross_equivalence(json, rego)` reads the
`fixtures/cross/canonical_policy/canonical_policy.coseTrustPolicy.{json,rego}`
sibling pair and asserts byte-equality on the canonical IR. The Phase 4
test was a degenerate `(json, json)` pivot; Phase 5a expands it to the
true `(json, rego)` matrix.

## CLI dispatch (D8 override)

The CoseSignTool CLI's `verify x509 --trust-policy <path>` flag dispatches
between frontends based on:

1. File extension — `.coseTrustPolicy.rego` routes to this crate; anything
   else routes to `cose_sign1_trustfrontends_json`.
2. Document leading header — when no recognisable extension is present,
   a leading `package cose_trust_policy` (with optional banner comments)
   sniffs as Rego.

Pack defaults are bypassed when `--trust-policy` is supplied (per
`D8 override semantics`); pack fact producers stay registered so
`RequireFact` references resolve.

## FFI surface (Phase 4.5)

Phase 4.5 shipped the JSON-only FFI extern `cose_sign1_trust_policy_translate_json`.
Phase 5a does **not** add a sibling `cose_sign1_trust_policy_translate_rego`
extern. Rationale:

- The Rego frontend is a parse + lower pipeline whose output is a JSON
  tree the existing FFI extern accepts.
- Adding a Rego extern would expand the C-ABI surface and force a
  `cbindgen` re-run plus a header-drift assertion update.

This crate currently exposes Rust APIs only — there is no shipped
`extern "C"` boundary on the Rego frontend itself. Non-Rust hosts have
two options:

1. **Lower in the host language.** Translate the Rego document to its
   `cose-tp-json/v1` equivalent in the host language (the vocabulary
   matches; only the syntax differs), then call the existing
   `cose_sign1_trust_policy_translate_json` extern.
2. **Build their own Rust shim.** Wrap a thin
   `extern "C" fn translate_rego(...)` over `CoseTpRegoFrontend` in a
   purpose-built bridge crate, ship it alongside the host's binary, and
   link against it.

If FFI consumer demand surfaces in a later phase, an extern can be added
additively in this crate without breaking either path; the absence here
is forward-compatible.

## Reading diagnostics (operator guide)

Every diagnostic emitted by `CoseTpRegoFrontend` carries:

| Field | Meaning |
| --- | --- |
| `code` | Stable `TPXxxx` identifier (see Reject-list above). Switch on this in tooling rather than the message string. |
| `message` | Human-readable description; when a `document_source` was supplied to `translate_text`, the message is prefixed `<source>:<line>:<col>: ` so editor / log tooling can navigate back to the offending file. |
| `severity` | Always `Error` for parse failures (totality contract — no partial successes). |
| `location` | 1-based `(line, column)` anchoring the offending construct. |
| `suggestion` | Optional remediation hint for the reject-list family (e.g. `Replace 'data.<name>' with 'input.<name>' …` for TPX303). |

For deeper debugging — for example when a `TPX100` (JSON-shape
violation) surfaces but the underlying Rego document looks correct — the
crate exposes `RegoDocument::lowered()` which returns the lowered
`serde_json::Value` exactly as it reaches the JSON walker. Pretty-print
that tree to see what shape the parser produced and where the JSON
schema disagrees with it.

## Cross-port note

This crate is logically equivalent to the .NET frontend at
`V2/CoseSign1.Validation.TrustFrontends.Rego/`. Both share the same
frontend id, media type, accept-list grammar, and reject-list
(TPX301-306). Diagnostic codes, suggestion strings, and DoS caps
(64-deep nesting, 1-MiB input) are identical so cross-port telemetry
attributes rejection rates to the same buckets regardless of which port a
given trust evaluator runs on.
