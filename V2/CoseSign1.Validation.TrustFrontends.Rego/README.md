# CoseSign1.Validation.TrustFrontends.Rego

Constrained-Rego-subset frontend (`cose-tp-rego/v1`) for CoseSignTool trust policies.

The frontend parses a small, closed Rego dialect and lowers it onto the canonical
`cose-tp-json/v1` shape. Translation is performed by reusing the JSON frontend's schema
validator + walker, so byte-equality with the JSON IR for the same logical policy is a
property of construction, not of duplicated logic.

## Why a constrained subset (and not full Rego)

There is no first-class .NET OPA partial-evaluation library in active maintenance. The
realistic options for shipping Rego-on-.NET were:

| Option | Cost | Verdict |
| --- | --- | --- |
| **A.** Wrap [regorus](https://github.com/microsoft/regorus) via P/Invoke | Rust toolchain + native packaging | rejected for V2 |
| **B.** Implement a constrained-subset interpreter directly in C# | ~1k LoC, audited | **chosen** |
| **C.** Shell out to the `opa eval --partial` binary | Operator-installed dependency, IPC overhead, risk of arbitrary execution | rejected |

The §6.5.6 example (and the operational shape of "trust policy as data") is a tightly
bounded subset: object literals, `input.<name>` parameter substitution, scalar literals,
arrays. A purpose-built parser hits the requirements without a 100 MB dependency or an
ambient process. Anything outside the accept-list is rejected with a `TPX300` diagnostic so
authors find out at translate time, not at evaluation time.

## Accept-list grammar

```
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

- The `policy` rule body must be an object literal whose shape mirrors the
  `cose-tp-json/v1` schema (`primary_signing_key`, `any_counter_signature`, `message`,
  `combinator`, `all_of`, `any_of`, `not`, `implies`, `fact`, `predicate`, …). The
  vocabulary is identical between frontends — Rego authors do **not** translate property
  names; the frontend preserves them.
- `input.<name>` becomes the canonical `{"$param": "<name>"}` JSON node, so the
  post-translate `Bind` pass binds Rego documents the same way it binds JSON ones.
- Strings use double quotes with the JSON escape set. Comments are `# … <eol>`.

## Reject-list (TPX300 with a diagnostic suggestion)

| Construct | Rejected because |
| --- | --- |
| `some x in coll`, `every`, `with`, `default`, `not` keywords | unconstrained iteration / quantification |
| Comprehensions (`[x | y]`, `{x | y}`, `{k: v | y}`) | unconstrained iteration over external data |
| `http.send(...)`, `regex.match(...)`, `crypto.*`, `net.*`, `time.*`, `opa.*`, `os.*`, `io.*`, `file.*` | side-effecting / network / filesystem builtins |
| `data.<...>` | only `input.<...>` is allowed; trust policies must be parameter-driven |
| `eval`, custom rules other than `policy` | code-loading or extra-rule indirection |
| Multiple `policy` rules per package | exactly one rule per document |
| `import` other than `future.keywords.in` | restricted to the OPA-compat alias only |

The reject-list is **closed**: adding a new forbidden construct requires a code change in
`RegoParser` plus a fixture under `fixtures/rego/untranslatable/`.

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

## Diagnostic codes

| Code | Severity | Meaning |
| --- | --- | --- |
| `TPX001` | Error | Lexical / syntactic error (unterminated string, malformed number, unexpected token). |
| `TPX002` | Error | Missing or wrong `package` declaration. |
| `TPX003` | Error | Missing `policy := ...` rule. |
| `TPX004` | Error | Forbidden `import` (only `future.keywords.in` is allowed). |
| `TPX005` | Error | Multiple rules per package. |
| `TPX100` | Error | Schema validation failure on the lowered JSON shape (forwarded from the JSON frontend). |
| `TPX200` | Error | Unknown fact id (forwarded from the JSON frontend's capability-aware translation). |
| `TPX300` | Error | Untranslatable construct (catch-all: unknown identifier, generic comprehension fallback). |
| `TPX301` | Error | Forbidden builtin: `http.*`, `regex.*`, `file.*`, `io.*`, `os.*`, `crypto.*`, `net.*`, `time.*`, `opa.*`. |
| `TPX302` | Error | Unconstrained iteration / quantification: `some`, `every`, `with`, `default`, `not`, `eval`. |
| `TPX303` | Error | Reserved `data.<...>` reference (only `input.<...>` is allowed). |
| `TPX304` | Error | Comprehension expression (`[x | y]`, `{x | y}`, `{k: v | y}`). |
| `TPX305` | Error | Maximum nesting depth exceeded (cap is 64 — defense-in-depth against stack-exhaustion DoS). |
| `TPX306` | Error | Maximum input size exceeded (cap is 1 MiB — defense-in-depth against memory-exhaustion DoS). |

The `TPX301`–`TPX306` sub-codes split the broader `TPX300` translation-error band so
blue-team telemetry can attribute rejection rates to the specific construct class without
parsing the human-readable message.

`TPX100` and `TPX200` are emitted by the JSON frontend on the lowered tree — the Rego
frontend never duplicates that logic, so the diagnostic vocabulary is identical between
frontends.

## Testing your Rego policy outside CoseSignTool

The constrained subset is a strict superset-friendly fragment of OPA's Rego, so any
`.coseTrustPolicy.rego` document that the CoseSignTool frontend accepts can be lint-checked
and unit-tested with the standard OPA toolchain:

```sh
# fmt
opa fmt my-validation.coseTrustPolicy.rego

# lint
opa check my-validation.coseTrustPolicy.rego

# unit tests via opa test (write your own *_test.rego beside the policy)
opa test -v .
```

This is intentional: OPA shops keep their existing review pipeline, bundle / data-feed
mechanism, and editor integration. The CoseSignTool frontend is a CI gate on top of that
toolchain, not a replacement for it.

## Architecture (hint for code reviewers)

```
+----------------+    parse     +-----------+   lower    +-----------+
| .rego document |  ────────►   | RegoAST   |  ───────►  | JsonObject|
+----------------+              +-----------+            +-----+-----+
                                                                │ ToJsonString
                                                                ▼
                                                       +------------------+
                                                       | CoseTpJsonFrontend|
                                                       |  (schema + walk)  |
                                                       +--------+---------+
                                                                │
                                                                ▼
                                                       +------------------+
                                                       | TrustPolicySpec   |
                                                       +------------------+
```

The Rego frontend never executes user input. There is no `opa eval`, no regorus, no
shell-out. The parser walks tokens; the lowerer pattern-matches AST nodes; the JSON
frontend (audited under Phase 2 / Phase 4) handles schema validation + IR construction.
