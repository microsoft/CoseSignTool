# CoseSign1.Validation.TrustFrontends.Json

Canonical reference frontend (`cose-tp-json/v1`) for CoseSign1 trust policies. Parses,
JSON-Schema-validates, and translates user-authored `.coseTrustPolicy.json` documents into a
`TrustPolicySpec` (the IR shipped by `CoseSign1.Validation.Trust.PlanPolicy.Spec`).

## What this package ships

- `ICoseTrustPolicyFrontend<JsonDocument>` implementation: `CoseTpJsonFrontend`.
- The canonical JSON Schema for `cose-tp-json/v1`, embedded as a manifest resource so
  translation has no runtime network dependency.
- A post-translate `Bind(parameters)` step that substitutes `$param` references per design
  decision D5.
- An in-process LRU translator cache (default size 32) per design decision D9.

The frontend satisfies the eight translation guarantees of §6.5.4: determinism, totality,
attribute fidelity, reject-what-you-can't-translate, capability-aware, no code execution,
bounded runtime, schema-checked output.

## Frontend grammar (cose-tp-json/v1)

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

JSONC comments (`//` and `/* … */`) are accepted; the translator strips them before
schema-validating the document.

See the design doc (`eval-trust-policy-translation-contract.md`) §6.5.5 for the full
specification.
