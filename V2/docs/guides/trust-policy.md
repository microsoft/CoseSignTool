# Trust Plan Deep Dive

This guide describes the V2 trust model used by `CoseSign1.Validation`.

V2 trust is evaluated using the **Facts + Rules** model:

- **Facts** are produced on-demand by registered `ITrustPack` implementations.
- **Rules** are evaluated by a compiled plan (`CompiledTrustPlan`).
- Optional *additional requirements* can be expressed as a `TrustPlanPolicy`.

## Key concepts

| Concept | Description |
|---------|-------------|
| **Trust pack** (`ITrustPack`) | Produces facts and contributes secure-by-default plan fragments |
| **Compiled plan** (`CompiledTrustPlan`) | Root rule + available fact producers; evaluated during the trust stage |
| **Policy fragment** (`TrustPlanPolicy`) | Fluent authoring surface for additional requirements; compiles to a plan |

Important properties of this model:

- Trust is **data-driven** (facts are lazy) and **declarative** (rules).
- Trust evaluation runs **before signature verification** in the staged validator. If trust fails, the signature stage is marked `NotApplicable`.
- Extension packages drive trust by registering `ITrustPack` and exposing opt-in configuration via `ICoseValidationBuilder` extensions.

## Default trust behavior

Trust packs can contribute default plan fragments, but the overall system is still **deny-by-default** unless something explicitly provides a trust source. In many cases (including the CLI), the active configuration determines which trust sources exist.

If your app relies on defaults, use:

```csharp
using var sp = services.BuildServiceProvider();
CompiledTrustPlan plan = CompiledTrustPlan.CompileDefaults(sp);
```

If you need explicit requirements, prefer compiling an explicit `TrustPlanPolicy` (next section).

## Common usage

### Certificate trust (system roots)

`CoseSign1.Certificates` provides a trust pack that evaluates X.509 chain trust and exposes it as facts.
You can require those facts with a `TrustPlanPolicy`.

```csharp
using Microsoft.Extensions.DependencyInjection;
using System.Security.Cryptography.Cose;
using CoseSign1.Certificates.Trust.Facts;
using CoseSign1.Validation;
using CoseSign1.Validation.DependencyInjection;
using CoseSign1.Validation.Trust;
using CoseSign1.Validation.Trust.Plan;

var services = new ServiceCollection();
services.AddLogging();

var validation = services.ConfigureCoseValidation();
validation.EnableCertificateSupport();

// Add explicit requirements (require chain to be trusted)
var policy = TrustPlanPolicy.PrimarySigningKey(key => key.RequireFact<X509ChainTrustedFact>(
    f => f.IsTrusted,
    "X.509 certificate chain must be trusted"));

services.AddSingleton<CompiledTrustPlan>(sp => policy.Compile(sp));

using var sp = services.BuildServiceProvider();
var validator = sp.GetRequiredService<ICoseSign1ValidatorFactory>().Create();

var message = CoseMessage.DecodeSign1(signatureBytes);
var result = message.Validate(validator);
```

### Counter-signatures (receipt-style trust subjects)

Some trust packs model additional signed artifacts as **counter-signature subjects**.
This is useful for scenarios where there can be multiple independent “receipts” attached to a message.

For example, `CoseSign1.Transparent.MST` models each MST receipt as a counter-signature subject and produces receipt facts in the **counter-signature scope**.
To require “at least one valid MST receipt”, use `TrustPlanPolicy.AnyCounterSignature(...)`:

```csharp
using CoseSign1.Certificates.Trust.Facts;
using CoseSign1.Transparent.MST.Trust;
using CoseSign1.Validation;
using CoseSign1.Validation.DependencyInjection;
using CoseSign1.Validation.Trust;
using Microsoft.Extensions.DependencyInjection;
using System.Security.Cryptography.Cose;

var services = new ServiceCollection();
services.AddLogging();

var validation = services.ConfigureCoseValidation();
validation.EnableCertificateSupport();
validation.EnableMstSupport(mst => mst.VerifyReceipts(new Uri("https://dataplane.codetransparency.azure.net")));

var policy = TrustPlanPolicy.PrimarySigningKey(key => key
        .RequireFact<X509ChainTrustedFact>(f => f.IsTrusted, "X.509 certificate chain must be trusted"))
    .And(TrustPlanPolicy.AnyCounterSignature(cs => cs
        .RequireFact<MstReceiptPresentFact>(f => f.IsPresent, "MST receipt must be present")
        .RequireFact<MstReceiptTrustedFact>(f => f.IsTrusted, "MST receipt must verify")));

services.AddSingleton<CompiledTrustPlan>(sp => policy.Compile(sp));

using var sp = services.BuildServiceProvider();
var validator = sp.GetRequiredService<ICoseSign1ValidatorFactory>().Create();

var message = CoseMessage.DecodeSign1(signatureBytes);
var result = message.Validate(validator);
```

Notes:

- `AnyCounterSignature(...)` defaults to **deny on empty**, so it naturally expresses “a receipt is required”.
- If you want “receipt present but don’t cryptographically verify it”, omit the `MstReceiptTrustedFact` requirement.

### Adding additional requirements (advanced)

If you need an explicit, deployment-specific requirement that is not covered by a pack’s options, author a `TrustPlanPolicy`.

In the CLI, plugin providers contribute `TrustPlanPolicy` fragments which are AND-ed together.
In a library integration, prefer configuring packs (options) where possible; author explicit policies when you need a hard requirement.

## Document-driven trust policy

In addition to the code-driven fluent surface described above, V2 supports loading a trust policy from a versioned text document (`.coseTrustPolicy.json` or `.coseTrustPolicy.rego`). Compliance/security authors edit the document; the CLI loads it; the validator enforces it. Same `CompiledTrustPlan`, different input path.

### CLI usage

```bash
cosesigntool verify x509 signed.cose \
    --trust-roots ca.pem \
    --trust-policy ./trust.coseTrustPolicy.json \
    --trust-policy-param trusted_log_hosts='["dataplane.codetransparency.azure.net"]'
```

When `--trust-policy <path>` is supplied, the document is the **sole source of trust requirements** for that invocation. Pack default contributions (`ITrustPack.GetDefaults()`) are **bypassed**; pack fact producers stay registered so the document's `RequireFact` references resolve. This is the deliberate D8 override semantic — what the operator sees in the file is exactly what the verifier enforces, with no implicit ANDed-in defaults.

Without `--trust-policy`, existing pack-default behaviour is unchanged.

### JSON document format (`cose-tp-json/v1`)

The canonical reference frontend. Documents validate against an embedded JSON Schema; comments and trailing commas (JSONC) are accepted. Example:

```jsonc
// trust.coseTrustPolicy.json
{
  "$schema": "https://raw.githubusercontent.com/microsoft/CoseSignTool/main/V2/schemas/cose-tp/v1.json",
  "frontend": "cose-tp-json/v1",
  "primary_signing_key": {
    "all_of": [
      { "fact": "x509-chain-trusted/v1",         "predicate": { "is_trusted": true } },
      { "fact": "x509-cert-identity-allowed/v1", "predicate": { "is_allowed": true } }
    ]
  },
  "any_counter_signature": {
    "on_empty": "deny",
    "all_of": [
      { "fact": "mst-receipt-present/v1", "predicate": { "is_present": true } },
      { "fact": "mst-receipt-trusted/v1", "predicate": { "is_trusted": true } },
      { "fact": "mst-receipt-issuer-host/v1",
        "predicate": {
          "operator": "In",
          "path": "$.host",
          "value": { "$param": "trusted_log_hosts" }
        }
      }
    ]
  },
  "combinator": "and"
}
```

Predicates support two forms (D1 hybrid):

- **Property-shorthand** (`{ "is_trusted": true }`) — terse for boolean/scalar properties of a fact.
- **Path/operator** (`{ "path": "$.host", "operator": "In", "value": ... }`) — uniform shape for every fact; lets you assert across nested structure or use comparison operators.

Both forms compile to byte-identical IR. Use whichever reads better in PR review.

### Rego document format (`cose-tp-rego/v1`)

For organizations standardising on OPA/Rego. The frontend parses a constrained Rego subset and lowers it onto the same IR; no Rego policy is ever executed (no built-ins, no HTTP, no filesystem, no `regex`). Example:

```rego
# trust.coseTrustPolicy.rego
package cose_trust_policy

import future.keywords.in

policy := {
    "primary_signing_key": {
        "all_of": [
            {"fact": "x509-chain-trusted/v1",         "predicate": {"is_trusted": true}},
            {"fact": "x509-cert-identity-allowed/v1", "predicate": {"is_allowed": true}}
        ]
    },
    "any_counter_signature": {
        "on_empty": "deny",
        "all_of": [
            {"fact": "mst-receipt-trusted/v1", "predicate": {"is_trusted": true}}
        ]
    },
    "combinator": "and"
}
```

Logical policies expressed in JSON and Rego that translate to the same IR are byte-identical at the canonical-JSON level — verified by the cross-frontend conformance suite. You can pick whichever language fits your existing review pipeline.

### Parameters

`$param` references in JSON (and `input.<name>` in Rego) are replaced at translation time by values from `--trust-policy-param key=value` (repeatable). Unbound parameters with no in-document `default` produce diagnostic `TPX400` and the verify command fails — there is no silent default substitution.

### Available fact ids

The document's `RequireFact` entries reference stable fact ids attribute-tagged on each fact CLR type. The current set (16 v1 ids) is enumerated in `CoseSign1.Validation.Trust.PlanPolicy.Spec/Registry/StaticFactRegistry.cs` and exposed at runtime via `IFactRegistry.AllFactIds`. Renaming a v1 id is a v2 breaking change; new facts get new `/v1` ids and are added without disturbing existing ones.

### Diagnostic codes

| Code   | Meaning                                                                    |
|--------|----------------------------------------------------------------------------|
| TPX001 | Malformed JSON or Rego (parser error).                                     |
| TPX100 | JSON-Schema validation failure (unknown fields, wrong types, etc.).        |
| TPX101 | Frontend discriminator mismatch.                                           |
| TPX200 | Unknown fact id (not in `IFactRegistry.AllFactIds`).                       |
| TPX201 | Predicate fails the per-fact predicate schema.                             |
| TPX300 | Rego construct outside the accept-list (e.g. `regex.match`, `some x in`). |
| TPX400 | `$param` reference is unbound and has no in-document `default`.            |

### Authoring discipline

- Treat the document as the policy of record. Re-translate on each load; never store the compiled IR as the policy artifact (caching is internal-only per design D9).
- Don't put trust roots / certs / private keys inline. Trust roots flow via `ITrustPack` configuration; the document references fact ids that *describe* the assertion.
- The full design rationale lives in the eval doc: `eval-trust-policy-translation-contract.md`. The per-frontend project READMEs (`CoseSign1.Validation.TrustFrontends.Json/README.md`, `CoseSign1.Validation.TrustFrontends.Rego/README.md`) document grammar specifics, diagnostic codes, and library-integration code samples.

## Troubleshooting

If trust fails, `result.Trust` contains the denial reasons from the plan evaluation:

```csharp
if (!result.Trust.IsValid)
{
    foreach (var failure in result.Trust.Failures)
    {
        Console.WriteLine($"{failure.ErrorCode}: {failure.Message}");
    }
}
```

## See also

- [Audit and Replay](audit-and-replay.md)
