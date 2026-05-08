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

## Installation

```xml
<PackageReference Include="CoseSign1.Validation.TrustFrontends.Json" Version="2.0.0-preview" />
```

## Quickstart — translate, bind, compile

```csharp
using CoseSign1.Validation.Trust.Frontends;
using CoseSign1.Validation.Trust.PlanPolicy.Spec.Compilation;
using CoseSign1.Validation.Trust.PlanPolicy.Spec.Registry;
using CoseSign1.Validation.TrustFrontends.Json;
using Microsoft.Extensions.DependencyInjection;
using System.Text.Json.Nodes;

// 1. Wire the frontend + translator cache into DI.
var services = new ServiceCollection()
    .AddCoseTpJsonFrontend()
    .AddAttributeDrivenFactRegistry()
    .BuildServiceProvider();

var frontend = services.GetRequiredService<CoseTpJsonFrontend>();
var registry = services.GetRequiredService<IFactRegistry>();

// 2. Translate the document. Diagnostics carry JSON-pointer source locations.
string documentText = File.ReadAllText("trust.coseTrustPolicy.json");
TrustPolicyTranslationResult result = frontend.TranslateText(
    documentText,
    new TrustPolicyTranslationContext
    {
        AvailableFacts = new FactCapabilities { AvailableFactIds = registry.AllFactIds },
    },
    documentSource: "file:///etc/myapp/trust.coseTrustPolicy.json");

if (!result.IsSuccess)
{
    foreach (var d in result.Diagnostics)
        Console.Error.WriteLine($"[{d.Code}] {d.Message} (at {d.Location?.Source})");
    return;
}

// 3. Bind any $param references the document carries.
TrustPolicyTranslationResult bound = result.Bind(new Dictionary<string, JsonNode?>
{
    ["trusted_log_hosts"] = JsonNode.Parse("[\"dataplane.codetransparency.azure.net\"]"),
});

// 4. Compile to a CompiledTrustPlan that bypasses pack defaults (D8 override semantics).
var plan = CompiledTrustPlanFromSpec.CompileFromSpec(bound.Spec!, registry, services);
```

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

JSONC comments (`//` and `/* … */`) and trailing commas are accepted.

## Diagnostic codes

| Code     | Meaning                                                                          |
|----------|----------------------------------------------------------------------------------|
| `TPX001` | Malformed JSON (parser error).                                                   |
| `TPX100` | JSON-Schema validation failure.                                                  |
| `TPX101` | `frontend` discriminator does not match `cose-tp-json/v1`.                       |
| `TPX200` | Unknown fact id (fact not advertised in `FactCapabilities.AvailableFactIds`).    |
| `TPX201` | Predicate fails the host-supplied per-fact predicate schema.                     |
| `TPX300` | Predicate operator is not in the closed `PredicateOperator` set.                 |
| `TPX301` | Document node is structurally untranslatable (defensive — schema rejects first). |
| `TPX302` | Reserved property name (e.g. `$param`) used in a fact-property assertion.        |
| `TPX400` | `$param` reference is unbound and has no in-document `default`.                  |
| `TPX401` | (Reserved) Future strict-typed parameter binding type-mismatch.                  |

See the design doc (`eval-trust-policy-translation-contract.md`) §6.5.5 for the full
specification.

