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
