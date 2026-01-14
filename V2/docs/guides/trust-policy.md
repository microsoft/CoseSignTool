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
- Trust evaluation runs **after signature verification** (so untrusted signers do not become a signature oracle).
- Extension packages drive trust by registering `ITrustPack` and (optionally) exposing configuration via DI builder extensions.

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
using System.Security.Cryptography.X509Certificates;
using CoseSign1.Certificates.Trust;
using CoseSign1.Certificates.Trust.Facts;
using CoseSign1.Validation;
using CoseSign1.Validation.Interfaces;
using CoseSign1.Validation.Trust;

var services = new ServiceCollection();
services.AddLogging();

// 1) Components (key material resolution)
services.AddSingleton<IValidationComponent>(_ => new CertificateSigningKeyResolver());

// 2) Trust facts (chain trust evaluation)
var certTrust = new CertificateTrustBuilder()
    .UseSystemTrust()
    // For apps, prefer pinning identities; this keeps the sample short.
    .AllowAnyCertificateIdentity()
    .WithRevocationMode(X509RevocationMode.Online);

services.AddSingleton<ITrustPack>(_ => new CoseSign1.Certificates.Trust.Facts.Producers.X509CertificateTrustPack(certTrust.Options));

// 3) Trust policy (require chain to be trusted)
var policy = TrustPlanPolicy.PrimarySigningKey(key => key.RequireFact<X509ChainTrustedFact>(
    f => f.IsTrusted,
    "X.509 certificate chain must be trusted"));

using var sp = services.BuildServiceProvider();
var trustPlan = policy.Compile(sp);
var components = sp.GetServices<IValidationComponent>().ToArray();
var validator = new CoseSign1Validator(components, trustPlan);

var message = CoseMessage.DecodeSign1(signatureBytes);
var result = message.Validate(validator);
```

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
