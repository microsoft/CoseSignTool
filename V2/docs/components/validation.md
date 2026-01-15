# CoseSign1.Validation Package

**NuGet**: `CoseSign1.Validation`  
**Purpose**: Staged validation pipeline for COSE Sign1 messages

## What this package provides

This package defines the core primitives for V2 staged validation:

- `ICoseSign1Validator` and the orchestration implementation `CoseSign1Validator`
- Stage-specific interfaces:
    - `ISigningKeyResolver` (resolve key material)
    - `IPostSignatureValidator` (business rules after trust + signature)
- Trust evaluation via a **trust plan** (`CompiledTrustPlan`):
    - `ITrustPack` (fact production + default trust fragments)
    - `TrustPlanPolicy` (optional additional requirements)
    - `CompiledTrustPlan` (the compiled evaluation plan)
- `ICoseSign1ValidatorFactory` for DI-based construction of fully-wired validators
- `CoseSign1Message` extension methods: `Validate(...)` / `ValidateAsync(...)`

Validation in V2 is **staged and safe-by-default**:

1. Resolve signing key material (`ISigningKeyResolver`)
2. Evaluate trust (`CompiledTrustPlan`)
3. Verify signature (crypto using the resolved key)
4. Run post-signature checks (`IPostSignatureValidator`)

## Quick start

```csharp
using System.Security.Cryptography.Cose;
using CoseSign1.Validation;
using CoseSign1.Validation.DependencyInjection;
using Microsoft.Extensions.DependencyInjection;

var message = CoseMessage.DecodeSign1(signatureBytes);

var services = new ServiceCollection();
services.AddLogging();

var validation = services.ConfigureCoseValidation();
validation.EnableCertificateTrust();

using var serviceProvider = services.BuildServiceProvider();
var validator = serviceProvider.GetRequiredService<ICoseSign1ValidatorFactory>().Create();

var result = message.Validate(validator);
```

## Writing your own validation components

Choose the stage-specific interface based on where your logic belongs:

- `ISigningKeyResolver` — extract key material from headers (x5chain, kid, etc.)
- `IPostSignatureValidator` — business rules that require full context (resolved key, trust decision, signature metadata, options)

If you need custom trust signals, implement a custom `ITrustPack` (facts + defaults) and/or contribute an additional `TrustPlanPolicy`.

## See Also

- [Architecture: Validation Framework](../architecture/validation-framework.md)
- [Trust Policy Guide](../guides/trust-policy.md)
- [Certificates Component](certificates.md)
- [Custom Validators Guide](../guides/custom-validators.md)
- [Validation Extension Packages](../guides/validation-extension-packages.md)
