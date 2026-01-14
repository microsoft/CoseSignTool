# CoseSign1.Validation Package

**NuGet**: `CoseSign1.Validation`  
**Purpose**: Component-based validation pipeline for COSE Sign1 messages

## What this package provides

This package defines the core primitives for V2 staged validation:

- `ICoseSign1Validator` and the orchestration implementation `CoseSign1Validator`
- `IValidationComponent` base interface and stage-specific interfaces:
    - `ISigningKeyResolver` (resolve key material)
    - `IPostSignatureValidator` (business rules after trust)
- Trust evaluation via **TrustPlan**:
    - `ITrustPack` (fact production + default trust fragments)
    - `TrustPlanPolicy` (optional additional requirements)
    - `CompiledTrustPlan` (the compiled evaluation plan)
- `CoseSign1Message` extension methods: `Validate(...)` / `ValidateAsync(...)`

Validation in V2 is **staged and safe-by-default**:

1. Resolve signing key material (`ISigningKeyResolver`)
2. Verify signature (crypto using the resolved key)
3. Evaluate trust (`CompiledTrustPlan`)
4. Run post-signature checks (`IPostSignatureValidator`)

## Quick start

```csharp
using System;
using Microsoft.Extensions.DependencyInjection;
using System.Security.Cryptography.Cose;
using CoseSign1.Certificates.Validation;
using CoseSign1.Validation;
using CoseSign1.Validation.Interfaces;
using CoseSign1.Validation.Trust.Engine;
using CoseSign1.Validation.Trust.Plan;
using CoseSign1.Validation.Trust.Rules;

var message = CoseMessage.DecodeSign1(signatureBytes);

// Minimal example: certificate-backed signatures + cryptographic verification.
// This demonstrates the staged validator, but bypasses trust (do not treat this as an authorization decision).
var services = new ServiceCollection();
services.AddLogging();

services.ConfigureCoseValidation()
    .EnableMessageFacts();

services.AddSingleton<IValidationComponent>(_ => new CertificateSigningKeyResolver());

using var serviceProvider = services.BuildServiceProvider();
var trustPlan = new CompiledTrustPlan(
    root: TrustRules.AllowAll(),
    producers: Array.Empty<IMultiTrustFactProducer>());
var components = serviceProvider.GetServices<IValidationComponent>().ToArray();
var validator = new CoseSign1Validator(
    components,
    trustPlan,
    trustEvaluationOptions: new TrustEvaluationOptions { BypassTrust = true });

var result = message.Validate(validator);
```

## Writing your own validation components

Choose the stage-specific interface based on where your logic belongs:

- `ISigningKeyResolver` — extract key material from headers (x5chain, kid, etc.)
- `IPostSignatureValidator` — business rules that require full context (resolved key, trust decision, signature metadata, options)

If you need custom trust signals, implement a custom `ITrustPack` (facts + defaults) and/or contribute an additional `TrustPlanPolicy`.

Components opt out via `IValidationComponent.IsApplicableTo(message, options)`.
To get caching for applicability checks, inherit from `ValidationComponentBase`.

## See Also

- [Architecture: Validation Framework](../architecture/validation-framework.md)
- [Trust Policy Guide](../guides/trust-policy.md)
- [Certificates Component](certificates.md)
- [Custom Validators Guide](../guides/custom-validators.md)
- [Validation Extension Packages](../guides/validation-extension-packages.md)
