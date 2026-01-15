# Validation Framework

The CoseSignTool V2 validation model (package: `CoseSign1.Validation`) is a **staged**, DI-composed pipeline for validating COSE Sign1 messages.

## Overview

Validation is orchestrated by `ICoseSign1Validator` (implemented by `CoseSign1Validator`) and runs in a secure-by-default order:

1. Key material resolution (`ISigningKeyResolver`)
2. Signing key trust (`CompiledTrustPlan` over facts)
3. Signature verification (crypto using the resolved key)
4. Post-signature validation (`IPostSignatureValidator`)

Key security property: **trust is established before signature verification**. If trust fails, signature verification is marked `NotApplicable` (no signature-oracle behavior for untrusted inputs).

## Typical usage (DI)

Most callers configure validation through DI and then create a validator via `ICoseSign1ValidatorFactory`:

```csharp
using System.Security.Cryptography.Cose;
using CoseSign1.Validation;
using CoseSign1.Validation.DependencyInjection;
using Microsoft.Extensions.DependencyInjection;

var services = new ServiceCollection();

// Adds the staged validation "gate" and registers core message facts.
var validation = services.ConfigureCoseValidation();

// Enable one or more trust packs.
validation.EnableCertificateTrust();
validation.EnableMstTrust();

using var sp = services.BuildServiceProvider();

var validator = sp.GetRequiredService<ICoseSign1ValidatorFactory>().Create();

var message = CoseMessage.DecodeSign1(signatureBytes);
var result = message.Validate(validator);
```

## Result shape and metadata

`CoseSign1ValidationResult` contains per-stage results:

- `Resolution`: key material resolution
- `Trust`: signing key trust (trust plan)
- `Signature`: cryptographic signature verification
- `PostSignaturePolicy`: post-signature validators
- `Overall`: overall decision

The trust stage attaches structured metadata:

- `TrustDecision` (always when trust is evaluated)
- `TrustDecisionAudit` (when trust is evaluated; not present when `TrustEvaluationOptions.BypassTrust` is enabled)

See [Audit and Replay](../guides/audit-and-replay.md) for how to extract and interpret the audit payload.

## Customizing trust

### Defaults (trust packs)

Trust packs (`ITrustPack`) contribute **secure-by-default** plan fragments (constraints, trust sources, vetoes). The default compiled plan is created from the registered packs.

For most apps, enabling the desired trust packs is sufficient.

### Explicit requirements (TrustPlanPolicy)

If you need additional, deployment-specific requirements, author a `TrustPlanPolicy` and register a `CompiledTrustPlan` in DI:

```csharp
using CoseSign1.Validation.Trust;
using CoseSign1.Validation.Trust.Plan;

services.AddSingleton<CompiledTrustPlan>(sp =>
{
    var policy = TrustPlanPolicy.PrimarySigningKey(key =>
        key.RequireFact<MySigningKeyFact>(f => f.IsAllowed, "Signing key is not allowed"));

    return policy.Compile(sp);
});
```

Then create validators normally via `ICoseSign1ValidatorFactory` (it prefers an unkeyed `CompiledTrustPlan` registration when present).

## Extending the pipeline

- Add a new key material source: implement and register `ISigningKeyResolver`.
- Add business rules: implement and register `IPostSignatureValidator`.
- Add a reusable trust pack: implement `ITrustPack` and expose an opt-in `Enable*Trust(...)` extension.

See:

- [Custom Validators](../guides/custom-validators.md)
- [Validation Extension Packages](../guides/validation-extension-packages.md)
- [Trust Plan Deep Dive](../guides/trust-policy.md)
