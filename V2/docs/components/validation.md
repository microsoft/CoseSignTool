# CoseSign1.Validation Package

**NuGet**: `CoseSign1.Validation`  
**Purpose**: Component-based validation pipeline for COSE Sign1 messages

## What this package provides

This package defines the core primitives for V2 validation:

- `ICoseSign1Validator` and `CoseSign1ValidationBuilder`
- `IValidationComponent` base interface and stage-specific interfaces:
  - `ISigningKeyResolver`
  - `ISigningKeyAssertionProvider`
  - `IPostSignatureValidator`
- `TrustPolicy` (typed assertion-based)
- `CoseSign1Message` extension methods: `Validate(...)` / `ValidateAsync(...)`

Validation in V2 is **trust-first**:

1. Resolve signing key material (resolvers)
2. Evaluate trust policy (assertion providers + policy)
3. Verify signature (crypto)
4. Run post-signature checks (post-signature validators)

## Quick start

```csharp
using CoseSign1.Certificates.Validation;
using CoseSign1.Validation;
using System.Security.Cryptography.Cose;

var message = CoseMessage.DecodeSign1(signatureBytes);

// Option 1: Inline configuration
var result1 = message.Validate(builder => builder
    .ValidateCertificate(cert => cert
        .NotExpired()
        .HasCommonName("MySigner")
        .ValidateChain()));

// Option 2: Reusable validator
var validator = new CoseSign1ValidationBuilder()
    .ValidateCertificate(cert => cert
        .NotExpired()
        .HasCommonName("MySigner")
        .ValidateChain())
    .Build();

var result2 = message.Validate(validator);
```

## Writing your own validation components

Choose the stage-specific interface based on where your logic belongs:

- `ISigningKeyResolver` — extract key material from headers (x5chain, kid, etc.)
- `ISigningKeyAssertionProvider` — emit trust assertions for policy evaluation
- `IPostSignatureValidator` — business rules that require full context (resolved key, trust decision, signature metadata, options)

Components opt out via `IValidationComponent.IsApplicableTo(message, options)`.
To get caching for applicability checks, inherit from `ValidationComponentBase`.

## See Also

- [Architecture: Validation Framework](../architecture/validation-framework.md)
- [Trust Policy Guide](../guides/trust-policy.md)
- [Certificates Component](certificates.md)
- [Custom Validators Guide](../guides/custom-validators.md)
- [Validation Extension Packages](../guides/validation-extension-packages.md)
