# CoseSign1.Validation

Composable, stage-aware validation framework for COSE Sign1 messages with security-by-default semantics.

## Installation

```bash
dotnet add package CoseSign1.Validation
```

## Overview

This package provides:

- **Staged validation**: Four-stage pipeline (Resolution -> Trust -> Signature -> PostSignature)
- **Declarative trust policies**: Boolean expressions over trust claims
- **Composable validators**: Build complex validation from simple primitives
- **Security by default**: Trust evaluated before signature verification

## Quick Start

```csharp
using CoseSign1.Validation;
using System.Security.Cryptography.Cose;

// Decode COSE message
byte[] signedBytes = File.ReadAllBytes("document.cose");
var message = CoseMessage.DecodeSign1(signedBytes);

// Shorthand: Validate with inline configuration
var result = message.Validate(builder => builder
    .ValidateCertificate(cert => cert
        .NotExpired()
        .HasCommonName("Trusted Signer")
        .ValidateChain()));

// Or build a reusable validator
var validator = new CoseSign1ValidationBuilder()
    .ValidateCertificate(cert => cert
        .NotExpired()
        .ValidateChain())
    .Build();

var result = message.Validate(validator);

if (result.Overall.IsValid)
{
    Console.WriteLine("Verified!");
}
else
{
    foreach (var failure in result.Overall.Failures)
    {
        Console.WriteLine($"{failure.ErrorCode}: {failure.Message}");
    }
}
```

## Entry Points

### Extension Method (Shorthand)

For quick validation, use the `Validate()` extension method on `CoseSign1Message`:

```csharp
// Inline configuration - builds validator internally
var result = message.Validate(builder => builder
    .ValidateCertificate(cert => cert.ValidateChain()));

// With pre-built validator - reusable for multiple messages
var result = message.Validate(validator);
```

### Fluent Builder

Use `CoseSign1ValidationBuilder` to build reusable validators:

```csharp
var validator = new CoseSign1ValidationBuilder(loggerFactory)
    .AddComponent(myComponent)
    .OverrideDefaultTrustPolicy(policy)
    .Build();
```

## Validation Stages

| Stage | Order | Purpose |
|-------|-------|---------|
| KeyMaterialResolution | 0 | Extract certificates from headers |
| KeyMaterialTrust | 1 | Evaluate trust policy |
| Signature | 2 | Cryptographic verification |
| PostSignature | 3 | Additional business rules |

**Important**: Trust is evaluated BEFORE signature verification for security.

## Trust Policies

Declarative boolean expressions over typed signing-key assertions.
Assertions are facts emitted by validation components (e.g., "chain was trusted", "kid looked like AKV").
Policies decide which facts matter.

```csharp
// Simple requirement: an assertion type must be present
var policy = TrustPolicy.RequirePresent<MyAssertion>("MyAssertion must be present");

// Combined: multiple requirements must be satisfied
var policy = TrustPolicy.And(
    TrustPolicy.RequirePresent<MyAssertion>("MyAssertion must be present"),
    TrustPolicy.Require<MyOtherAssertion>(a => a.IsTrusted, "MyOtherAssertion must be trusted")
);

// Alternative paths
var policy = TrustPolicy.Or(
    TrustPolicy.Require<MyEnvironmentAssertion>(a => a.Name == "internal", "Must be internal"),
    TrustPolicy.Require<MyEnvironmentAssertion>(a => a.Name == "partner", "Must be partner")
);

// Conditional
var policy = TrustPolicy.Implies(
    TrustPolicy.Require<MyEnvironmentAssertion>(a => a.Name == "production", "Must be production"),
    TrustPolicy.RequirePresent<MyProductionReadyAssertion>("Production-ready assertion is required in production")
);
```

## Trust model rework (in progress)

This repo is evolving toward the TrustPlan / Facts + Rules model described in [V2/proposal.md](../proposal.md).
As a first step, the package now includes core contracts for stable subject identities and multi-valued facts:

- `TrustSubjectId` and `TrustIds` (stable SHA-256 based IDs)
- `TrustSubject` and `TrustSubjectKind`
- `TrustFactSet<TFact>` and `TrustFactMissing`
- `TrustEvaluationOptions` (includes `BypassTrust`)

The existing `TrustPolicy` model remains the default trust stage. However, the staged validator now also supports TrustPlan evaluation when a compiled `TrustPlan` is supplied.

Use TrustPlan validation (auto-discovery + plan):

```csharp
var trustPlan = TrustPlan.CompileDefaults(serviceProvider);
var result = message.Validate(trustPlan);
```

Bypass trust evaluation (still performs cryptographic signature verification):

```csharp
var trustPlan = TrustPlan.CompileDefaults(serviceProvider);
var result = message.Validate(
    trustPlan,
    trustEvaluationOptions: new TrustEvaluationOptions { BypassTrust = true });
```

Additional contracts now exist for fact production:

- `TrustFactEngine` (per-validation memoization)
- `IMultiTrustFactProducer` and `TrustFactContext`
- Producer-owned cross-validation caching via `TrustFactContext.MemoryCache` and `TrustFactCacheKey`
- Budget-related missing reasons via `TrustFactMissingCodes`

Step 5 adds the initial rules + plan layer:

- `TrustRule` and `TrustRules` (boolean combinators + quantifiers)
- `OnEmptyBehavior`
- `TrustPlan` and `TrustPlan.CompileDefaults(IServiceProvider)`
- `ITrustPlanDefaultsProvider` and `TrustPlanDefaults` (constraints/sources/vetoes)

Step 6 adds an auditable evaluation result:

- `TrustDecisionAudit` (schema versioned) + related audit record types
- `TrustPlan.EvaluateWithAudit(...)` and `TrustPlan.EvaluateWithAuditAsync(...)`

## Creating Custom Validators

```csharp
public class CustomValidator : IValidator
{
    public IReadOnlyCollection<ValidationStage> Stages =>
        new[] { ValidationStage.PostSignature };

    public ValidationResult Validate(CoseSign1Message input, ValidationStage stage)
    {
        if (!IsValid(input))
        {
            return ValidationResult.Failure(
                "CustomValidator",
                stage,
                new ValidationFailure
                {
                    ErrorCode = "CUSTOM_CHECK_FAILED",
                    Message = "Custom validation failed"
                });
        }
        
        return ValidationResult.Success("CustomValidator", stage);
    }

    public Task<ValidationResult> ValidateAsync(
        CoseSign1Message input,
        ValidationStage stage,
        CancellationToken ct) => Task.FromResult(Validate(input, stage));
}
```

## Key Types

- `Cose` - Entry point for building validators
- `ICoseSign1ValidationBuilder` - Fluent builder interface
- `CoseSign1Validator` - Built validator
- `IValidator` - Validator interface
- `ValidationStage` - Stage enum
- `ValidationResult` - Validation result
- `TrustPolicy` - Declarative trust policy
- `TrustAssertion` - Trust claim assertion

## Documentation

- [Validation Framework](../docs/architecture/validation-framework.md)
- [Trust Policy Guide](../docs/guides/trust-policy.md)
- [Trust contracts (work in progress)](../docs/architecture/trust-contracts.md)
