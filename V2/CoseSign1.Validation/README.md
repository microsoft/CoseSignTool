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
using CoseSign1.Validation.Extensions;
using System.Security.Cryptography.Cose;

// Decode COSE message
byte[] signedBytes = File.ReadAllBytes("document.cose");
var message = CoseSign1Message.DecodeSign1(signedBytes);

// Shorthand: Validate with inline configuration
var result = message.Validate(builder => builder
    .ValidateCertificate(cert => cert
        .NotExpired()
        .HasCommonName("Trusted Signer")
        .ValidateChain()));

// Or build a reusable validator
var validator = Cose.Sign1Message()
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
using CoseSign1.Validation.Extensions;

// Inline configuration - builds validator internally
var result = message.Validate(builder => builder
    .ValidateCertificate(cert => cert.ValidateChain()));

// With pre-built validator - reusable for multiple messages
var result = message.Validate(validator);
```

### Fluent Builder

The `Cose` static class provides the fluent entry point for building reusable validators:

```csharp
var validator = Cose.Sign1Message(loggerFactory)
    .AddValidator(myValidator)
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

Declarative boolean expressions over trust claims:

```csharp
// Simple claim
var policy = TrustPolicy.Claim("x509.chain.trusted");

// Combined
var policy = TrustPolicy.And(
    TrustPolicy.Claim("x509.chain.trusted"),
    TrustPolicy.Claim("cert.notexpired")
);

// Alternative paths
var policy = TrustPolicy.Or(
    TrustPolicy.Claim("issuer.internal"),
    TrustPolicy.Claim("issuer.partner")
);

// Conditional
var policy = TrustPolicy.Implies(
    TrustPolicy.Claim("env.production"),
    TrustPolicy.Claim("cert.production")
);
```

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
