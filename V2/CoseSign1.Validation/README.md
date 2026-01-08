# CoseSign1.Validation

Composable, stage-aware validation primitives for COSE Sign1 messages.

## Installation

```bash
dotnet add package CoseSign1.Validation --version 2.0.0-preview
```

## Overview

This package provides:

- Stage-aware validators (`IValidator`) for `CoseSign1Message`
- `CompositeValidator` for aggregating validators within a stage
- `AnySignatureValidator` for signature strategy selection
- Result types (`ValidationResult`, `ValidationFailure`) that support Success/Failure/NotApplicable

For end-to-end verification (trust-first staged orchestration), use `CoseSign1Verifier` or `Cose.Sign1Verifier()`.

## Key Features

- ✅ **Stage-aware validators** - Validators declare `ValidationStage` participation
- ✅ **Composable** - Combine multiple validators with `CompositeValidator`
- ✅ **Signature orchestration** - Require at least one applicable verifier via `AnySignatureValidator`
- ✅ **Rich results** - Success/Failure/NotApplicable, failures + metadata
- ✅ **Extensible** - Add custom validation logic via interfaces or functions

## Quick Start

### Basic Validation

```csharp
using CoseSign1.Validation;
using CoseSign1.Verification;
using System.Security.Cryptography.Cose;

// Decode message
byte[] signedBytes = File.ReadAllBytes("document.cose");
CoseSign1Message message = CoseSign1Message.DecodeSign1(signedBytes);

// Build a staged verifier pipeline.
// NOTE: Signature validators must be provided; trust policy is evaluated before signature.
var pipeline = Cose.Sign1Verifier()
    .WithTrustPolicy(TrustPolicy.AllowAll("Demo"))
    .WithSignatureValidators(new IValidator[]
    {
        // Example: you can plug in signature validators from other packages.
        // new CertificateSignatureValidator(allowUnprotectedHeaders: true)
    })
    .Build();

// Verify
var result = pipeline.Verify(message);

if (result.Overall.IsValid)
{
    Console.WriteLine("Verified!");
}
else
{
    foreach (var failure in result.Overall.Failures)
    {
        Console.WriteLine($"Failure: {failure.ErrorCode}: {failure.Message}");
    }
}
```

### Certificate Validation Pipeline

```csharp
var validator = Cose.Sign1Message()
    .ValidateCertificateSignature()
    .ValidateCertificate(cert => cert
        .NotExpired()
        .HasCommonName("Trusted Signer")
        .HasEnhancedKeyUsage("1.3.6.1.5.5.7.3.3"))
    .Build();

var signatureResult = validator.Validate(message, ValidationStage.Signature);
var postSignatureResult = validator.Validate(message, ValidationStage.PostSignature);
```

### Complete Validation Pipeline

```csharp
var validator = Cose.Sign1Message()
    // Verify cryptographic signature
    .ValidateCertificateSignature()
    
    // Certificate property validation
    .ValidateCertificate(cert => cert
        .NotExpired()
        .HasCommonName("Production Signer"))
    
    // Chain validation with custom roots
    .ValidateCertificateChain(chain => chain
        .WithTrustedRoots(trustedCaCertificates)
        .AllowUntrusted(false))
    
    // Custom validation
    .AddValidator((msg, stage) =>
    {
        const string validatorName = "CustomHeaderValidator";

        if (stage != ValidationStage.PostSignature)
        {
            return ValidationResult.NotApplicable(validatorName, stage);
        }

        // Check custom header
        bool hasCustomHeader = msg.ProtectedHeaders.TryGetValue(
            new CoseHeaderLabel("custom"), out _);
        
        return hasCustomHeader
            ? ValidationResult.Success(validatorName, stage)
            : ValidationResult.Failure(validatorName, stage, "Missing custom header");
    })
    .Build();

var signatureResult = validator.Validate(message, ValidationStage.Signature);
var postSignatureResult = validator.Validate(message, ValidationStage.PostSignature);
```

## Entry Points

The `Cose` static class provides two entry points:

- `Cose.Sign1Message()` builds a stage-aware `IValidator`.
- `Cose.Sign1Verifier()` builds a staged verification pipeline.

## Core Types

### ValidationStage

```csharp
public enum ValidationStage
{
    KeyMaterialResolution,
    KeyMaterialTrust,
    Signature,
    PostSignature,
}
```

### IValidator

```csharp
public interface IValidator
{
    IReadOnlyCollection<ValidationStage> Stages { get; }
    ValidationResult Validate(CoseSign1Message input, ValidationStage stage);
    Task<ValidationResult> ValidateAsync(CoseSign1Message input, ValidationStage stage, CancellationToken cancellationToken = default);
}
```

### ValidationResult / ValidationFailure

```csharp
public sealed class ValidationResult
{
    public ValidationResultKind Kind { get; init; }
    public ValidationStage? Stage { get; init; }

    public bool IsValid { get; }
    public bool IsFailure { get; }
    public bool IsNotApplicable { get; }

    public string ValidatorName { get; init; }
    public IReadOnlyList<ValidationFailure> Failures { get; init; }
    public IReadOnlyDictionary<string, object> Metadata { get; init; }
}

public sealed class ValidationFailure
{
    public string Message { get; init; }
    public string? ErrorCode { get; init; }
    public Exception? Exception { get; init; }
}
```

### CompositeValidator

Combines multiple validators:

```csharp
var composite = new CompositeValidator(
    new IValidator[] { validator1, validator2, validator3 },
    stopOnFirstFailure: false,
    runInParallel: false);

var result = composite.Validate(message, ValidationStage.PostSignature);
```

### Custom validators

The staged verifier builder composes `IValidator` instances into a verification pipeline.
Implement `IValidator` to run at one or more `ValidationStage` values.

## Built-in validators

This package contains core orchestration validators (e.g., `CompositeValidator`, `AnySignatureValidator`).
Domain-specific validators (X.509, MST, etc.) live in their respective packages.

### Verification builder extensions

```csharp
var verifier = Cose.Sign1Message()
    .AllowAllTrust("example")
    // Signature validation
    .ValidateCertificateSignature()
    .Build();

var result = verifier.Verify(message);
```

## Custom Validators

### Implementing a stage-specific validator

```csharp
private sealed class ContentTypeValidator : IValidator
{
    public IReadOnlyCollection<ValidationStage> Stages { get; } = new[] { ValidationStage.PostSignature };

    public ValidationResult Validate(CoseSign1Message input, ValidationStage stage)
    {
        const string validatorName = "ContentTypeValidator";

        if (!input.ProtectedHeaders.TryGetValue(CoseHeaderLabel.ContentType, out _))
        {
            return ValidationResult.Failure(
                validatorName,
                stage,
                "Content type header is required",
                errorCode: "MissingHeader");
        }

        return ValidationResult.Success(validatorName, stage);
    }

    public Task<ValidationResult> ValidateAsync(CoseSign1Message input, ValidationStage stage, CancellationToken cancellationToken = default)
        => Task.FromResult(Validate(input, stage));
}

var verifier = Cose.Sign1Message()
    .AllowAllTrust("example")
    .AddPostSignatureValidator(new ContentTypeValidator())
    .Build();

var result = verifier.Verify(message);
```

## Testing

```csharp
[Fact]
public void Validator_ReturnsFailures_OnInvalidInput()
{
    var validator = Cose.Sign1Message()
        .AddValidator((message, stage) =>
            stage == ValidationStage.PostSignature
                ? ValidationResult.Failure("TestValidator", stage, "Some failure", errorCode: "SomeCode")
                : ValidationResult.NotApplicable("TestValidator", stage))
        .Build();

    var result = validator.Validate(message, ValidationStage.PostSignature);

    Assert.False(result.IsValid);
    Assert.Contains(result.Failures, f => f.ErrorCode == "SomeCode");
}
```

## See Also

- [docs/architecture/validation-framework.md](../docs/architecture/validation-framework.md)
- [docs/cli/verify.md](../docs/cli/verify.md)
- [CoseSign1.Certificates/README.md](../CoseSign1.Certificates/README.md)
