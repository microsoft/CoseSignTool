# CoseSign1.Validation Package

**NuGet**: `CoseSign1.Validation`  
**Purpose**: Composable, stage-aware validation framework for COSE Sign1 messages

## Overview

This package defines a small set of primitives for validating `CoseSign1Message`:

- `ValidationStage` for stage-aware orchestration
- `IValidator` returns a `ValidationResult` for a specific stage
- `CompositeValidator` aggregates multiple validators for a stage
- `IConditionalValidator` can opt out when not applicable
- `AnySignatureValidator` orchestrates multiple signature validators

For end-to-end verification (trust-first staged verification), the preferred entry point is an immutable `CoseSign1VerificationPipeline` built via `Cose.Sign1Verifier()`.

`CoseSign1Verifier` is the underlying orchestration engine used by the pipeline.

## Core types

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
    public bool IsValid { get; init; }
    public string ValidatorName { get; init; } = string.Empty;
    public IReadOnlyList<ValidationFailure> Failures { get; init; } = Array.Empty<ValidationFailure>();

    public static ValidationResult Success(string validatorName, IDictionary<string, object>? metadata = null);
    public static ValidationResult Failure(string validatorName, params ValidationFailure[] failures);
    public static ValidationResult Failure(string validatorName, string message, string? errorCode = null);
}

public sealed class ValidationFailure
{
    public string Message { get; init; } = string.Empty;
    public string? ErrorCode { get; init; }
    public string? PropertyName { get; init; }
    public object? AttemptedValue { get; init; }
    public Exception? Exception { get; init; }
}
```

## Composition

### CompositeValidator

Use `CompositeValidator` to run multiple validators and aggregate failures.

```csharp
var validator = new CompositeValidator(new IValidator[]
{
    // Key material resolution (e.g., parse x5t/x5chain)
    new CertificateKeyMaterialResolutionValidator(allowUnprotectedHeaders: true),

    // Trust evaluation (e.g., chain build)
    new CertificateChainValidator(allowUnprotectedHeaders: true),
});

ValidationResult trustResult = validator.Validate(message, ValidationStage.KeyMaterialTrust);
```

### Conditional validators

Implement `IConditionalValidator` when a validator is only meaningful for some inputs.

```csharp
public sealed class MyOptionalValidator :
    IValidator,
    IConditionalValidator
{
    public IReadOnlyCollection<ValidationStage> Stages => new[] { ValidationStage.PostSignature };

    public bool IsApplicable(CoseSign1Message message, ValidationStage stage)
        => /* e.g., header present */ true;

    public ValidationResult Validate(CoseSign1Message message, ValidationStage stage)
        => ValidationResult.Success(nameof(MyOptionalValidator), stage);

    public Task<ValidationResult> ValidateAsync(CoseSign1Message message, ValidationStage stage, CancellationToken cancellationToken = default)
        => Task.FromResult(Validate(message, stage));
}
```

`CompositeValidator` skips non-applicable conditional validators.

## Signature validation orchestration

Some signatures can be verified via multiple strategies (certificate headers, plugin-provided key verification, etc.). V2 supports this by requiring **at least one applicable signature validator** to succeed.

```csharp
var signatureValidator = new AnySignatureValidator(new IValidator[]
{
    // Certificate signature validator, plugin validators, etc.
    new CertificateSignatureValidator(allowUnprotectedHeaders: true),
});

ValidationResult sigResult = signatureValidator.Validate(message, ValidationStage.Signature);
```

## See Also

- [Architecture: Validation Framework](../architecture/validation-framework.md)
- [Certificates Component](certificates.md)
- [Custom Validators Guide](../guides/custom-validators.md)
