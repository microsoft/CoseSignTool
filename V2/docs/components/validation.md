# CoseSign1.Validation Package

**NuGet**: `CoseSign1.Validation`  
**Purpose**: Composable validation framework for COSE Sign1 messages

## Overview

This package defines a small set of primitives for validating `CoseSign1Message`:

- `IValidator<T>` returns a `ValidationResult`
- `CompositeValidator` aggregates multiple validators
- Conditional validators (`IConditionalValidator<T>`) can opt out when not applicable
- Signature validation can be orchestrated via `ISignatureValidator` + `AnySignatureValidator`

## Core types

### IValidator<T>

```csharp
public interface IValidator<in T>
{
    ValidationResult Validate(T input);

    Task<ValidationResult> ValidateAsync(
        T input,
        CancellationToken cancellationToken = default);
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
var validator = new CompositeValidator(new IValidator<CoseSign1Message>[]
{
    // Signature verification (certificate headers)
    new CertificateSignatureValidator(allowUnprotectedHeaders: true),

    // Certificate property checks
    new CertificateExpirationValidator(allowUnprotectedHeaders: true),
});

ValidationResult result = validator.Validate(message);
```

### Conditional validators

Implement `IConditionalValidator<T>` when a validator is only meaningful for some inputs.

```csharp
public sealed class MyOptionalValidator :
    IValidator<CoseSign1Message>,
    IConditionalValidator<CoseSign1Message>
{
    public bool IsApplicable(CoseSign1Message message)
        => /* e.g., header present */ true;

    public ValidationResult Validate(CoseSign1Message message)
        => ValidationResult.Success(nameof(MyOptionalValidator));
}
```

`CompositeValidator` skips non-applicable conditional validators.

## Signature validation orchestration

Some signatures can be verified via multiple strategies (certificate headers, plugin-provided key verification, etc.). V2 supports this by requiring **at least one applicable signature validator** to succeed.

```csharp
var signatureValidator = new AnySignatureValidator(new IValidator<CoseSign1Message>[]
{
    // Certificate signature validator, plugin validators, etc.
    new CertificateSignatureValidator(allowUnprotectedHeaders: true),
});

ValidationResult sigResult = signatureValidator.Validate(message);
```

## See Also

- [Architecture: Validation Framework](../architecture/validation-framework.md)
- [Certificates Component](certificates.md)
- [Custom Validators Guide](../guides/custom-validators.md)
