# Validation Framework

This document describes the composable validation framework in CoseSignTool V2.

## Overview

The validation framework provides a composable, extensible system for validating COSE Sign1 messages. Validators can be chained together to create complex validation pipelines.

## Core Concepts

### IValidator Interface

```csharp
public interface IValidator<T>
{
    ValidationResult Validate(T input);

    Task<ValidationResult> ValidateAsync(
        T input,
        CancellationToken cancellationToken = default);
}
```

### Conditional Validators

Some validators are only meaningful when a message contains certain headers/content.

Validators can optionally implement `IConditionalValidator<T>` to indicate whether they apply to a given input. When used under `CompositeValidator`, non-applicable validators are skipped.

```csharp
public interface IConditionalValidator<in T>
{
    bool IsApplicable(T input);
}
```

Examples:
- X.509 / certificate validators only apply when `x5t` + `x5chain` headers exist.
- MST receipt validation only applies when a receipt is present.

### ValidationResult

```csharp
public sealed class ValidationResult
{
    public bool IsValid { get; }
    public string ValidatorName { get; }
    public IReadOnlyList<ValidationFailure> Failures { get; }
}
```

## Built-in Validators

### Signature Validators

Signature validation is treated as a distinct stage during verification. Multiple signature validators may exist (certificate-based, key-based, plugin-provided, etc.).

| Validator | Description |
|-----------|-------------|
| `CertificateSignatureValidator` | Verifies signature using certificate from `x5t`/`x5chain` headers (embedded or detached) |
| `AnySignatureValidator` | Aggregates multiple signature validators; requires at least one applicable validator to succeed |

### Certificate Validators

| Validator | Description |
|-----------|-------------|
| `CertificateChainValidator` | Validates certificate chain |
| `CertificateExpirationValidator` | Checks certificate validity period |
| `CertificateCommonNameValidator` | Validates certificate CN |
| `CertificateKeyUsageValidator` | Validates EKU/key usage |

### Transparency Validators

| Validator | Description |
|-----------|-------------|
| `MstReceiptPresenceValidator` | Requires MST receipt |
| `MstReceiptValidator` | Validates MST receipt |

## Composing Validators

### Using CompositeValidator

```csharp
var validator = new CompositeValidator<CoseSign1Message>(
    new CertificateSignatureValidator(allowUnprotectedHeaders: true),
    new CertificateChainValidator(allowUnprotectedHeaders: true),
    new CertificateExpirationValidator(allowUnprotectedHeaders: true)
);

var result = validator.Validate(message);
```

### Using Validation Builder

```csharp
var validator = Cose.Sign1Message()
    .AddCertificateValidator(b => b
        .AllowUnprotectedHeaders()
        .ValidateSignature()
        .ValidateExpiration()
        .ValidateCommonName("Trusted Signer"))
    .Build();
```

### Using Fluent Extensions

```csharp
var validator = Cose.Sign1Message()
    .AddCertificateValidator(b => b
        .ValidateSignature()
        .ValidateExpiration()
        .ValidateCommonName("My CA"))
    .Build();

var result = await validator.ValidateAsync(message);
```

## Creating Custom Validators

```csharp
public class PayloadSizeValidator : IValidator<CoseSign1Message>
{
    private readonly int _maxSize;

    private const string ValidatorName = nameof(PayloadSizeValidator);
    
    public PayloadSizeValidator(int maxSize) => _maxSize = maxSize;
    
    public ValidationResult Validate(CoseSign1Message message)
    {
        // Detached signature: no embedded payload to validate for size.
        if (message is null || message.Content is null)
            return ValidationResult.Success(ValidatorName);
            
        if (message.Content.Value.Length > _maxSize)
            return ValidationResult.Failure(
                ValidatorName,
                $"Payload size {message.Content.Value.Length} exceeds maximum {_maxSize}");

        return ValidationResult.Success(ValidatorName);
    }
    
    public Task<ValidationResult> ValidateAsync(
        CoseSign1Message message,
        CancellationToken cancellationToken = default)
    {
        return Task.FromResult(Validate(message));
    }
}
```

## Signature Validation Orchestration

Verification composes signature validators so that **at least one applicable signature validator must succeed**.

This enables scenarios like:
- verifying signatures using embedded X.509 headers when present,
- verifying “key-only” signatures supplied by a plugin (for example, when a public key is embedded as a `COSE_Key` header),
- skipping irrelevant validators automatically.

## Error Handling

```csharp
var result = validator.Validate(message);

if (!result.IsValid)
{
    foreach (var failure in result.Failures)
    {
        Console.WriteLine($"Validation failed: {failure.Message}");
        Console.WriteLine($"  Validator: {failure.ValidatorName}");
        Console.WriteLine($"  Code: {failure.Code}");
    }
}
```

## See Also

- [Creating Custom Validators](../guides/custom-validators.md)
- [CoseSign1.Validation](../components/validation.md)
- [Certificate Chain Validation](../guides/chain-validation.md)
