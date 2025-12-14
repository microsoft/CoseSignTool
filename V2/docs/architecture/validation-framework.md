# Validation Framework

This document describes the composable validation framework in CoseSignTool V2.

## Overview

The validation framework provides a composable, extensible system for validating COSE Sign1 messages. Validators can be chained together to create complex validation pipelines.

## Core Concepts

### IValidator Interface

```csharp
public interface IValidator<T>
{
    string Name { get; }
    string Description { get; }
    
    ValidationResult Validate(T target);
    
    Task<ValidationResult> ValidateAsync(
        T target, 
        CancellationToken cancellationToken = default);
}
```

### ValidationResult

```csharp
public sealed class ValidationResult
{
    public bool IsValid { get; }
    public IReadOnlyList<ValidationFailure> Failures { get; }
    
    public static ValidationResult Success() => new(true, []);
    public static ValidationResult Failure(string message) => 
        new(false, [new ValidationFailure(message)]);
}
```

## Built-in Validators

### Signature Validators

| Validator | Description |
|-----------|-------------|
| `SignatureValidator` | Validates cryptographic signature |
| `CertificateSignatureValidator` | Validates signature with certificate |
| `CertificateDetachedSignatureValidator` | Validates detached signatures |

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
    new SignatureValidator(),
    new CertificateChainValidator(trustedRoots),
    new CertificateExpirationValidator()
);

var result = validator.Validate(message);
```

### Using Validation Builder

```csharp
var validator = new CoseMessageValidationBuilder()
    .AddValidator(new SignatureValidator())
    .AddCertificateValidator(cert => cert
        .ValidateSignature()
        .NotExpired()
        .HasCommonName("Trusted Signer")
        .HasEku(Oids.CodeSigning))
    .Build();
```

### Using Fluent Extensions

```csharp
var result = message.ValidateSignature()
    .ValidateCertificate(cert => cert
        .NotExpired()
        .HasCommonName("My CA"));
```

## Creating Custom Validators

```csharp
public class PayloadSizeValidator : IValidator<CoseSign1Message>
{
    private readonly int _maxSize;
    
    public string Name => "PayloadSize";
    public string Description => $"Validates payload is under {_maxSize} bytes";
    
    public PayloadSizeValidator(int maxSize) => _maxSize = maxSize;
    
    public ValidationResult Validate(CoseSign1Message message)
    {
        if (!message.Content.HasValue)
            return ValidationResult.Success(); // Detached signature
            
        if (message.Content.Value.Length > _maxSize)
            return ValidationResult.Failure(
                $"Payload size {message.Content.Value.Length} exceeds maximum {_maxSize}");
                
        return ValidationResult.Success();
    }
    
    public Task<ValidationResult> ValidateAsync(
        CoseSign1Message message,
        CancellationToken cancellationToken = default)
    {
        return Task.FromResult(Validate(message));
    }
}
```

## Validation Pipeline

```
Message → Signature Validation → Certificate Extraction → Chain Validation → Custom Validators → Result
```

### Pipeline Configuration

```csharp
var pipeline = new ValidationPipelineBuilder()
    .AddStage("signature", new SignatureValidator())
    .AddStage("chain", new CertificateChainValidator())
    .AddStage("expiration", new CertificateExpirationValidator())
    .AddStage("custom", new PayloadSizeValidator(1024 * 1024))
    .Build();
```

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
