# CoseSign1.Validation

Comprehensive validation framework for COSE Sign1 messages with composable validators.

## Installation

```bash
dotnet add package CoseSign1.Validation --version 2.0.0-preview
```

## Overview

A flexible, extensible validation framework for COSE Sign1 messages. Build custom validation pipelines using built-in validators or create your own with the fluent builder API.

## Key Features

- ✅ **Fluent Builder API** - Easy validation pipeline construction
- ✅ **Composable Validators** - Combine multiple validators
- ✅ **Built-in Validators** - Signature, certificate, chain validators
- ✅ **Function Validators** - Inline lambda validation
- ✅ **Rich Results** - Detailed error information
- ✅ **Extensible** - Easy to add custom validation logic

## Quick Start

### Basic Validation

```csharp
using CoseSign1.Validation;
using System.Security.Cryptography.Cose;

// Decode message
byte[] signedBytes = File.ReadAllBytes("document.cose");
CoseSign1Message message = CoseMessage.DecodeSign1(signedBytes);

// Build validator
var validator = Cose.Sign1Message()
    .ValidateCertificateSignature()
    .Build();

// Validate
var result = validator.Validate(message);

if (result.IsValid)
{
    Console.WriteLine("Signature is valid!");
}
else
{
    foreach (var error in result.Errors)
    {
        Console.WriteLine($"Error: {error.Message}");
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

var result = validator.Validate(message);
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
    .AddValidator(msg =>
    {
        // Check custom header
        var customHeader = msg.ProtectedHeaders.TryGetValue(
            new CoseHeaderLabel("custom"), out var value);
        
        return customHeader
            ? ValidationResult.Success()
            : ValidationResult.Failed("Missing custom header");
    })
    .Build();
```

## Entry Point

The `Cose` static class provides the entry point for building validators:

```csharp
// Start building a CoseSign1Message validator
var builder = Cose.Sign1Message();

// Add validators using fluent API
builder.ValidateCertificateSignature();
builder.ValidateCertificate(cert => cert.NotExpired());

// Build the composite validator
IValidator<CoseSign1Message> validator = builder.Build();
```

## Core Types

### IValidator<T>

The core validation interface:

```csharp
public interface IValidator<in T>
{
    ValidationResult Validate(T input);
}
```

### ValidationResult

Result of validation operation:

```csharp
public class ValidationResult
{
    // Whether validation passed
    public bool IsValid { get; }
    
    // Collection of validation errors
    public IReadOnlyList<ValidationError> Errors { get; }
    
    // Create success result
    public static ValidationResult Success();
    
    // Create failure result
    public static ValidationResult Failed(string message);
    public static ValidationResult Failed(ValidationError error);
}
```

### ValidationError

Details about a validation failure:

```csharp
public class ValidationError
{
    public string Source { get; set; }
    public string Message { get; set; }
    public ValidationErrorCode Code { get; set; }
    public IDictionary<string, object>? Metadata { get; set; }
}
```

### CompositeValidator

Combines multiple validators:

```csharp
var composite = new CompositeValidator(
    new IValidator<CoseSign1Message>[] 
    { 
        validator1, 
        validator2, 
        validator3 
    },
    stopOnFirstFailure: false,
    runInParallel: false);

var result = composite.Validate(message);
```

### FunctionValidator

Wrap a lambda as a validator:

```csharp
var validator = new FunctionValidator<CoseSign1Message>(
    message =>
    {
        // Custom validation logic
        if (SomeCondition(message))
            return ValidationResult.Success();
        else
            return ValidationResult.Failed("Validation failed");
    },
    name: "CustomValidator");
```

## Built-in Validators

### CoseMessageValidationBuilder Extensions

```csharp
builder
    // Signature validation
    .ValidateCertificateSignature()
    
    // Certificate validation
    .ValidateCertificate(cert => cert
        .NotExpired()
        .NotExpired(asOf: specificDate)
        .HasCommonName("Expected CN")
        .HasEnhancedKeyUsage("1.3.6.1.5.5.7.3.3")
        .HasKeyUsage(X509KeyUsageFlags.DigitalSignature)
        .Matches(c => c.Subject.Contains("Contoso"), "Must be Contoso cert"))
    
    // Chain validation
    .ValidateCertificateChain(chain => chain
        .WithTrustedRoots(caCertificates)
        .AllowUntrusted(false)
        .TrustUserRoots(true))
    
    // Custom validators
    .AddValidator(customValidator)
    .AddValidator(validationFunc);
```

## Custom Validators

### Function-Based

```csharp
var validator = Cose.Sign1Message()
    .AddValidator(message =>
    {
        // Access protected headers
        if (!message.ProtectedHeaders.TryGetValue(
            CoseHeaderLabel.ContentType, out var contentType))
        {
            return ValidationResult.Failed(new ValidationError
            {
                Source = "ContentTypeValidator",
                Message = "Content type header is required",
                Code = ValidationErrorCode.MissingHeader
            });
        }
        
        return ValidationResult.Success();
    })
    .Build();
```

### Class-Based

```csharp
public class IssuerValidator : IValidator<CoseSign1Message>
{
    private readonly string[] AllowedIssuers;
    
    public IssuerValidator(params string[] allowedIssuers)
    {
        AllowedIssuers = allowedIssuers;
    }
    
    public ValidationResult Validate(CoseSign1Message message)
    {
        // Extract issuer from CWT claims
        var claims = message.GetCwtClaims();
        
        if (claims?.Issuer == null)
        {
            return ValidationResult.Failed(new ValidationError
            {
                Source = nameof(IssuerValidator),
                Message = "No issuer claim found",
                Code = ValidationErrorCode.MissingClaim
            });
        }
        
        if (!AllowedIssuers.Contains(claims.Issuer))
        {
            return ValidationResult.Failed(new ValidationError
            {
                Source = nameof(IssuerValidator),
                Message = $"Issuer '{claims.Issuer}' is not trusted",
                Code = ValidationErrorCode.UntrustedIssuer,
                Metadata = new Dictionary<string, object>
                {
                    ["ActualIssuer"] = claims.Issuer,
                    ["AllowedIssuers"] = AllowedIssuers
                }
            });
        }
        
        return ValidationResult.Success();
    }
}

// Usage
var validator = Cose.Sign1Message()
    .AddValidator(new IssuerValidator(
        "https://trusted.example.com",
        "https://another-trusted.example.com"))
    .Build();
```

## Configuration Options

### Stop On First Failure

```csharp
var validator = Cose.Sign1Message()
    .ValidateCertificateSignature()
    .ValidateCertificate(cert => cert.NotExpired())
    .StopOnFirstFailure(true)  // Stop at first error
    .Build();
```

### Parallel Validation

```csharp
var validator = Cose.Sign1Message()
    .ValidateCertificateSignature()
    .ValidateCertificate(cert => cert.NotExpired())
    .RunInParallel(true)  // Run validators concurrently
    .Build();
```

## Error Codes

```csharp
public enum ValidationErrorCode
{
    Unknown,
    SignatureInvalid,
    CertificateExpired,
    CertificateNotYetValid,
    ChainBuildFailed,
    ChainValidationFailed,
    CommonNameMismatch,
    EkuMismatch,
    KeyUsageMismatch,
    MissingCertificate,
    MissingHeader,
    MissingClaim,
    UntrustedIssuer,
    CustomValidationFailed
}
```

## Testing

Validators are easily testable:

```csharp
[Fact]
public void Validator_WithExpiredCertificate_ReturnsFailure()
{
    // Arrange
    var expiredCert = CreateExpiredCertificate();
    var message = CreateSignedMessage(expiredCert);
    
    var validator = Cose.Sign1Message()
        .ValidateCertificate(cert => cert.NotExpired())
        .Build();
    
    // Act
    var result = validator.Validate(message);
    
    // Assert
    Assert.False(result.IsValid);
    Assert.Contains(result.Errors, 
        e => e.Code == ValidationErrorCode.CertificateExpired);
}
```

## See Also

- [CoseSign1.Certificates](../CoseSign1.Certificates/README.md) - Certificate validators
- [CoseSign1](../CoseSign1/README.md) - Signature factories
- [Architecture Overview](../docs/architecture/overview.md) - System architecture
