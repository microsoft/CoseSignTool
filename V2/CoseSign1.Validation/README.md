# CoseSign1.Validation

Comprehensive validation framework for COSE Sign1 messages with composable validators.

## Overview

A flexible, extensible validation framework for COSE Sign1 messages. Build custom validation pipelines using built-in validators or create your own with the fluent builder API.

## Installation

```bash
dotnet add package CoseSign1.Validation --version 2.0.0-preview
```

## Key Features

- ✅ **Composable Validators** - Combine multiple validators into pipelines
- ✅ **Fluent Builder API** - Easy-to-use validation pipeline construction
- ✅ **Built-in Validators** - Signature, chain, EKU, SAN validators
- ✅ **Custom Validation** - Function-based and class-based custom validators
- ✅ **Rich Results** - Detailed failure information
- ✅ **Extensible** - Easy to add new validation logic

## Quick Start

### Basic Validation

```csharp
using CoseSign1.Validation;

var validator = new ValidatorBuilder()
    .WithSignatureValidator()
    .WithExpirationValidator()
    .Build();

var result = validator.Validate(message);

if (!result.Success)
{
    foreach (var failure in result.Failures)
    {
        Console.WriteLine($"{failure.Code}: {failure.Message}");
    }
}
```

### Certificate Chain Validation

```csharp
var policy = new X509ChainPolicy
{
    RevocationMode = X509RevocationMode.Online,
    RevocationFlag = X509RevocationFlag.EntireChain,
    VerificationFlags = X509VerificationFlags.NoFlag
};

var validator = new ValidatorBuilder()
    .WithSignatureValidator()
    .WithExpirationValidator()
    .WithChainValidator(policy, trustedRootCertificates)
    .Build();

var result = validator.Validate(message);
```

### Complete Validation Pipeline

```csharp
var validator = new ValidatorBuilder()
    .WithSignatureValidator()
    .WithExpirationValidator()
    .WithChainValidator(chainPolicy, trustedRoots)
    .WithEkuPolicy("1.3.6.1.5.5.7.3.3")  // Code signing
    .WithSanPolicy(
        allowedDnsNames: new[] { "*.contoso.com" },
        allowedEmailAddresses: new[] { "*@contoso.com" }
    )
    .Build();
```

## Custom Validation

### Function-Based Validator

```csharp
var validator = new ValidatorBuilder()
    .WithSignatureValidator()
    .WithCustomValidator(message =>
    {
        var issuer = message.ProtectedHeaders.GetValueOrDefault<string>(
            new CoseHeaderLabel("iss"));
        
        if (issuer != "expected-issuer")
        {
            return ValidationResult.Failed(
                new ValidationFailure
                {
                    Code = ValidationFailureCode.CustomValidationFailed,
                    Message = "Invalid issuer"
                });
        }
        
        return ValidationResult.Success(message);
    })
    .Build();
```

### Class-Based Custom Validator

```csharp
public class IssuerValidator : IValidator<CoseSign1Message>
{
    private readonly string[] _allowedIssuers;
    
    public IssuerValidator(params string[] allowedIssuers)
    {
        _allowedIssuers = allowedIssuers;
    }
    
    public ValidationResult Validate(
        CoseSign1Message message,
        ValidationOptions? options = null)
    {
        var issuer = message.ProtectedHeaders.GetValueOrDefault<string>(
            new CoseHeaderLabel("iss"));
        
        if (!_allowedIssuers.Contains(issuer))
        {
            return ValidationResult.Failed(
                new ValidationFailure
                {
                    Code = ValidationFailureCode.CustomValidationFailed,
                    Message = $"Issuer '{issuer}' is not allowed"
                });
        }
        
        return ValidationResult.Success(message);
    }
}

// Usage
var validator = new ValidatorBuilder()
    .AddValidator(new IssuerValidator("https://contoso.com", "https://fabrikam.com"))
    .Build();
```

## Built-in Validators

### Signature Validator
Verifies cryptographic signature using the certificate.

```csharp
.WithSignatureValidator()
```

### Expiration Validator
Checks certificate expiration dates.

```csharp
.WithExpirationValidator()
.WithExpirationValidator(DateTimeOffset.Parse("2024-01-01")) // Historical validation
```

### Chain Validator
Validates the full certificate chain.

```csharp
.WithChainValidator(chainPolicy, trustedRootCertificates)
```

### EKU Policy Validator
Validates Extended Key Usage extensions.

```csharp
.WithEkuPolicy("1.3.6.1.5.5.7.3.3")  // Code signing
.WithEkuPolicy("1.3.6.1.5.5.7.3.3", "1.3.6.1.4.1.311.10.3.13")  // Multiple
```

### SAN Policy Validator
Validates Subject Alternative Name extensions.

```csharp
.WithSanPolicy(
    allowedDnsNames: new[] { "*.contoso.com" },
    allowedEmailAddresses: new[] { "*@contoso.com" }
)
```

## Validation Results

```csharp
public record ValidationResult
{
    public bool Success { get; }
    public IReadOnlyList<ValidationFailure> Failures { get; }
    public CoseSign1Message Message { get; }
    public IDictionary<string, object> Metadata { get; }
}

public record ValidationFailure
{
    public ValidationFailureCode Code { get; }
    public string Message { get; }
    public string? ValidatorName { get; }
    public IDictionary<string, object> Context { get; }
}
```

## Composite Validators

Manually compose validators:

```csharp
var validator = new CompositeValidator(
    new CertificateSignatureValidator(),
    new CertificateExpirationValidator(),
    new EkuPolicyValidator("1.3.6.1.5.5.7.3.3"),
    new IssuerValidator("https://contoso.com")
);

var result = validator.Validate(message);
```

## Validation Options

```csharp
var options = new ValidationOptions
{
    StopOnFirstFailure = false,  // Collect all failures
    ValidationTime = DateTimeOffset.Parse("2024-01-01"),  // Historical validation
    Context = 
    {
        ["Environment"] = "Production",
        ["RequireTimestamp"] = true
    }
};

var result = validator.Validate(message, options);
```

## ASP.NET Core Integration

```csharp
// Startup.cs
services.AddSingleton<IValidator<CoseSign1Message>>(sp =>
{
    var config = sp.GetRequiredService<IConfiguration>();
    var trustedRoots = LoadTrustedRoots(config);
    
    return new ValidatorBuilder()
        .WithSignatureValidator()
        .WithExpirationValidator()
        .WithChainValidator(trustedRoots: trustedRoots)
        .WithEkuPolicy(config.GetSection("RequiredEkus").Get<string[]>())
        .Build();
});

// Controller
public class ValidationController : ControllerBase
{
    private readonly IValidator<CoseSign1Message> _validator;
    
    [HttpPost("validate")]
    public IActionResult Validate([FromBody] byte[] encodedMessage)
    {
        var message = CoseSign1Message.Decode(encodedMessage);
        var result = _validator.Validate(message);
        
        return result.Success 
            ? Ok(new { Valid = true })
            : BadRequest(new { Valid = false, Errors = result.Failures });
    }
}
```

## When to Use

- ✅ Validating COSE Sign1 message signatures
- ✅ Building custom validation pipelines
- ✅ Implementing business-specific validation rules
- ✅ SCITT compliance validation
- ✅ Policy-based validation
- ✅ Multi-stage validation workflows

## Related Packages

- **CoseSign1.Abstractions** - Core interfaces
- **CoseSign1.Certificates** - Certificate validators
- **CoseSign1.Headers** - CWT claims validation
- **CoseSign1** - Message creation

## Documentation

- 📖 [Full Package Documentation](https://github.com/microsoft/CoseSignTool/blob/main/V2/docs/packages/validation.md)
- 📖 [Custom Validators Guide](https://github.com/microsoft/CoseSignTool/blob/main/V2/docs/guides/custom-validators.md)
- 📖 [Validation Architecture](https://github.com/microsoft/CoseSignTool/blob/main/V2/docs/architecture/validation-framework.md)

## Support

- 🐛 [Report Issues](https://github.com/microsoft/CoseSignTool/issues)
- 💬 [Discussions](https://github.com/microsoft/CoseSignTool/discussions)
- 📧 Email: cosesigntool@microsoft.com

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
