# CoseSign1.Validation Package

**NuGet**: `CoseSign1.Validation`  
**Purpose**: Comprehensive validation framework for COSE Sign1 messages  
**Dependencies**: CoseSign1.Abstractions

## Overview

This package provides a flexible, composable validation framework for COSE Sign1 messages. It includes built-in validators and a builder pattern for creating custom validation pipelines.

## When to Use

- Validating COSE Sign1 message signatures
- Building custom validation pipelines
- Implementing business-specific validation rules
- SCITT compliance validation
- Policy-based validation
- Multi-stage validation workflows

## Core Interfaces

### IValidator<T>

The base interface for all validators.

```csharp
public interface IValidator<T>
{
    /// <summary>
    /// Validates the specified item.
    /// </summary>
    ValidationResult Validate(T item, ValidationOptions? options = null);
}
```

### ValidationResult

Represents the result of a validation operation.

```csharp
public record ValidationResult
{
    /// <summary>
    /// Indicates whether validation succeeded.
    /// </summary>
    public required bool Success { get; init; }
    
    /// <summary>
    /// Collection of validation failures.
    /// </summary>
    public required IReadOnlyList<ValidationFailure> Failures { get; init; }
    
    /// <summary>
    /// The validated message.
    /// </summary>
    public required CoseSign1Message Message { get; init; }
    
    /// <summary>
    /// Additional metadata from validation.
    /// </summary>
    public IDictionary<string, object> Metadata { get; init; } 
        = new Dictionary<string, object>();
}
```

### ValidationFailure

Represents a single validation failure.

```csharp
public record ValidationFailure
{
    /// <summary>
    /// The failure code.
    /// </summary>
    public required ValidationFailureCode Code { get; init; }
    
    /// <summary>
    /// Human-readable failure message.
    /// </summary>
    public required string Message { get; init; }
    
    /// <summary>
    /// The validator that produced this failure.
    /// </summary>
    public string? ValidatorName { get; init; }
    
    /// <summary>
    /// Additional context about the failure.
    /// </summary>
    public IDictionary<string, object> Context { get; init; }
        = new Dictionary<string, object>();
}
```

### ValidationFailureCode

Enumeration of standard failure codes.

```csharp
public enum ValidationFailureCode
{
    SignatureVerificationFailed,
    CertificateExpired,
    CertificateNotYetValid,
    ChainValidationFailed,
    EkuPolicyViolation,
    SanPolicyViolation,
    CustomValidationFailed,
    PayloadMismatch,
    InvalidHeader,
    MissingRequiredHeader
}
```

## Core Validators

### CompositeValidator

Combines multiple validators into a single validation pipeline.

```csharp
public class CompositeValidator : IValidator<CoseSign1Message>
{
    public CompositeValidator(params IValidator<CoseSign1Message>[] validators);
    public CompositeValidator(IEnumerable<IValidator<CoseSign1Message>> validators);
}
```

**Usage**:
```csharp
var validator = new CompositeValidator(
    new CertificateSignatureValidator(),
    new CertificateExpirationValidator(),
    new EkuPolicyValidator("1.3.6.1.5.5.7.3.3")
);

var result = validator.Validate(message);

if (!result.Success)
{
    foreach (var failure in result.Failures)
    {
        Console.WriteLine($"{failure.Code}: {failure.Message}");
    }
}
```

**Short-Circuit Behavior**:
```csharp
// Fails fast on first error by default
var validator = new CompositeValidator(validators);

// Collect all failures
var options = new ValidationOptions { StopOnFirstFailure = false };
var result = validator.Validate(message, options);
```

### FunctionValidator

Creates validators from lambda functions.

```csharp
public class FunctionValidator : IValidator<CoseSign1Message>
{
    public FunctionValidator(
        Func<CoseSign1Message, ValidationResult> validationFunc);
}
```

**Usage**:
```csharp
// Simple validation
var headerValidator = new FunctionValidator(message =>
{
    if (!message.ProtectedHeaders.ContainsKey(CoseHeaderLabel.ContentType))
    {
        return ValidationResult.Failed(
            new ValidationFailure
            {
                Code = ValidationFailureCode.MissingRequiredHeader,
                Message = "Content-Type header is required"
            });
    }
    
    return ValidationResult.Success(message);
});

// Complex validation
var businessValidator = new FunctionValidator(message =>
{
    var failures = new List<ValidationFailure>();
    
    // Check issuer
    var issuer = message.ProtectedHeaders.GetValueOrDefault<string>(
        new CoseHeaderLabel("iss"));
    
    if (issuer == null || !_allowedIssuers.Contains(issuer))
    {
        failures.Add(new ValidationFailure
        {
            Code = ValidationFailureCode.CustomValidationFailed,
            Message = $"Issuer '{issuer}' is not allowed"
        });
    }
    
    // Check subject
    var subject = message.ProtectedHeaders.GetValueOrDefault<string>(
        new CoseHeaderLabel("sub"));
    
    if (string.IsNullOrEmpty(subject))
    {
        failures.Add(new ValidationFailure
        {
            Code = ValidationFailureCode.MissingRequiredHeader,
            Message = "Subject is required"
        });
    }
    
    return failures.Count == 0 
        ? ValidationResult.Success(message)
        : ValidationResult.Failed(failures, message);
});
```

## Validation Builder

### CoseMessageValidationBuilder

Fluent API for building validation pipelines.

```csharp
public interface ICoseMessageValidationBuilder
{
    ICoseMessageValidationBuilder AddValidator(IValidator<CoseSign1Message> validator);
    ICoseMessageValidationBuilder WithSignatureValidator();
    ICoseMessageValidationBuilder WithExpirationValidator(DateTimeOffset? validationTime = null);
    ICoseMessageValidationBuilder WithChainValidator(X509ChainPolicy? policy = null, IEnumerable<X509Certificate2>? trustedRoots = null);
    ICoseMessageValidationBuilder WithEkuPolicy(params string[] requiredEkus);
    ICoseMessageValidationBuilder WithSanPolicy(IEnumerable<string>? allowedDns = null, IEnumerable<string>? allowedEmails = null);
    ICoseMessageValidationBuilder WithCustomValidator(Func<CoseSign1Message, ValidationResult> validator);
    IValidator<CoseSign1Message> Build();
}
```

**Basic Usage**:
```csharp
var validator = new ValidatorBuilder()
    .WithSignatureValidator()
    .WithExpirationValidator()
    .Build();

var result = validator.Validate(message);
```

**Advanced Configuration**:
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
    .WithEkuPolicy("1.3.6.1.5.5.7.3.3", "1.3.6.1.4.1.311.10.3.13")
    .WithSanPolicy(
        allowedDns: new[] { "*.contoso.com" },
        allowedEmails: new[] { "*@contoso.com" })
    .WithCustomValidator(message =>
    {
        // Custom business logic
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

var result = validator.Validate(message);
```

## Advanced Scenarios

### Conditional Validation

```csharp
public class ConditionalValidator : IValidator<CoseSign1Message>
{
    private readonly IValidator<CoseSign1Message> _strictValidator;
    private readonly IValidator<CoseSign1Message> _lenientValidator;
    private readonly Func<CoseSign1Message, bool> _condition;
    
    public ConditionalValidator(
        Func<CoseSign1Message, bool> condition,
        IValidator<CoseSign1Message> strictValidator,
        IValidator<CoseSign1Message> lenientValidator)
    {
        _condition = condition;
        _strictValidator = strictValidator;
        _lenientValidator = lenientValidator;
    }
    
    public ValidationResult Validate(
        CoseSign1Message message, 
        ValidationOptions? options = null)
    {
        var validator = _condition(message) 
            ? _strictValidator 
            : _lenientValidator;
        
        return validator.Validate(message, options);
    }
}

// Usage
var conditionalValidator = new ConditionalValidator(
    message => message.ProtectedHeaders.ContainsKey(new CoseHeaderLabel("critical")),
    strictValidator: new ValidatorBuilder()
        .WithSignatureValidator()
        .WithExpirationValidator()
        .WithChainValidator()
        .Build(),
    lenientValidator: new ValidatorBuilder()
        .WithSignatureValidator()
        .Build()
);
```

### Async Validation

```csharp
public interface IAsyncValidator<T>
{
    Task<ValidationResult> ValidateAsync(
        T item, 
        ValidationOptions? options = null,
        CancellationToken cancellationToken = default);
}

public class AsyncRevocationValidator : IAsyncValidator<CoseSign1Message>
{
    private readonly HttpClient _httpClient;
    
    public async Task<ValidationResult> ValidateAsync(
        CoseSign1Message message,
        ValidationOptions? options = null,
        CancellationToken ct = default)
    {
        var cert = message.GetSigningCertificate();
        if (cert == null)
        {
            return ValidationResult.Failed(
                new ValidationFailure
                {
                    Code = ValidationFailureCode.CustomValidationFailed,
                    Message = "No certificate found"
                });
        }
        
        // Check OCSP
        var isRevoked = await CheckOcspAsync(cert, ct);
        
        if (isRevoked)
        {
            return ValidationResult.Failed(
                new ValidationFailure
                {
                    Code = ValidationFailureCode.ChainValidationFailed,
                    Message = "Certificate has been revoked"
                });
        }
        
        return ValidationResult.Success(message);
    }
    
    private async Task<bool> CheckOcspAsync(
        X509Certificate2 cert, 
        CancellationToken ct)
    {
        // OCSP checking implementation
        await Task.CompletedTask;
        return false;
    }
}
```

### Validation with Context

```csharp
public class ValidationOptions
{
    public bool StopOnFirstFailure { get; set; } = true;
    public DateTimeOffset? ValidationTime { get; set; }
    public IDictionary<string, object> Context { get; } 
        = new Dictionary<string, object>();
}

public class ContextAwareValidator : IValidator<CoseSign1Message>
{
    public ValidationResult Validate(
        CoseSign1Message message, 
        ValidationOptions? options = null)
    {
        var context = options?.Context ?? new Dictionary<string, object>();
        
        // Use context for validation decisions
        if (context.TryGetValue("Environment", out var env) 
            && env is string environment)
        {
            if (environment == "Production")
            {
                // Strict validation for production
                return StrictValidate(message);
            }
            else
            {
                // Lenient validation for dev/test
                return LenientValidate(message);
            }
        }
        
        return DefaultValidate(message);
    }
}

// Usage
var options = new ValidationOptions
{
    Context = 
    {
        ["Environment"] = "Production",
        ["RequireTimestamp"] = true
    }
};

var result = validator.Validate(message, options);
```

### Multi-Stage Validation

```csharp
public class MultiStageValidator : IValidator<CoseSign1Message>
{
    private readonly IValidator<CoseSign1Message>[] _stages;
    
    public MultiStageValidator(params IValidator<CoseSign1Message>[] stages)
    {
        _stages = stages;
    }
    
    public ValidationResult Validate(
        CoseSign1Message message, 
        ValidationOptions? options = null)
    {
        var allFailures = new List<ValidationFailure>();
        var metadata = new Dictionary<string, object>();
        
        for (int i = 0; i < _stages.Length; i++)
        {
            var stageResult = _stages[i].Validate(message, options);
            
            metadata[$"Stage{i + 1}Result"] = stageResult.Success;
            
            if (!stageResult.Success)
            {
                allFailures.AddRange(stageResult.Failures);
                
                if (options?.StopOnFirstFailure ?? true)
                {
                    return new ValidationResult
                    {
                        Success = false,
                        Failures = allFailures,
                        Message = message,
                        Metadata = metadata
                    };
                }
            }
        }
        
        return new ValidationResult
        {
            Success = allFailures.Count == 0,
            Failures = allFailures,
            Message = message,
            Metadata = metadata
        };
    }
}

// Usage
var validator = new MultiStageValidator(
    // Stage 1: Structure validation
    new ValidatorBuilder()
        .WithCustomValidator(msg => ValidateStructure(msg))
        .Build(),
    
    // Stage 2: Signature validation
    new ValidatorBuilder()
        .WithSignatureValidator()
        .Build(),
    
    // Stage 3: Certificate validation
    new ValidatorBuilder()
        .WithExpirationValidator()
        .WithChainValidator()
        .Build(),
    
    // Stage 4: Business validation
    new ValidatorBuilder()
        .WithCustomValidator(msg => ValidateBusinessRules(msg))
        .Build()
);
```

### Caching Validation Results

```csharp
public class CachingValidator : IValidator<CoseSign1Message>
{
    private readonly IValidator<CoseSign1Message> _innerValidator;
    private readonly IMemoryCache _cache;
    private readonly TimeSpan _cacheDuration;
    
    public CachingValidator(
        IValidator<CoseSign1Message> innerValidator,
        IMemoryCache cache,
        TimeSpan cacheDuration)
    {
        _innerValidator = innerValidator;
        _cache = cache;
        _cacheDuration = cacheDuration;
    }
    
    public ValidationResult Validate(
        CoseSign1Message message, 
        ValidationOptions? options = null)
    {
        // Use message hash as cache key
        var messageHash = SHA256.HashData(message.Encode());
        var cacheKey = $"validation_{Convert.ToBase64String(messageHash)}";
        
        if (_cache.TryGetValue<ValidationResult>(cacheKey, out var cachedResult))
        {
            return cachedResult!;
        }
        
        var result = _innerValidator.Validate(message, options);
        
        // Only cache successful validations
        if (result.Success)
        {
            _cache.Set(cacheKey, result, _cacheDuration);
        }
        
        return result;
    }
}
```

### Validation Reporting

```csharp
public class ValidationReport
{
    public bool IsValid { get; set; }
    public DateTimeOffset ValidationTime { get; set; }
    public TimeSpan ValidationDuration { get; set; }
    public List<ValidationStageResult> Stages { get; set; } = new();
    public Dictionary<string, object> Metadata { get; set; } = new();
}

public class ValidationStageResult
{
    public string StageName { get; set; }
    public bool Success { get; set; }
    public List<ValidationFailure> Failures { get; set; } = new();
    public TimeSpan Duration { get; set; }
}

public class ReportingValidator : IValidator<CoseSign1Message>
{
    private readonly IValidator<CoseSign1Message> _validator;
    
    public ValidationResult Validate(
        CoseSign1Message message, 
        ValidationOptions? options = null)
    {
        var startTime = DateTimeOffset.UtcNow;
        var stopwatch = Stopwatch.StartNew();
        
        var result = _validator.Validate(message, options);
        
        stopwatch.Stop();
        
        var report = new ValidationReport
        {
            IsValid = result.Success,
            ValidationTime = startTime,
            ValidationDuration = stopwatch.Elapsed,
            Metadata = result.Metadata.ToDictionary(kvp => kvp.Key, kvp => kvp.Value)
        };
        
        // Add report to result metadata
        result.Metadata["ValidationReport"] = report;
        
        return result;
    }
}
```

## Integration Patterns

### ASP.NET Core

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
        .WithEkuPolicy(config.GetSection("Validation:RequiredEkus").Get<string[]>())
        .Build();
});

// Controller
public class ValidationController : ControllerBase
{
    private readonly IValidator<CoseSign1Message> _validator;
    
    public ValidationController(IValidator<CoseSign1Message> validator)
    {
        _validator = validator;
    }
    
    [HttpPost("validate")]
    public IActionResult Validate([FromBody] byte[] encodedMessage)
    {
        try
        {
            var message = CoseSign1Message.Decode(encodedMessage);
            var result = _validator.Validate(message);
            
            if (result.Success)
            {
                return Ok(new { Valid = true });
            }
            
            return BadRequest(new 
            { 
                Valid = false, 
                Errors = result.Failures.Select(f => new 
                {
                    f.Code,
                    f.Message
                })
            });
        }
        catch (Exception ex)
        {
            return BadRequest(new { Error = ex.Message });
        }
    }
}
```

### Background Validation Service

```csharp
public class ValidationBackgroundService : BackgroundService
{
    private readonly IValidator<CoseSign1Message> _validator;
    private readonly IMessageQueue _queue;
    private readonly ILogger _logger;
    
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        while (!stoppingToken.IsCancellationRequested)
        {
            var encodedMessage = await _queue.DequeueAsync(stoppingToken);
            
            try
            {
                var message = CoseSign1Message.Decode(encodedMessage);
                var result = _validator.Validate(message);
                
                if (result.Success)
                {
                    await ProcessValidMessageAsync(message, stoppingToken);
                }
                else
                {
                    _logger.LogWarning(
                        "Validation failed: {Failures}",
                        string.Join(", ", result.Failures.Select(f => f.Message)));
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Validation error");
            }
        }
    }
}
```

## Testing

### Unit Testing Validators

```csharp
[Test]
public void Validate_WithValidSignature_ReturnsSuccess()
{
    // Arrange
    using var cert = TestCertificateProvider.GetTestCertificate();
    using var service = new LocalCertificateSigningService(cert);
    var factory = new DirectSignatureFactory(service);
    var message = await factory.CreateAsync(new byte[] { 1, 2, 3 });
    
    var validator = new ValidatorBuilder()
        .WithSignatureValidator()
        .Build();
    
    // Act
    var result = validator.Validate(message);
    
    // Assert
    Assert.IsTrue(result.Success);
    Assert.IsEmpty(result.Failures);
}

[Test]
public void Validate_WithExpiredCertificate_ReturnsFailed()
{
    // Arrange
    var expiredCert = TestCertificateProvider.GetExpiredCertificate();
    var message = CreateMessageWithCertificate(expiredCert);
    
    var validator = new ValidatorBuilder()
        .WithExpirationValidator()
        .Build();
    
    // Act
    var result = validator.Validate(message);
    
    // Assert
    Assert.IsFalse(result.Success);
    Assert.IsTrue(result.Failures.Any(f => 
        f.Code == ValidationFailureCode.CertificateExpired));
}
```

### Testing Custom Validators

```csharp
[Test]
public void CustomValidator_WithInvalidIssuer_Fails()
{
    // Arrange
    var message = CreateTestMessage();
    var validator = new FunctionValidator(msg =>
    {
        var issuer = msg.ProtectedHeaders.GetValueOrDefault<string>(
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
        
        return ValidationResult.Success(msg);
    });
    
    // Act
    var result = validator.Validate(message);
    
    // Assert
    Assert.IsFalse(result.Success);
}
```

## Best Practices

1. **Build Validators Once**: Create validators at startup, not per request
2. **Use Builder Pattern**: Prefer `ValidatorBuilder` for readability
3. **Compose Validators**: Build complex validation from simple validators
4. **Handle All Failure Modes**: Check all validation requirements
5. **Provide Clear Messages**: Make failure messages actionable
6. **Consider Performance**: Cache validation results when appropriate
7. **Test Extensively**: Test both success and failure paths

## See Also

- [Abstractions Package](abstractions.md)
- [Certificates Package](certificates.md)
- [Custom Validators Guide](../guides/custom-validators.md)
- [Validation Architecture](../architecture/validation-framework.md)
