# Custom Validators Guide

This guide explains how to create custom validators for the CoseSignTool V2 validation framework.

## Overview

The V2 validation framework is designed to be extensible. You can create custom validators to implement organization-specific validation rules or integrate with external validation services.

## IValidator Interface

All validators implement `IValidator<CoseSign1Message>`:

```csharp
public interface IValidator<T>
{
    ValidationResult Validate(T input);

    Task<ValidationResult> ValidateAsync(
        T input,
        CancellationToken cancellationToken = default);
}
```

## Creating a Custom Validator

### Basic Structure

```csharp
using CoseSign1.Validation;

public class MyCustomValidator : IValidator<CoseSign1Message>
{
    private const string Name = nameof(MyCustomValidator);

    public ValidationResult Validate(CoseSign1Message message)
    {
        // Your validation logic here

        if (/* validation passes */)
        {
            return ValidationResult.Success(Name);
        }

        return ValidationResult.Failure(Name, "Validation failed: reason", errorCode: "CUSTOM_VALIDATION_FAILED");
    }

    public Task<ValidationResult> ValidateAsync(
        CoseSign1Message message,
        CancellationToken cancellationToken = default)
    {
        return Task.FromResult(Validate(message));
    }
}
```

### Example: Content Type Validator

```csharp
using CoseSign1.Extensions;
using CoseSign1.Validation;

public class ContentTypeValidator : IValidator<CoseSign1Message>
{
    private readonly HashSet<string> _allowedContentTypes;
    private const string Name = nameof(ContentTypeValidator);
    
    public ContentTypeValidator(IEnumerable<string> allowedContentTypes)
    {
        _allowedContentTypes = new HashSet<string>(allowedContentTypes, StringComparer.OrdinalIgnoreCase);
    }
    
    public ValidationResult Validate(CoseSign1Message message)
    {
        if (!message.TryGetContentType(out string? contentType) || string.IsNullOrWhiteSpace(contentType))
        {
            return ValidationResult.Failure(Name, "Missing content type header", errorCode: "MISSING_CONTENT_TYPE");
        }

        if (!_allowedContentTypes.Contains(contentType))
        {
            return ValidationResult.Failure(Name, $"Content type '{contentType}' is not allowed", errorCode: "CONTENT_TYPE_NOT_ALLOWED");
        }

        return ValidationResult.Success(Name);
    }

    public Task<ValidationResult> ValidateAsync(CoseSign1Message message, CancellationToken cancellationToken = default)
        => Task.FromResult(Validate(message));
}
```

### Example: Timestamp Range Validator

```csharp
using CoseSign1.Validation;

public class TimestampRangeValidator : IValidator<CoseSign1Message>
{
    private readonly TimeSpan _maxAge;
    private readonly TimeSpan _maxFutureSkew;
    private const string Name = nameof(TimestampRangeValidator);
    
    public TimestampRangeValidator(TimeSpan maxAge, TimeSpan maxFutureSkew)
    {
        _maxAge = maxAge;
        _maxFutureSkew = maxFutureSkew;
    }
    
    public ValidationResult Validate(CoseSign1Message message)
    {
        // Extract timestamp from CWT claims or custom header
        var timestamp = ExtractTimestamp(message);
        
        if (!timestamp.HasValue)
        {
            return ValidationResult.Success(Name); // No timestamp to validate
        }
        
        var now = DateTimeOffset.UtcNow;
        
        if (timestamp.Value > now + _maxFutureSkew)
        {
            return ValidationResult.Failure(Name, "Signature timestamp is too far in the future", errorCode: "TIMESTAMP_TOO_FAR_IN_FUTURE");
        }
        
        if (timestamp.Value < now - _maxAge)
        {
            return ValidationResult.Failure(Name, $"Signature is too old (max age: {_maxAge})", errorCode: "TIMESTAMP_TOO_OLD");
        }

        return ValidationResult.Success(Name);
    }
    
    private DateTimeOffset? ExtractTimestamp(CoseSign1Message message)
    {
        // Implementation to extract timestamp
    }

    public Task<ValidationResult> ValidateAsync(CoseSign1Message message, CancellationToken cancellationToken = default)
        => Task.FromResult(Validate(message));
}
```

## Registering Custom Validators

### Using ValidationBuilder

```csharp
var validator = Cose.Sign1Message()
    .AddValidator(new MyCustomValidator())
    .AddValidator(new ContentTypeValidator(new[] { "application/json", "application/xml" }))
    .Build();
```

### With Dependency Injection

```csharp
services.AddSingleton<IValidator<CoseSign1Message>, MyCustomValidator>();
services.AddSingleton<IValidator<CoseSign1Message>>(sp =>
    new ContentTypeValidator(new[] { "application/json" }));

// Build composite validator from all registered validators
services.AddSingleton<IValidator<CoseSign1Message>>(sp =>
    new CompositeValidator(sp.GetServices<IValidator<CoseSign1Message>>()));
```

## Validator Ordering

Validators run in the order you compose them.

If you need strict ordering with dependency injection, register validators as distinct services and build a `CompositeValidator` with a deterministic ordering (for example, by ordering the sequence before passing it to the constructor).

## Async Validation

For validators that call external services:

```csharp
public class ExternalServiceValidator : IValidator<CoseSign1Message>
{
    private readonly HttpClient _httpClient;

    private const string Name = nameof(ExternalServiceValidator);

    public ValidationResult Validate(CoseSign1Message message)
        => throw new NotSupportedException("Use ValidateAsync for this validator.");

    public async Task<ValidationResult> ValidateAsync(
        CoseSign1Message message,
        CancellationToken cancellationToken = default)
    {
        try
        {
            var response = await _httpClient.PostAsync(
                "https://validation-service.example.com/validate",
                new ByteArrayContent(message.GetEncodedBytes()),
                cancellationToken);
            
            if (response.IsSuccessStatusCode)
            {
                return ValidationResult.Success(Name);
            }
            
            var error = await response.Content.ReadAsStringAsync(cancellationToken);
            return ValidationResult.Failure(Name, $"External validation failed: {error}");
        }
        catch (Exception ex)
        {
            return ValidationResult.Failure(Name, $"External validation error: {ex.Message}");
        }
    }
}
```

## Testing Custom Validators

```csharp
[TestClass]
public class MyCustomValidatorTests
{
    [TestMethod]
    public async Task ValidateAsync_WithValidMessage_ReturnsSuccess()
    {
        // Arrange
        var validator = new MyCustomValidator();
        var message = CreateTestMessage(/* valid data */);
        
        // Act
        var result = await validator.ValidateAsync(message);
        
        // Assert
        Assert.IsTrue(result.IsValid);
    }
    
    [TestMethod]
    public async Task ValidateAsync_WithInvalidMessage_ReturnsFailure()
    {
        // Arrange
        var validator = new MyCustomValidator();
        var message = CreateTestMessage(/* invalid data */);
        
        // Act
        var result = await validator.ValidateAsync(message);
        
        // Assert
        Assert.IsFalse(result.IsValid);
        Assert.IsNotEmpty(result.Failures);
    }
}
```

## See Also

- [Validation Framework Architecture](../architecture/validation-framework.md)
- [Built-in Validators](../api/README.md)
- [Testing Guide](testing.md)
