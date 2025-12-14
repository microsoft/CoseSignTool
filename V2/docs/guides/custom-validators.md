# Custom Validators Guide

This guide explains how to create custom validators for the CoseSignTool V2 validation framework.

## Overview

The V2 validation framework is designed to be extensible. You can create custom validators to implement organization-specific validation rules or integrate with external validation services.

## IValidator Interface

All validators implement the `IValidator` interface:

```csharp
public interface IValidator
{
    /// <summary>
    /// Validates a COSE signature.
    /// </summary>
    Task<ValidationResult> ValidateAsync(
        CoseSign1Message message,
        ValidationContext context,
        CancellationToken cancellationToken = default);
    
    /// <summary>
    /// Order in which this validator runs (lower runs first).
    /// </summary>
    int Order { get; }
}
```

## Creating a Custom Validator

### Basic Structure

```csharp
using CoseSign1.Abstractions;

public class MyCustomValidator : IValidator
{
    public int Order => 100; // Run after built-in validators

    public async Task<ValidationResult> ValidateAsync(
        CoseSign1Message message,
        ValidationContext context,
        CancellationToken cancellationToken = default)
    {
        // Your validation logic here
        
        if (/* validation passes */)
        {
            return ValidationResult.Success();
        }
        
        return ValidationResult.Failure("Validation failed: reason");
    }
}
```

### Example: Content Type Validator

```csharp
public class ContentTypeValidator : IValidator
{
    private readonly HashSet<string> _allowedContentTypes;
    
    public ContentTypeValidator(IEnumerable<string> allowedContentTypes)
    {
        _allowedContentTypes = new HashSet<string>(allowedContentTypes, StringComparer.OrdinalIgnoreCase);
    }
    
    public int Order => 50;

    public async Task<ValidationResult> ValidateAsync(
        CoseSign1Message message,
        ValidationContext context,
        CancellationToken cancellationToken = default)
    {
        var contentType = message.ProtectedHeaders.GetValueOrDefault(CoseHeaderLabel.ContentType)?.ToString();
        
        if (string.IsNullOrEmpty(contentType))
        {
            return ValidationResult.Failure("Missing content type header");
        }
        
        if (!_allowedContentTypes.Contains(contentType))
        {
            return ValidationResult.Failure($"Content type '{contentType}' is not allowed");
        }
        
        return ValidationResult.Success();
    }
}
```

### Example: Timestamp Range Validator

```csharp
public class TimestampRangeValidator : IValidator
{
    private readonly TimeSpan _maxAge;
    private readonly TimeSpan _maxFutureSkew;
    
    public TimestampRangeValidator(TimeSpan maxAge, TimeSpan maxFutureSkew)
    {
        _maxAge = maxAge;
        _maxFutureSkew = maxFutureSkew;
    }
    
    public int Order => 60;

    public async Task<ValidationResult> ValidateAsync(
        CoseSign1Message message,
        ValidationContext context,
        CancellationToken cancellationToken = default)
    {
        // Extract timestamp from CWT claims or custom header
        var timestamp = ExtractTimestamp(message);
        
        if (!timestamp.HasValue)
        {
            return ValidationResult.Success(); // No timestamp to validate
        }
        
        var now = DateTimeOffset.UtcNow;
        
        if (timestamp.Value > now + _maxFutureSkew)
        {
            return ValidationResult.Failure("Signature timestamp is too far in the future");
        }
        
        if (timestamp.Value < now - _maxAge)
        {
            return ValidationResult.Failure($"Signature is too old (max age: {_maxAge})");
        }
        
        return ValidationResult.Success();
    }
    
    private DateTimeOffset? ExtractTimestamp(CoseSign1Message message)
    {
        // Implementation to extract timestamp
    }
}
```

## Registering Custom Validators

### Using ValidationBuilder

```csharp
var validator = ValidationBuilder.Create()
    .AddValidator(new MyCustomValidator())
    .AddValidator(new ContentTypeValidator(new[] { "application/json", "application/xml" }))
    .Build();
```

### With Dependency Injection

```csharp
services.AddSingleton<IValidator, MyCustomValidator>();
services.AddSingleton<IValidator>(sp => 
    new ContentTypeValidator(new[] { "application/json" }));

// Build composite validator from all registered validators
services.AddSingleton<CompositeValidator>();
```

## Validator Ordering

Validators run in order of their `Order` property (lower values run first):

| Order Range | Typical Usage |
|-------------|---------------|
| 0-20 | Structural validation (format, required headers) |
| 20-40 | Cryptographic validation (signature verification) |
| 40-60 | Certificate validation (chain, revocation) |
| 60-80 | Business rules (content type, timestamp) |
| 80-100 | External validation (transparency, custom) |
| 100+ | Application-specific validators |

## Async Validation

For validators that call external services:

```csharp
public class ExternalServiceValidator : IValidator
{
    private readonly HttpClient _httpClient;
    
    public int Order => 90;

    public async Task<ValidationResult> ValidateAsync(
        CoseSign1Message message,
        ValidationContext context,
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
                return ValidationResult.Success();
            }
            
            var error = await response.Content.ReadAsStringAsync(cancellationToken);
            return ValidationResult.Failure($"External validation failed: {error}");
        }
        catch (Exception ex)
        {
            return ValidationResult.Failure($"External validation error: {ex.Message}");
        }
    }
}
```

## Validation Context

The `ValidationContext` provides additional information to validators:

```csharp
public class ValidationContext
{
    /// <summary>
    /// The original payload (for detached signatures).
    /// </summary>
    public byte[]? DetachedPayload { get; set; }
    
    /// <summary>
    /// Additional validation options.
    /// </summary>
    public IDictionary<string, object> Options { get; }
    
    /// <summary>
    /// Results from previous validators.
    /// </summary>
    public IReadOnlyList<ValidationResult> PreviousResults { get; }
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
        var context = new ValidationContext();
        
        // Act
        var result = await validator.ValidateAsync(message, context);
        
        // Assert
        Assert.IsTrue(result.IsSuccess);
    }
    
    [TestMethod]
    public async Task ValidateAsync_WithInvalidMessage_ReturnsFailure()
    {
        // Arrange
        var validator = new MyCustomValidator();
        var message = CreateTestMessage(/* invalid data */);
        var context = new ValidationContext();
        
        // Act
        var result = await validator.ValidateAsync(message, context);
        
        // Assert
        Assert.IsFalse(result.IsSuccess);
        Assert.IsNotNull(result.ErrorMessage);
    }
}
```

## See Also

- [Validation Framework Architecture](../architecture/validation-framework.md)
- [Built-in Validators](../api/README.md)
- [Testing Guide](testing.md)
