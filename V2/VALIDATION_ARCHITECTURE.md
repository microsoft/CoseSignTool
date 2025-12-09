# V2 COSE Validation Architecture Design

## Overview
This document outlines the elegant, composable validation architecture for V2 that allows callers to validate `CoseSign1Message` objects from the .NET BCL `System.Security.Cryptography.Cose` package across various validation concerns.

## Design Principles

1. **Fluent Interface**: Chain validations naturally with a readable, self-documenting API
2. **Composition over Inheritance**: Build complex validators from simple, focused components
3. **Single Responsibility**: Each validator handles one specific concern
4. **Immutability**: Validators are immutable and thread-safe
5. **Extensibility**: Easy to add custom validators without modifying the core
6. **Result Aggregation**: Collect all validation results, not just first failure
7. **Async Support**: First-class support for async validation (e.g., CRL/OCSP checks)

## Core Abstractions

### 1. IValidator<T>
```csharp
public interface IValidator<in T>
{
    /// <summary>
    /// Validates the input and returns a validation result.
    /// </summary>
    ValidationResult Validate(T input);
    
    /// <summary>
    /// Asynchronously validates the input and returns a validation result.
    /// </summary>
    Task<ValidationResult> ValidateAsync(T input, CancellationToken cancellationToken = default);
}
```

### 2. ValidationResult
```csharp
public sealed class ValidationResult
{
    public bool IsValid { get; init; }
    public string ValidatorName { get; init; }
    public IReadOnlyList<ValidationFailure> Failures { get; init; }
    public IReadOnlyDictionary<string, object> Metadata { get; init; }
    
    // Factory methods
    public static ValidationResult Success(string validatorName, IDictionary<string, object>? metadata = null);
    public static ValidationResult Failure(string validatorName, params ValidationFailure[] failures);
    public static ValidationResult Failure(string validatorName, string message, string? errorCode = null);
}
```

### 3. ValidationFailure
```csharp
public sealed class ValidationFailure
{
    public string Message { get; init; }
    public string? ErrorCode { get; init; }
    public string? PropertyName { get; init; }
    public object? AttemptedValue { get; init; }
    public Exception? Exception { get; init; }
}
```

### 4. CompositeValidator
```csharp
public sealed class CompositeValidator<T> : IValidator<T>
{
    private readonly IReadOnlyList<IValidator<T>> _validators;
    
    // Combines multiple validators
    // Can run in sequence or parallel
    // Aggregates all results
}
```

## Validation Domains

### 1. Signature Validation
**Purpose**: Verify cryptographic signature is valid

```csharp
// Basic signature validation
var validator = CoseValidatorBuilder
    .ForMessage()
    .ValidateSignature()  // Uses embedded cert or provided key
    .Build();

// With specific key
var validator = CoseValidatorBuilder
    .ForMessage()
    .ValidateSignatureWith(publicKey)
    .Build();

// Detached payload support
var validator = CoseValidatorBuilder
    .ForMessage()
    .ValidateSignature(detachedPayload)
    .Build();
```

**Validators**:
- `SignatureValidator` - Validates embedded signature
- `DetachedSignatureValidator` - Validates with detached payload
- `SignatureWithKeyValidator` - Validates with provided public key

### 2. Indirect Signature Validation
**Purpose**: Verify hash-based indirect signatures

```csharp
var validator = CoseValidatorBuilder
    .ForMessage()
    .ValidateIndirectSignature(originalPayload)  // Validates hash matches
    .Build();

// Or for CoseHashV format
var validator = CoseValidatorBuilder
    .ForMessage()
    .ValidateCoseHashV(originalPayload)
    .Build();

// Or for CoseHashEnvelope format
var validator = CoseValidatorBuilder
    .ForMessage()
    .ValidateCoseHashEnvelope(originalPayload)
    .Build();
```

**Validators**:
- `IndirectSignatureValidator` - Base for indirect signatures
- `CoseHashVValidator` - Validates CoseHashV format
- `CoseHashEnvelopeValidator` - Validates CoseHashEnvelope format

### 3. Certificate Validation
**Purpose**: Verify certificate-related properties

```csharp
var validator = CoseValidatorBuilder
    .ForMessage()
    .ValidateCertificate(cert => cert
        .HasCommonName("MyApp")
        .IsSignedBy(trustedRoot)
        .NotExpired()
        .HasExtendedKeyUsage(X509KeyUsageFlags.DigitalSignature))
    .Build();

// Chain validation
var validator = CoseValidatorBuilder
    .ForMessage()
    .ValidateCertificateChain(chain => chain
        .TrustRoots(customRoots)
        .AllowRevocationOffline()  // Don't fail if CRL unreachable
        .RequireValidFor(DateTime.UtcNow))
    .Build();
```

**Validators**:
- `CertificateExtractionValidator` - Extracts cert from x5t header
- `CertificateCommonNameValidator` - Validates CN
- `CertificateChainValidator` - Validates cert chain trust
- `CertificateRevocationValidator` - Checks CRL/OCSP
- `CertificateExpirationValidator` - Validates NotBefore/NotAfter
- `CertificateKeyUsageValidator` - Validates EKU/KU

### 4. Header Validation
**Purpose**: Verify header integrity and values

```csharp
var validator = CoseValidatorBuilder
    .ForMessage()
    .RequireProtectedHeaders()  // All critical headers must be protected
    .RequireHeader("alg")
    .RequireHeader("kid", expectedValue: myKid)
    .ForbidUnprotectedHeader("crit")
    .Build();
```

**Validators**:
- `ProtectedHeaderValidator` - Ensures headers are protected
- `RequiredHeaderValidator` - Checks required headers exist
- `HeaderValueValidator` - Validates header values
- `CustomHeaderValidator` - User-defined header validation

### 5. Content Type Validation
**Purpose**: Verify content type matches expectations

```csharp
var validator = CoseValidatorBuilder
    .ForMessage()
    .RequireContentType("application/json")
    .Build();
```

**Validators**:
- `ContentTypeValidator` - Validates content-type header

## Builder API

### Decoupled Extension-Based Pattern

The builder uses a minimal core interface that validators extend through extension methods. This decouples the builder from specific validators and allows validators to contribute their own fluent APIs.

#### Core Builder Interface

```csharp
/// <summary>
/// Core builder interface for COSE message validation.
/// Validators extend this through extension methods to add domain-specific APIs.
/// </summary>
public interface ICoseMessageValidationBuilder
{
    /// <summary>
    /// Adds a validator to the validation pipeline.
    /// Used internally by extension methods to register validators.
    /// </summary>
    ICoseMessageValidationBuilder AddValidator(IValidator<CoseSign1Message> validator);
    
    /// <summary>
    /// Adds a simple function-based validator to the validation pipeline.
    /// </summary>
    ICoseMessageValidationBuilder AddValidator(Func<CoseSign1Message, ValidationResult> validatorFunc);
    
    /// <summary>
    /// Configures whether to stop on first failure or collect all failures.
    /// Default: collect all failures
    /// </summary>
    ICoseMessageValidationBuilder StopOnFirstFailure(bool stopOnFirstFailure = true);
    
    /// <summary>
    /// Configures whether to run validators in parallel when safe.
    /// Default: sequential
    /// </summary>
    ICoseMessageValidationBuilder RunInParallel(bool parallel = true);
    
    /// <summary>
    /// Builds the final composite validator.
    /// </summary>
    IValidator<CoseSign1Message> Build();
    
    /// <summary>
    /// Gets the current builder configuration (for advanced scenarios).
    /// </summary>
    ValidationBuilderContext Context { get; }
}

/// <summary>
/// Entry point for building COSE message validators.
/// </summary>
public static class CoseValidatorBuilder
{
    public static ICoseMessageValidationBuilder ForMessage() => new CoseMessageValidationBuilder();
}

/// <summary>
/// Context that can be shared between validators and extension methods.
/// Allows validators to coordinate and share state during build process.
/// </summary>
public sealed class ValidationBuilderContext
{
    public IDictionary<string, object> Properties { get; } = new Dictionary<string, object>();
    public bool StopOnFirstFailure { get; set; }
    public bool RunInParallel { get; set; }
}
```

#### Extension Method Pattern

Each validator domain provides its own extension methods:

**Signature Validation Extensions** (in `CoseSign1.Validation/Signature/SignatureValidationExtensions.cs`)
```csharp
public static class SignatureValidationExtensions
{
    /// <summary>
    /// Validates the embedded signature using the certificate in x5t header.
    /// </summary>
    public static ICoseMessageValidationBuilder ValidateSignature(
        this ICoseMessageValidationBuilder builder)
    {
        return builder.AddValidator(new SignatureValidator());
    }
    
    /// <summary>
    /// Validates the signature using the provided public key.
    /// </summary>
    public static ICoseMessageValidationBuilder ValidateSignatureWith(
        this ICoseMessageValidationBuilder builder,
        AsymmetricAlgorithm publicKey)
    {
        return builder.AddValidator(new SignatureWithKeyValidator(publicKey));
    }
    
    /// <summary>
    /// Validates the signature with a detached payload.
    /// </summary>
    public static ICoseMessageValidationBuilder ValidateSignature(
        this ICoseMessageValidationBuilder builder,
        byte[] detachedPayload)
    {
        return builder.AddValidator(new DetachedSignatureValidator(detachedPayload));
    }
    
    /// <summary>
    /// Validates the signature with a detached payload.
    /// </summary>
    public static ICoseMessageValidationBuilder ValidateSignature(
        this ICoseMessageValidationBuilder builder,
        ReadOnlyMemory<byte> detachedPayload)
    {
        return builder.AddValidator(new DetachedSignatureValidator(detachedPayload));
    }
}
```

**Certificate Validation Extensions** (in `CoseSign1.Validation/Certificate/CertificateValidationExtensions.cs`)
```csharp
public static class CertificateValidationExtensions
{
    /// <summary>
    /// Validates certificate properties using a domain-specific builder.
    /// Transfers control to ICertificateValidationBuilder for certificate-specific configuration.
    /// </summary>
    public static ICoseMessageValidationBuilder ValidateCertificate(
        this ICoseMessageValidationBuilder builder,
        Action<ICertificateValidationBuilder> configure)
    {
        var certBuilder = new CertificateValidationBuilder();
        configure(certBuilder);
        
        // Build certificate validator and add to main builder
        var validator = certBuilder.Build();
        return builder.AddValidator(validator);
    }
    
    /// <summary>
    /// Validates certificate chain trust using a domain-specific builder.
    /// Transfers control to ICertificateChainValidationBuilder for chain-specific configuration.
    /// </summary>
    public static ICoseMessageValidationBuilder ValidateCertificateChain(
        this ICoseMessageValidationBuilder builder,
        Action<ICertificateChainValidationBuilder> configure)
    {
        var chainBuilder = new CertificateChainValidationBuilder();
        configure(chainBuilder);
        
        // Build chain validator and add to main builder
        var validator = chainBuilder.Build();
        return builder.AddValidator(validator);
    }
}

/// <summary>
/// Domain-specific builder for certificate validation.
/// Keeps certificate-specific APIs separate from main builder.
/// </summary>
public interface ICertificateValidationBuilder
{
    ICertificateValidationBuilder HasCommonName(string commonName);
    ICertificateValidationBuilder IsIssuedBy(string issuerName);
    ICertificateValidationBuilder NotExpired();
    ICertificateValidationBuilder NotExpired(DateTime asOf);
    ICertificateValidationBuilder HasExtendedKeyUsage(Oid eku);
    ICertificateValidationBuilder HasKeyUsage(X509KeyUsageFlags usage);
    ICertificateValidationBuilder Matches(Func<X509Certificate2, bool> predicate, string? failureMessage = null);
    
    // Internal: Build the composite certificate validator
    IValidator<CoseSign1Message> Build();
}

/// <summary>
/// Domain-specific builder for certificate chain validation.
/// Keeps chain-specific APIs separate from main builder.
/// </summary>
public interface ICertificateChainValidationBuilder
{
    ICertificateChainValidationBuilder TrustRoots(params X509Certificate2[] roots);
    ICertificateChainValidationBuilder TrustRoots(X509Certificate2Collection roots);
    ICertificateChainValidationBuilder TrustSystemRoots();
    ICertificateChainValidationBuilder AllowRevocationOffline();
    ICertificateChainValidationBuilder RequireRevocationCheck();
    ICertificateChainValidationBuilder AllowPartialChain();
    ICertificateChainValidationBuilder RequireValidFor(DateTime timestamp);
    ICertificateChainValidationBuilder AllowFlags(X509ChainStatusFlags flags);
    
    // Internal: Build the chain validator
    IValidator<CoseSign1Message> Build();
}
```

**Indirect Signature Extensions** (in `CoseSign1.Validation/Indirect/IndirectSignatureValidationExtensions.cs`)
```csharp
public static class IndirectSignatureValidationExtensions
{
    /// <summary>
    /// Validates an indirect signature by comparing the hash in the signature with the original payload.
    /// Auto-detects CoseHashV or CoseHashEnvelope format.
    /// </summary>
    public static ICoseMessageValidationBuilder ValidateIndirectSignature(
        this ICoseMessageValidationBuilder builder,
        byte[] originalPayload)
    {
        return builder.AddValidator(new IndirectSignatureValidator(originalPayload));
    }
    
    /// <summary>
    /// Validates a CoseHashV indirect signature.
    /// </summary>
    public static ICoseMessageValidationBuilder ValidateCoseHashV(
        this ICoseMessageValidationBuilder builder,
        byte[] originalPayload)
    {
        return builder.AddValidator(new CoseHashVValidator(originalPayload));
    }
    
    /// <summary>
    /// Validates a CoseHashEnvelope indirect signature.
    /// </summary>
    public static ICoseMessageValidationBuilder ValidateCoseHashEnvelope(
        this ICoseMessageValidationBuilder builder,
        byte[] originalPayload)
    {
        return builder.AddValidator(new CoseHashEnvelopeValidator(originalPayload));
    }
    
    /// <summary>
    /// Validates an indirect signature using a domain-specific builder for advanced scenarios.
    /// </summary>
    public static ICoseMessageValidationBuilder ValidateIndirectSignature(
        this ICoseMessageValidationBuilder builder,
        Action<IIndirectSignatureValidationBuilder> configure)
    {
        var indirectBuilder = new IndirectSignatureValidationBuilder();
        configure(indirectBuilder);
        
        var validator = indirectBuilder.Build();
        return builder.AddValidator(validator);
    }
}

/// <summary>
/// Domain-specific builder for indirect signature validation.
/// </summary>
public interface IIndirectSignatureValidationBuilder
{
    IIndirectSignatureValidationBuilder WithPayload(byte[] payload);
    IIndirectSignatureValidationBuilder WithPayload(Stream payloadStream);
    IIndirectSignatureValidationBuilder ExpectFormat(IndirectSignatureFormat format);
    IIndirectSignatureValidationBuilder ExpectHashAlgorithm(HashAlgorithmName algorithm);
    
    IValidator<CoseSign1Message> Build();
}
```

**Header Validation Extensions** (in `CoseSign1.Validation/Headers/HeaderValidationExtensions.cs`)
```csharp
public static class HeaderValidationExtensions
{
    /// <summary>
    /// Requires all critical headers to be protected.
    /// </summary>
    public static ICoseMessageValidationBuilder RequireProtectedHeaders(
        this ICoseMessageValidationBuilder builder)
    {
        return builder.AddValidator(new ProtectedHeaderValidator());
    }
    
    /// <summary>
    /// Requires a specific header to be present.
    /// </summary>
    public static ICoseMessageValidationBuilder RequireHeader(
        this ICoseMessageValidationBuilder builder,
        string headerName,
        object? expectedValue = null)
    {
        return builder.AddValidator(new RequiredHeaderValidator(headerName, expectedValue));
    }
    
    /// <summary>
    /// Forbids a specific header from being in unprotected headers.
    /// </summary>
    public static ICoseMessageValidationBuilder ForbidUnprotectedHeader(
        this ICoseMessageValidationBuilder builder,
        string headerName)
    {
        return builder.AddValidator(new ForbiddenUnprotectedHeaderValidator(headerName));
    }
    
    /// <summary>
    /// Validates headers using a domain-specific builder.
    /// </summary>
    public static ICoseMessageValidationBuilder ValidateHeaders(
        this ICoseMessageValidationBuilder builder,
        Action<IHeaderValidationBuilder> configure)
    {
        var headerBuilder = new HeaderValidationBuilder();
        configure(headerBuilder);
        
        var validator = headerBuilder.Build();
        return builder.AddValidator(validator);
    }
}
```

**Content Type Extensions** (in `CoseSign1.Validation/ContentType/ContentTypeValidationExtensions.cs`)
```csharp
public static class ContentTypeValidationExtensions
{
    /// <summary>
    /// Requires the content type header to match the specified value.
    /// </summary>
    public static ICoseMessageValidationBuilder RequireContentType(
        this ICoseMessageValidationBuilder builder,
        string contentType)
    {
        return builder.AddValidator(new ContentTypeValidator(contentType));
    }
}
```

## Usage Examples

### Example 1: Simple Embedded Signature Validation
```csharp
// Validate that the signature is cryptographically valid
var validator = CoseValidatorBuilder
    .ForMessage()
    .ValidateSignature()
    .Build();

var result = validator.Validate(coseMessage);
if (!result.IsValid)
{
    foreach (var failure in result.Failures)
    {
        Console.WriteLine($"Validation failed: {failure.Message}");
    }
}
```

### Example 2: Detached Payload Validation
```csharp
// Validate detached signature with original payload
var validator = CoseValidatorBuilder
    .ForMessage()
    .ValidateSignature(originalPayloadBytes)
    .Build();

var result = validator.Validate(coseMessage);
```

### Example 3: Indirect Signature Validation
```csharp
// Validate CoseHashEnvelope indirect signature
var validator = CoseValidatorBuilder
    .ForMessage()
    .ValidateCoseHashEnvelope(originalPayloadBytes)
    .ValidateCertificate(cert => cert
        .NotExpired()
        .HasCommonName("MyService"))
    .Build();

var result = await validator.ValidateAsync(coseMessage);
```

### Example 4: Certificate Chain Validation
```csharp
// Validate certificate chain with custom roots
var validator = CoseValidatorBuilder
    .ForMessage()
    .ValidateSignature()
    .ValidateCertificateChain(chain => chain
        .TrustRoots(myCustomRoots)
        .RequireRevocationCheck()
        .RequireValidFor(DateTime.UtcNow))
    .Build();

var result = await validator.ValidateAsync(coseMessage);
```

### Example 5: Comprehensive Validation
```csharp
// Full validation pipeline
var validator = CoseValidatorBuilder
    .ForMessage()
    .ValidateSignature()
    .RequireProtectedHeaders()
    .RequireContentType("application/json")
    .ValidateCertificate(cert => cert
        .NotExpired()
        .HasCommonName("production-service")
        .HasExtendedKeyUsage(new Oid("1.3.6.1.5.5.7.3.3"))) // Code signing
    .ValidateCertificateChain(chain => chain
        .TrustSystemRoots()
        .RequireRevocationCheck()
        .AllowRevocationOffline())  // Don't fail if CRL unreachable
    .Build();

var result = await validator.ValidateAsync(coseMessage);

if (result.IsValid)
{
    Console.WriteLine("All validations passed!");
}
else
{
    Console.WriteLine("Validation failures:");
    foreach (var failure in result.Failures)
    {
        Console.WriteLine($"  [{failure.ErrorCode}] {failure.Message}");
    }
}
```

### Example 6: Custom Validator with Extension Method
```csharp
// Define your custom validator
public class CustomTimestampValidator : IValidator<CoseSign1Message>
{
    private readonly TimeSpan _maxAge;
    
    public CustomTimestampValidator(TimeSpan maxAge)
    {
        _maxAge = maxAge;
    }
    
    public ValidationResult Validate(CoseSign1Message input)
    {
        // Custom validation logic
        // ...
    }
    
    public Task<ValidationResult> ValidateAsync(CoseSign1Message input, CancellationToken ct = default)
    {
        return Task.FromResult(Validate(input));
    }
}

// Create extension method for fluent API
public static class CustomValidationExtensions
{
    public static ICoseMessageValidationBuilder ValidateTimestamp(
        this ICoseMessageValidationBuilder builder,
        TimeSpan maxAge)
    {
        return builder.AddValidator(new CustomTimestampValidator(maxAge));
    }
}

// Usage:
using MyNamespace;  // Brings in CustomValidationExtensions

var validator = CoseValidatorBuilder
    .ForMessage()
    .ValidateSignature()
    .ValidateTimestamp(TimeSpan.FromDays(30))  // Your custom extension method
    .Build();
```

### Example 7: Inline Custom Validator
```csharp
// Quick inline validator without creating a class
var validator = CoseValidatorBuilder
    .ForMessage()
    .ValidateSignature()
    .AddValidator(msg =>
    {
        // Custom logic to check timestamp is within acceptable range
        if (msg.ProtectedHeaders.TryGetValue(CoseHeaderLabel.Algorithm, out var algValue))
        {
            // Custom validation logic here
            return ValidationResult.Success("CustomTimestampValidator");
        }
        return ValidationResult.Failure("CustomTimestampValidator", "Missing algorithm header");
    })
    .Build();
```

### Example 8: Conditional Validation
```csharp
// Different validation based on environment
var builder = CoseValidatorBuilder
    .ForMessage()
    .ValidateSignature();

if (isProduction)
{
    builder = builder
        .ValidateCertificateChain(chain => chain
            .TrustSystemRoots()
            .RequireRevocationCheck()
            .RequireValidFor(DateTime.UtcNow));
}
else
{
    builder = builder
        .ValidateCertificate(cert => cert.NotExpired());
}

var validator = builder.Build();
```

### Example 9: Third-Party Validator Package
```csharp
// Third-party package provides SCITT validation
// Package: Contoso.CoseValidation.Scitt
namespace Contoso.CoseValidation.Scitt
{
    public static class ScittValidationExtensions
    {
        /// <summary>
        /// Validates SCITT (Supply Chain Integrity, Transparency and Trust) compliance.
        /// </summary>
        public static ICoseMessageValidationBuilder ValidateScittCompliance(
            this ICoseMessageValidationBuilder builder,
            ScittOptions? options = null)
        {
            options ??= ScittOptions.Default;
            
            return builder
                .RequireContentType("application/scitt+cose")
                .RequireProtectedHeaders()
                .ValidateCertificateChain(chain => chain
                    .RequireRevocationCheck()
                    .TrustRoots(options.TrustAnchors))
                .AddValidator(new ScittTimestampValidator(options.MaxClockSkew))
                .AddValidator(new ScittReceiptValidator(options.TransparencyServices));
        }
    }
}

// User code:
using Contoso.CoseValidation.Scitt;

var validator = CoseValidatorBuilder
    .ForMessage()
    .ValidateSignature()
    .ValidateScittCompliance()  // Extension from third-party package
    .Build();
```

## Project Structure

```
V2/
  CoseSign1.Validation/                    # New validation library
    CoseValidatorBuilder.cs                # Entry point (minimal)
    ICoseMessageValidationBuilder.cs       # Core builder interface (minimal)
    ValidationBuilderContext.cs            # Shared context
    ValidationResult.cs                    # Result types
    ValidationFailure.cs
    IValidator.cs                          # Core interface
    CompositeValidator.cs                  # Combines validators
    
    Signature/                             # Signature validators
      SignatureValidator.cs
      DetachedSignatureValidator.cs
      SignatureWithKeyValidator.cs
      SignatureValidationExtensions.cs     # Extension methods for builder
    
    Indirect/                              # Indirect signature validators
      IndirectSignatureValidator.cs
      CoseHashVValidator.cs
      CoseHashEnvelopeValidator.cs
      IndirectSignatureValidationExtensions.cs  # Extension methods
      IIndirectSignatureValidationBuilder.cs    # Domain-specific builder
      IndirectSignatureValidationBuilder.cs
    
    Certificate/                           # Certificate validators
      CertificateExtractionValidator.cs
      CertificateCommonNameValidator.cs
      CertificateChainValidator.cs
      CertificateRevocationValidator.cs
      CertificateExpirationValidator.cs
      CertificateKeyUsageValidator.cs
      CertificateValidationExtensions.cs   # Extension methods
      ICertificateValidationBuilder.cs     # Domain-specific builder
      CertificateValidationBuilder.cs
      ICertificateChainValidationBuilder.cs
      CertificateChainValidationBuilder.cs
    
    Headers/                               # Header validators
      ProtectedHeaderValidator.cs
      RequiredHeaderValidator.cs
      HeaderValueValidator.cs
      ForbiddenUnprotectedHeaderValidator.cs
      HeaderValidationExtensions.cs        # Extension methods
      IHeaderValidationBuilder.cs          # Domain-specific builder
      HeaderValidationBuilder.cs
    
    ContentType/                           # Content type validators
      ContentTypeValidator.cs
      ContentTypeValidationExtensions.cs   # Extension methods
    
    Extensions/                            # General extension methods
      CoseSign1MessageExtensions.cs        # Helper extensions for extraction
  
  CoseSign1.Validation.Tests/              # Tests
    SignatureValidationTests.cs
    IndirectSignatureValidationTests.cs
    CertificateValidationTests.cs
    BuilderTests.cs
    ExtensibilityTests.cs                  # Tests for custom validators
```

## Benefits of This Design

1. **Discoverable**: IntelliSense guides users through available validations via extension methods
2. **Composable**: Mix and match validators as needed
3. **Testable**: Each validator can be unit tested in isolation
4. **Extensible**: Users can add custom validators with their own extension methods without modifying core
5. **Maintainable**: Clear separation of concerns, validators are self-contained
6. **Performant**: Can run validators in parallel when safe
7. **Flexible**: Same validators work sync or async
8. **Informative**: Collect all validation failures, not just first one
9. **Type-Safe**: Compile-time checking of validator combinations
10. **Modern**: Follows current C# best practices (records, init-only, nullable)
11. **Decoupled**: Core builder doesn't need to know about all validators upfront
12. **Domain-Specific**: Validators can provide their own specialized builder interfaces
13. **Open/Closed**: Open for extension (new validators), closed for modification (core builder)

### Extension Method Benefits

**For Library Authors:**
- Add new validators without modifying `ICoseMessageValidationBuilder`
- Package validators in separate assemblies if desired
- Validators own their own API surface

**For Library Users:**
- Only see relevant extension methods based on using statements
- IntelliSense shows validator-specific methods naturally
- Can create domain-specific extension packages

**Example: Third-Party Extension Package**
```csharp
// In separate package: MyCompany.CoseValidation.Extensions
namespace MyCompany.CoseValidation
{
    public static class ScittValidationExtensions
    {
        public static ICoseMessageValidationBuilder ValidateScittCompliance(
            this ICoseMessageValidationBuilder builder)
        {
            return builder
                .RequireContentType("application/scitt+cose")
                .ValidateCertificateChain(chain => chain
                    .RequireRevocationCheck()
                    .TrustSystemRoots())
                .AddValidator(new ScittTimestampValidator());
        }
    }
}

// Usage:
using MyCompany.CoseValidation;  // Brings in ScittValidationExtensions

var validator = CoseValidatorBuilder
    .ForMessage()
    .ValidateSignature()
    .ValidateScittCompliance()  // Extension method from third-party package
    .Build();
```

## Migration Path from V1

V1 validators can be wrapped in V2 adapters:

```csharp
public class V1ValidatorAdapter : IValidator<CoseSign1Message>
{
    private readonly CoseSign1MessageValidator _v1Validator;
    
    public ValidationResult Validate(CoseSign1Message input)
    {
        try
        {
            var v1Result = _v1Validator.Validate(input);
            return ValidationResult.Success("V1Adapter", new Dictionary<string, object>
            {
                ["V1Result"] = v1Result
            });
        }
        catch (CoseValidationException ex)
        {
            return ValidationResult.Failure("V1Adapter", ex.Message, "V1_VALIDATION_FAILED");
        }
    }
}
```

## Implementation Priority

**Phase 1: Core Infrastructure** (Essential)
1. `IValidator<T>`, `ValidationResult`, `ValidationFailure`
2. `CoseValidatorBuilder` and basic builder infrastructure
3. `CompositeValidator`

**Phase 2: Signature Validation** (High Priority)
1. `SignatureValidator` (embedded signature)
2. `DetachedSignatureValidator`
3. `SignatureWithKeyValidator`

**Phase 3: Certificate Validation** (High Priority)
1. `CertificateExtractionValidator`
2. `CertificateChainValidator`
3. `CertificateExpirationValidator`
4. `CertificateCommonNameValidator`

**Phase 4: Indirect Signatures** (Medium Priority)
1. `CoseHashEnvelopeValidator`
2. `CoseHashVValidator`

**Phase 5: Advanced Features** (Lower Priority)
1. `CertificateRevocationValidator` (async CRL/OCSP)
2. Header validators
3. Parallel execution
4. Performance optimizations

## Open Questions

1. Should validation results be cached? If so, how long?
2. Should we provide pre-built validator combinations for common scenarios?
3. Do we need a "validation profile" concept (e.g., "SCITT profile", "Production profile")?
4. Should async be the default, with sync as a wrapper?
5. How to handle validator dependencies (e.g., chain validation depends on cert extraction)?
