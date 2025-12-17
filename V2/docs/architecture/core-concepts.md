# Core Concepts

This document explains the fundamental concepts and patterns used throughout CoseSignTool V2.

## Table of Contents

- [Design Philosophy](#design-philosophy)
- [Dependency Injection and Services](#dependency-injection-and-services)
- [Factory Pattern](#factory-pattern)
- [Builder Pattern](#builder-pattern)
- [Composition Over Inheritance](#composition-over-inheritance)
- [Immutability](#immutability)
- [Resource Management](#resource-management)
- [Error Handling](#error-handling)

## Design Philosophy

V2 is built on several core principles:

### 1. Explicit Over Implicit

Every operation is explicit and intentional:

```csharp
// ❌ V1: Implicit certificate selection
var signature = CoseHandler.Sign(payload);

// ✅ V2: Explicit signing service configuration
var service = CertificateSigningService.Create(certificate);
var factory = new DirectSignatureFactory(service);
var signature = await factory.CreateAsync(payload);
```

### 2. Composition Over Configuration

Build functionality through composition rather than configuration strings:

```csharp
// ❌ V1: String-based configuration
CoseHandler.SetValidation("RequireEku:1.3.6.1.4.1.311.10.3.13");

// ✅ V2: Composable validators
var validator = new ValidatorBuilder()
    .WithEkuPolicy(new[] { "1.3.6.1.4.1.311.10.3.13" })
    .WithSignatureValidator()
    .Build();
```

### 3. Dependency Injection First

All services use DI patterns:

```csharp
// Register services
builder.Services
    .AddSingleton<ISigningService>(sp => CertificateSigningService.Create(certificate))
    .AddSingleton<IValidator<CoseSign1Message>, CompositeValidator>();

// Inject and use
public class DocumentSigner(ISigningService signingService)
{
    public async Task<CoseSign1Message> SignAsync(byte[] document)
        => await new DirectSignatureFactory(signingService)
            .CreateAsync(document);
}
```

### 4. Testability

Every component is designed for testing:

```csharp
// Mock signing service for testing
var mockService = new Mock<ISigningService>();
mockService.Setup(s => s.SignAsync(It.IsAny<byte[]>(), CancellationToken.None))
    .ReturnsAsync(new byte[64]);

var factory = new DirectSignatureFactory(mockService.Object);
var result = await factory.CreateAsync(payload);
```

## Dependency Injection and Services

### Service Interfaces

V2 defines clear service interfaces:

```csharp
public interface ISigningService : IDisposable
{
    Task<byte[]> SignAsync(byte[] data, CancellationToken cancellationToken = default);
    CoseAlgorithm Algorithm { get; }
}

public interface IValidator<T>
{
    ValidationResult Validate(T message, ValidationOptions? options = null);
}

public interface ICertificateSource : IDisposable
{
    X509Certificate2? GetCertificate();
}
```

### Service Lifetime

Different services have different lifetimes:

```csharp
// Singleton: Stateless services, expensive to create
services.AddSingleton<ICertificateValidator, CertificateSignatureValidator>();

// Scoped: Per-request services with state
services.AddScoped<ISigningService, AzureTrustedSigningService>();

// Transient: Lightweight, stateful services
services.AddTransient<ICoseSign1MessageFactory, DirectSignatureFactory>();
```

### Service Registration Patterns

```csharp
// Simple registration
services.AddSingleton<ISigningService>(sp => 
    CertificateSigningService.Create(certificate));

// Factory pattern
services.AddSingleton<ISigningService>(sp => 
{
    var certSource = sp.GetRequiredService<ICertificateSource>();
    return CertificateSigningService.Create(certSource.GetCertificate()!);
});

// Configuration-based
services.Configure<SigningOptions>(Configuration.GetSection("Signing"));
services.AddSingleton<ISigningService, ConfiguredSigningService>();
```

## Factory Pattern

Factories create COSE Sign1 messages with different characteristics.

### Direct vs Indirect Signatures

```csharp
// Direct signature: Payload embedded in message
var directFactory = new DirectSignatureFactory(signingService);
var directMessage = await directFactory.CreateAsync(payload);
// Message contains payload

// Indirect signature: Payload referenced by hash
var indirectFactory = new IndirectSignatureFactory(signingService);
var indirectMessage = await indirectFactory.CreateAsync(payload);
// Message contains hash(payload), not payload
```

### Factory Configuration

Factories accept optional configuration:

```csharp
var factory = new DirectSignatureFactory(
    signingService: service,
    headerContributors: new IHeaderContributor[] 
    { 
        new CwtClaimsHeaderContributor(),
        new TimestampHeaderContributor()
    },
    embeddedPayloadSupport: EmbeddedPayloadSupport.DetachedButEmbeddedHint
);
```

### Factory Extensibility

Extend factories with header contributors:

```csharp
public class CustomHeaderContributor : IHeaderContributor
{
    public Task ContributeAsync(
        CoseHeaderMap headers,
        byte[] payload,
        CancellationToken cancellationToken = default)
    {
        headers.SetValue(new CoseHeaderLabel("custom"), new CoseHeaderValue("value"));
        return Task.CompletedTask;
    }
}

var factory = new DirectSignatureFactory(
    service,
    headerContributors: new[] { new CustomHeaderContributor() }
);
```

## Builder Pattern

Builders construct complex objects step-by-step.

### Validator Builder

```csharp
var validator = new ValidatorBuilder()
    .WithSignatureValidator()           // Verify cryptographic signature
    .WithExpirationValidator()          // Check certificate expiration
    .WithEkuPolicy(requiredEkus)        // Require specific EKUs
    .WithSanPolicy(allowedSans)         // Require specific SANs
    .WithCustomValidator(myValidator)   // Add custom logic
    .Build();
```

### Certificate Chain Builder

```csharp
var chain = new CertificateChainBuilder()
    .WithChainPolicy(policy => 
    {
        policy.RevocationMode = X509RevocationMode.Online;
        policy.VerificationFlags = X509VerificationFlags.AllowUnknownCertificateAuthority;
    })
    .WithRootCertificates(rootCerts)
    .WithIntermediateCertificates(intermediates)
    .Build();
```

### Builder Benefits

1. **Fluent API**: Readable, discoverable
2. **Validation**: Validates configuration before building
3. **Immutability**: Returns immutable objects
4. **Testability**: Easy to configure for tests

## Composition Over Inheritance

V2 favors composition over class hierarchies.

### Validator Composition

```csharp
// Compose validators instead of inheriting
var validator = new CompositeValidator(
    new CertificateSignatureValidator(),
    new CertificateExpirationValidator(),
    new EkuPolicyValidator(requiredEkus),
    new CustomBusinessValidator()
);

// Each validator is independent and testable
var result = validator.Validate(message);
```

### Header Contribution Composition

```csharp
// Compose header contributors
var factory = new DirectSignatureFactory(
    service,
    headerContributors: new IHeaderContributor[]
    {
        new CwtClaimsHeaderContributor(),      // Add CWT claims
        new CertificateHeaderContributor(),    // Add certificate chain
        new TimestampHeaderContributor(),      // Add timestamp
        new CustomHeaderContributor()          // Add custom headers
    }
);
```

### Benefits

- **Flexibility**: Mix and match components
- **Testability**: Test components in isolation
- **Reusability**: Reuse components across scenarios
- **Maintainability**: Changes affect single components

## Immutability

V2 emphasizes immutable objects where appropriate.

### Immutable Configuration

```csharp
public record SigningOptions
{
    public required CoseAlgorithm Algorithm { get; init; }
    public required string CertificateThumbprint { get; init; }
    public bool IncludeChain { get; init; } = true;
}

// Once created, cannot be modified
var options = new SigningOptions 
{ 
    Algorithm = CoseAlgorithm.ES256,
    CertificateThumbprint = "..." 
};
```

### Immutable Results

```csharp
public record ValidationResult
{
    public required bool Success { get; init; }
    public required IReadOnlyList<ValidationFailure> Failures { get; init; }
    public required CoseSign1Message Message { get; init; }
}

// Result cannot be modified after creation
var result = validator.Validate(message);
```

### Benefits

- **Thread safety**: Safe to share across threads
- **Predictability**: State cannot change unexpectedly
- **Debugging**: Easier to reason about state
- **Caching**: Safe to cache immutable objects

## Resource Management

V2 follows .NET resource management patterns.

### IDisposable Implementation

```csharp
public class CertificateSigningServiceImpl : ISigningService
{
    private readonly X509Certificate2 _certificate;
    private bool _disposed;

    public void Dispose()
    {
        if (_disposed) return;
        _certificate?.Dispose();
        _disposed = true;
    }
}
```

### Using Statements

```csharp
// Automatic disposal
using var service = CertificateSigningService.Create(cert);
using var factory = new DirectSignatureFactory(service);
var message = await factory.CreateAsync(payload);
// service disposed here
```

### Certificate Ownership

```csharp
// Service takes ownership of certificate
using var cert = new X509Certificate2(path, password);
using var service = CertificateSigningService.Create(cert);
// service will dispose cert

// Service does NOT take ownership (use certificate source)
var cert = certificateStore.GetCertificate();
var service = CertificateSigningService.Create(cert);
// You must dispose cert
```

### Async Disposal

```csharp
public class AsyncSigningService : IAsyncDisposable
{
    public async ValueTask DisposeAsync()
    {
        await FlushBuffersAsync();
        // Dispose resources
    }
}

await using var service = new AsyncSigningService();
```

## Error Handling

V2 uses exceptions for exceptional cases, results for validation.

### Exceptions for Errors

```csharp
// Throw for programming errors or system failures
public class CertificateSigningServiceImpl(X509Certificate2 certificate)
{
    public Task<byte[]> SignAsync(byte[] data, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(data);
        
        if (!certificate.HasPrivateKey)
            throw new CoseSign1CertificateException(
                "Certificate must have a private key");
        
        // ... signing logic
    }
}
```

### Results for Validation

```csharp
// Return results for expected failures (validation)
public ValidationResult Validate(CoseSign1Message message)
{
    var failures = new List<ValidationFailure>();
    
    if (!VerifySignature(message))
        failures.Add(new ValidationFailure(
            ValidationFailureCode.SignatureVerificationFailed,
            "Cryptographic signature verification failed"));
    
    return new ValidationResult
    {
        Success = failures.Count == 0,
        Failures = failures,
        Message = message
    };
}
```

### Exception Types

```csharp
// Base exception
public class CoseSign1Exception : Exception

// Specific exceptions
public class CoseSign1CertificateException : CoseSign1Exception
public class CoseSign1ValidationException : CoseSign1Exception
public class CoseSign1FormatException : CoseSign1Exception
```

### Validation Result Pattern

```csharp
var result = validator.Validate(message);

if (!result.Success)
{
    foreach (var failure in result.Failures)
    {
        Console.WriteLine($"{failure.Code}: {failure.Message}");
    }
}
```

## Next Steps

- [Architecture Overview](overview.md) - High-level architecture and component diagrams
- [Quick Start](../getting-started/quick-start.md) - Get started in 5 minutes
- [Migration Guide](../getting-started/migration-from-v1.md) - Migrate from V1

## Package Documentation

- [CoseSign1.Abstractions](../../CoseSign1.Abstractions/README.md) - Core interfaces
- [CoseSign1.Certificates](../../CoseSign1.Certificates/README.md) - Certificate signing services
- [CoseSign1.Validation](../../CoseSign1.Validation/README.md) - Validation framework
- [CoseSign1.Headers](../../CoseSign1.Headers/README.md) - Header contributors and CWT claims
