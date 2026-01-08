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
using var chainBuilder = new CoseSign1.Certificates.ChainBuilders.X509ChainBuilder();
var service = CertificateSigningService.Create(certificate, chainBuilder);
var factory = new DirectSignatureFactory(service);
var message = await factory.CreateCoseSign1MessageAsync(payload, contentType: "application/octet-stream");
```

### 2. Composition Over Configuration

Build functionality through composition rather than configuration strings:

```csharp
// ❌ V1: String-based configuration
CoseHandler.SetValidation("RequireEku:1.3.6.1.4.1.311.10.3.13");

// ✅ V2: Composable validators
var validator = Cose.Sign1Message()
    .ValidateCertificate(cert => cert
        .AllowUnprotectedHeaders()
        .HasEnhancedKeyUsage("1.3.6.1.4.1.311.10.3.13"))
    .Build();
```

### 3. Dependency Injection First

All services use DI patterns:

```csharp
// Register services
builder.Services
    .AddSingleton<ISigningService<CertificateSigningOptions>>(sp =>
    {
        using var cb = new CoseSign1.Certificates.ChainBuilders.X509ChainBuilder();
        return CertificateSigningService.Create(certificate, cb);
    })
    .AddSingleton<IValidator>(sp =>
        Cose.Sign1Message().ValidateCertificateSignature(allowUnprotectedHeaders: true).Build());

// Inject and use
public class DocumentSigner(ISigningService<SigningOptions> signingService)
{
    public async Task<CoseSign1Message> SignAsync(byte[] document)
        => await new DirectSignatureFactory(signingService)
            .CreateCoseSign1MessageAsync(document, contentType: "application/octet-stream");
}
```

### 4. Testability

Every component is designed for testing:

```csharp
// Prefer real signing services + test certificates for high-fidelity tests
using var cert = TestCertificates.CreateEcdsa();
using var chainBuilder = new CoseSign1.Certificates.ChainBuilders.X509ChainBuilder();
using var signingService = CertificateSigningService.Create(cert, chainBuilder);
using var factory = new DirectSignatureFactory(signingService);

byte[] signed = factory.CreateCoseSign1MessageBytes(payload, contentType: "application/octet-stream");
```

## Dependency Injection and Services

### Service Interfaces

V2 defines clear service interfaces:

```csharp
public interface ISigningService<out TSigningOptions> : IDisposable
{
    CoseSigner GetCoseSigner(SigningContext context);
    TSigningOptions CreateSigningOptions();
    bool IsRemote { get; }
    SigningServiceMetadata ServiceMetadata { get; }
}

public interface IValidator
{
    IReadOnlyCollection<ValidationStage> Stages { get; }
    ValidationResult Validate(CoseSign1Message input, ValidationStage stage);
}

// V2 stage-aware validators implement IValidator (non-generic) with a ValidationStage parameter.
```

### Service Lifetime

Different services have different lifetimes:

```csharp
// Singleton: stateless validators/builders
services.AddSingleton<IValidator>(sp =>
    Cose.Sign1Message().ValidateCertificateSignature(allowUnprotectedHeaders: true).Build());

// Scoped/Transient: your app decides based on lifecycle of credentials/certs
services.AddScoped<ISigningService<CertificateSigningOptions>>(sp =>
{
    var cert = sp.GetRequiredService<X509Certificate2>();
    using var cb = new CoseSign1.Certificates.ChainBuilders.X509ChainBuilder();
    return CertificateSigningService.Create(cert, cb);
});
```

### Service Registration Patterns

```csharp
// Simple registration
services.AddSingleton<ISigningService<CertificateSigningOptions>>(sp =>
{
    using var cb = new CoseSign1.Certificates.ChainBuilders.X509ChainBuilder();
    return CertificateSigningService.Create(certificate, cb);
});

// Configuration-based: bind options in your application and construct the signing service from those values.
```

## Factory Pattern

Factories create COSE Sign1 messages with different characteristics.

### Direct vs Indirect Signatures

```csharp
// Direct signature: Payload embedded in message
var directFactory = new DirectSignatureFactory(signingService);
var directMessage = await directFactory.CreateCoseSign1MessageAsync(payload, contentType: "application/octet-stream");
// Message contains payload

// Indirect signature: Payload referenced by hash
var indirectFactory = new IndirectSignatureFactory(signingService);
var indirectMessage = await indirectFactory.CreateCoseSign1MessageAsync(payload, contentType: "application/octet-stream");
// Message contains hash(payload), not payload
```

### Factory Configuration

Factories accept optional configuration:

```csharp
var factory = new DirectSignatureFactory(signingService);

var options = new DirectSignatureOptions
{
    EmbedPayload = false,
    AdditionalHeaderContributors = new IHeaderContributor[]
    {
        new CwtClaimsHeaderContributor(),
        new TimestampHeaderContributor(),
    }
};

var message = await factory.CreateCoseSign1MessageAsync(payload, contentType: "application/octet-stream", options);
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
    new IValidator[]
    {
        new CertificateSignatureValidator(),
        new CertificateExpirationValidator(),
        new EkuPolicyValidator(requiredEkus),
        new CustomBusinessValidator()
    });

// Each validator is independent and testable
var signatureResult = validator.Validate(message, ValidationStage.Signature);
var postSignatureResult = validator.Validate(message, ValidationStage.PostSignature);
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
public class SigningOptions
{
    public bool DisableTransparency { get; set; }
    public bool FailOnTransparencyError { get; set; } = true;
    public IReadOnlyList<IHeaderContributor>? AdditionalHeaderContributors { get; set; }
}

// Once created, cannot be modified
var options = new SigningOptions 
{ 
    DisableTransparency = true
};
```

### Immutable Results

```csharp
public sealed class ValidationResult
{
    public ValidationResultKind Kind { get; init; }
    public ValidationStage? Stage { get; init; }

    public bool IsValid { get; }
    public string ValidatorName { get; init; } = string.Empty;
    public IReadOnlyList<ValidationFailure> Failures { get; init; } = Array.Empty<ValidationFailure>();
}

// Result cannot be modified after creation
var result = validator.Validate(message, ValidationStage.PostSignature);
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
public sealed class MySigningService : ISigningService<SigningOptions>
{
    private bool disposed;

    public void Dispose()
    {
        disposed = true;
    }

    public CoseSigner GetCoseSigner(SigningContext context) => throw new NotImplementedException();

    public SigningOptions CreateSigningOptions() => new();

    public bool IsRemote => false;

    public SigningServiceMetadata ServiceMetadata => new("MySigningService", "Example signing service");
}
```

### Using Statements

```csharp
// Automatic disposal
using var chainBuilder = new CoseSign1.Certificates.ChainBuilders.X509ChainBuilder();
using var service = CertificateSigningService.Create(cert, chainBuilder);
using var factory = new DirectSignatureFactory(service);
var message = await factory.CreateCoseSign1MessageAsync(payload, contentType: "application/octet-stream");
// service disposed here
```

### Certificate Ownership

```csharp
// CertificateSigningService does not dispose the provided certificate.
// The caller owns and must dispose the certificate.
using var cert = new X509Certificate2(path, password);
using var chainBuilder = new CoseSign1.Certificates.ChainBuilders.X509ChainBuilder();
using var service = CertificateSigningService.Create(cert, chainBuilder);
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
// Example: factory methods validate inputs and throw if required state is missing.
using var cert = new X509Certificate2(path, password);
using var chainBuilder = new CoseSign1.Certificates.ChainBuilders.X509ChainBuilder();
using var service = CertificateSigningService.Create(cert, chainBuilder); // throws if cert has no private key
```

### Results for Validation

```csharp
// Return results for expected failures (validation)
public ValidationResult Validate(CoseSign1Message message)
{
    if (!VerifySignature(message))
    {
        return ValidationResult.Failure(
            validatorName: nameof(MyValidator),
            message: "Cryptographic signature verification failed",
            errorCode: "SignatureVerificationFailed");
    }

    return ValidationResult.Success(nameof(MyValidator), stage);
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
var result = validator.Validate(message, ValidationStage.PostSignature);

if (!result.IsValid)
{
    foreach (var failure in result.Failures)
    {
        Console.WriteLine($"{failure.ErrorCode}: {failure.Message}");
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
