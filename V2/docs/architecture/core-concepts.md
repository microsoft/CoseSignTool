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
using var factory = new CoseSign1MessageFactory(service);
var message = await factory.CreateCoseSign1MessageAsync<CoseSign1.Factories.Direct.DirectSignatureOptions>(
    payload,
    contentType: "application/octet-stream");
```

### 2. Composition Over Configuration

Build functionality through composition rather than configuration strings:

```csharp
// ❌ V1: String-based configuration
CoseHandler.SetValidation("RequireEku:1.3.6.1.4.1.311.10.3.13");

// ✅ V2: Composable trust requirements (facts + rules)
var services = new ServiceCollection();
var validation = services.ConfigureCoseValidation();

validation.EnableCertificateSupport(cert => cert
    .UseSystemTrust()
    );

var policy = TrustPlanPolicy.PrimarySigningKey(key => key.RequireFact<X509SigningCertificateEkuFact>(
    f => f.OidValue == "1.3.6.1.4.1.311.10.3.13",
    "Signing certificate must include EKU 1.3.6.1.4.1.311.10.3.13"));

services.AddSingleton<CompiledTrustPlan>(sp => policy.Compile(sp));

using var sp = services.BuildServiceProvider();
var validator = sp.GetRequiredService<ICoseSign1ValidatorFactory>().Create();
```

### 3. Dependency Injection First

All services use DI patterns:

```csharp
// Register services
builder.Services
    .AddSingleton<ISigningService<SigningOptions>>(sp =>
    {
        using var cb = new CoseSign1.Certificates.ChainBuilders.X509ChainBuilder();
        return CertificateSigningService.Create(certificate, cb);
    })
    .ConfigureCoseValidation()
    .EnableCertificateSupport(cert => cert.UseSystemTrust());

builder.Services.AddScoped<ICoseSign1Validator>(sp =>
    sp.GetRequiredService<ICoseSign1ValidatorFactory>().Create());

// Inject and use
public class DocumentSigner(ISigningService<SigningOptions> signingService)
{
    public async Task<CoseSign1Message> SignAsync(byte[] document)
        => await new CoseSign1MessageFactory(signingService)
            .CreateCoseSign1MessageAsync<CoseSign1.Factories.Direct.DirectSignatureOptions>(
                document,
                contentType: "application/octet-stream");
}
```

### 4. Testability

Every component is designed for testing:

```csharp
// Prefer real signing services + test certificates for high-fidelity tests
using var cert = TestCertificates.CreateEcdsa();
using var chainBuilder = new CoseSign1.Certificates.ChainBuilders.X509ChainBuilder();
using var signingService = CertificateSigningService.Create(cert, chainBuilder);
using var factory = new CoseSign1MessageFactory(signingService);

byte[] signed = factory.CreateCoseSign1MessageBytes<CoseSign1.Factories.Direct.DirectSignatureOptions>(
    payload,
    contentType: "application/octet-stream");
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

public interface ICoseSign1Validator
{
    CoseSign1ValidationResult Validate(CoseSign1Message message);
}
```

### Service Lifetime

Different services have different lifetimes:

```csharp
// Scoped: build the validator from the current DI scope
services.ConfigureCoseValidation()
    .EnableCertificateSupport(cert => cert.UseSystemTrust());

services.AddScoped<ICoseSign1Validator>(sp =>
    sp.GetRequiredService<ICoseSign1ValidatorFactory>().Create());

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
services.AddSingleton<ISigningService<SigningOptions>>(sp =>
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
// Preferred: route via the options type for your intent
using var factory = new CoseSign1MessageFactory(signingService);

var directMessage = await factory.CreateCoseSign1MessageAsync<CoseSign1.Factories.Direct.DirectSignatureOptions>(
    payload,
    contentType: "application/octet-stream");

var indirectMessage = await factory.CreateCoseSign1MessageAsync<CoseSign1.Factories.Indirect.IndirectSignatureOptions>(
    payload,
    contentType: "application/octet-stream");
```

### Factory Configuration

Factories accept optional configuration:

```csharp
using var factory = new CoseSign1MessageFactory(signingService);

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
    public HeaderMergeStrategy MergeStrategy => HeaderMergeStrategy.Fail;

    public void ContributeProtectedHeaders(CoseHeaderMap headers, HeaderContributorContext context)
        => headers.Add(new CoseHeaderLabel("custom"), CoseHeaderValue.FromString("value"));

    public void ContributeUnprotectedHeaders(CoseHeaderMap headers, HeaderContributorContext context)
    {
        // Optional: add unsigned metadata here.
    }
}

using var factory = new CoseSign1MessageFactory(service);

var options = new DirectSignatureOptions
{
    AdditionalHeaderContributors = new[] { new CustomHeaderContributor() }
};

byte[] signature = factory.CreateCoseSign1MessageBytes(payload, contentType, options);
```

## Builder Pattern

Builders construct complex objects step-by-step.

### TrustPlanPolicy Builder

```csharp
// Build an explicit trust requirement (facts + rules)
var policy = TrustPlanPolicy.PrimarySigningKey(key => key
    .RequireFact<X509ChainTrustedFact>(f => f.IsTrusted, "X.509 chain must be trusted"));
```

### Certificate Chain Builder

```csharp
using CoseSign1.Certificates.ChainBuilders;
using System.Security.Cryptography.X509Certificates;

var policy = new X509ChainPolicy
{
    RevocationMode = X509RevocationMode.Online,
    VerificationFlags = X509VerificationFlags.NoFlag,
};

using var chainBuilder = new X509ChainBuilder(policy);
bool ok = chainBuilder.Build(leafCertificate);
IReadOnlyCollection<X509Certificate2> chain = chainBuilder.ChainElements;
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
// Compose validation via DI: trust packs + post-signature validators
var services = new ServiceCollection();
var validation = services.ConfigureCoseValidation();
validation.EnableCertificateSupport(cert => cert.UseSystemTrust());

services.AddSingleton<IPostSignatureValidator, CustomBusinessValidator>();

using var sp = services.BuildServiceProvider();
var validator = sp.GetRequiredService<ICoseSign1ValidatorFactory>().Create();

var result = message.Validate(validator);
var signatureResult = result.Signature;
var postSignatureResult = result.PostSignaturePolicy;
```

### Header Contribution Composition

```csharp
// Compose header contributors
using var factory = new CoseSign1MessageFactory(service);

var options = new DirectSignatureOptions
{
    AdditionalHeaderContributors = new IHeaderContributor[]
    {
        new CwtClaimsHeaderContributor(),      // Add CWT claims
        new CertificateHeaderContributor(),    // Add certificate headers (x5t/x5chain)
        new TimestampHeaderContributor(),      // Add timestamp
        new CustomHeaderContributor()          // Add custom headers
    }
};

var message = await factory.CreateCoseSign1MessageAsync(payload, contentType: "application/octet-stream", options);
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

    public bool IsValid { get; }
    public string ValidatorName { get; init; } = string.Empty;
    public IReadOnlyList<ValidationFailure> Failures { get; init; } = Array.Empty<ValidationFailure>();
}

// Result cannot be modified after creation
var result = message.Validate(validator);
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
using var factory = new CoseSign1MessageFactory(service);
var message = await factory.CreateCoseSign1MessageAsync<CoseSign1.Factories.Direct.DirectSignatureOptions>(payload, contentType: "application/octet-stream");
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
public sealed class MyPostSignatureValidator : IPostSignatureValidator
{
    public ValidationResult Validate(IPostSignatureValidationContext context)
    {
        if (!VerifyBusinessRules(context.Message))
        {
            return ValidationResult.Failure(
                validatorName: nameof(MyPostSignatureValidator),
                message: "Post-signature policy check failed",
                errorCode: "PostSignaturePolicyFailed");
        }

        return ValidationResult.Success(nameof(MyPostSignatureValidator));
    }

    public Task<ValidationResult> ValidateAsync(
        IPostSignatureValidationContext context,
        CancellationToken cancellationToken = default)
        => Task.FromResult(Validate(context));

    private static bool VerifyBusinessRules(CoseSign1Message message) => true;
}
```

### Common Exceptions

```csharp
// Common exceptions you may see when processing COSE signatures:
// - ArgumentNullException: invalid API usage
// - InvalidOperationException: validation builder missing a signing key resolver
// - CryptographicException: invalid COSE encoding/signature verification failure
// - CoseX509FormatException: malformed X.509 header data (x5chain/x5t)
```

### Validation Result Pattern

```csharp
var message = CoseMessage.DecodeSign1(signatureBytes);

var result = message.Validate(builder => builder
    .ValidateCertificate(cert => cert.ValidateChain())
    .AddComponent(new MyPostSignatureValidator()));

if (!result.Overall.IsValid)
{
    foreach (var failure in result.Overall.Failures)
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
