# CoseSign1.Abstractions

Core interfaces and abstractions for the CoseSignTool V2 architecture.

## Installation

```bash
dotnet add package CoseSign1.Abstractions --version 2.0.0-preview
```

## Overview

This package provides the foundational interfaces and contracts used throughout the V2 ecosystem. It establishes the abstraction layer that enables dependency injection, testability, and extensibility.

## Key Features

- ✅ **ICoseSign1MessageFactory<TOptions>** - Generic factory for creating COSE Sign1 messages
- ✅ **ISigningService<TOptions>** - Service abstraction that emits `CoseSigner` instances
- ✅ **ISigningKey** - Key abstraction for cryptographic operations
- ✅ **IHeaderContributor** - Extensible header contribution system
- ✅ **ITransparencyProvider** - Transparency service integration
- ✅ **Dependency Injection Ready** - Designed for modern DI patterns

## Core Interfaces

### ICoseSign1MessageFactory<TOptions>

Generic factory interface for creating COSE Sign1 messages with type-safe options:

```csharp
public interface ICoseSign1MessageFactory<TOptions> : IDisposable
    where TOptions : SigningOptions
{
    // Synchronous creation
    byte[] CreateCoseSign1MessageBytes(
        byte[] payload, 
        string contentType, 
        TOptions? options = default);
    
    // Asynchronous creation
    Task<byte[]> CreateCoseSign1MessageBytesAsync(
        byte[] payload, 
        string contentType, 
        TOptions? options = default,
        CancellationToken cancellationToken = default);
    
    // Transparency providers
    IReadOnlyList<ITransparencyProvider>? TransparencyProviders { get; }
}
```

### ISigningService<TOptions>

Service that provides `CoseSigner` instances for signing operations:

```csharp
public interface ISigningService<out TSigningOptions> : IDisposable
    where TSigningOptions : SigningOptions
{
    // Creates CoseSigner with key and headers
    CoseSigner GetCoseSigner(SigningContext context);
    
    // Creates default options instance
    TSigningOptions CreateSigningOptions();
    
    // Service characteristics
    bool IsRemote { get; }
    SigningServiceMetadata ServiceMetadata { get; }
}
```

### ISigningKey

Abstraction for cryptographic signing keys:

```csharp
public interface ISigningKey : IDisposable
{
    // Gets the underlying CoseKey for signing
    CoseKey GetCoseKey();
    
    // Key metadata (algorithm, type, size)
    SigningKeyMetadata Metadata { get; }
    
    // Back-reference to owning service
    ISigningService<SigningOptions> SigningService { get; }
}
```

### IHeaderContributor

Extension point for adding headers to COSE messages:

```csharp
public interface IHeaderContributor
{
    // How to handle existing headers
    HeaderMergeStrategy MergeStrategy { get; }
    
    // Add protected headers
    void ContributeProtectedHeaders(
        CoseHeaderMap headers, 
        HeaderContributorContext context);
    
    // Add unprotected headers
    void ContributeUnprotectedHeaders(
        CoseHeaderMap headers, 
        HeaderContributorContext context);
}
```

### ITransparencyProvider

Interface for transparency proof services:

```csharp
public interface ITransparencyProvider
{
    string ProviderName { get; }
    
    Task<CoseSign1Message> AddTransparencyProofAsync(
        CoseSign1Message message,
        CancellationToken cancellationToken = default);
}
```

## Key Types

### SigningContext

Encapsulates signing operation context:

```csharp
public class SigningContext
{
    public ReadOnlyMemory<byte> Payload { get; }
    public string? ContentType { get; }
    public CoseHeaderMap? AdditionalProtectedHeaders { get; }
    public CoseHeaderMap? AdditionalUnprotectedHeaders { get; }
}
```

### SigningOptions

Base class for signing options:

```csharp
public class SigningOptions
{
    public CoseHeaderMap? AdditionalProtectedHeaders { get; set; }
    public CoseHeaderMap? AdditionalUnprotectedHeaders { get; set; }
    public bool EnableTransparency { get; set; } = true;
}
```

### SigningKeyMetadata

Metadata about a signing key:

```csharp
public class SigningKeyMetadata
{
    public CoseAlgorithm Algorithm { get; set; }
    public SigningKeyType KeyType { get; set; }
    public int KeySizeInBits { get; set; }
}
```

### HeaderMergeStrategy

How to handle header conflicts:

```csharp
public enum HeaderMergeStrategy
{
    Fail,         // Throw if header exists
    KeepExisting, // Keep existing value
    Replace,      // Replace with new value
    Custom        // Let contributor decide
}
```

## Quick Start

### Implementing a Custom Signing Service

```csharp
public class MyHsmSigningService : ISigningService<SigningOptions>
{
    private readonly HsmClient _client;
    private readonly string _keyId;
    
    public MyHsmSigningService(HsmClient client, string keyId)
    {
        _client = client;
        _keyId = keyId;
    }
    
    public CoseSigner GetCoseSigner(SigningContext context)
    {
        // Get key from HSM
        var signingKey = new HsmSigningKey(_client, _keyId, this);
        var coseKey = signingKey.GetCoseKey();
        
        // Build headers
        var headers = new CoseHeaderMap();
        headers.SetValue(CoseHeaderLabel.ContentType, context.ContentType);
        
        return new CoseSigner(coseKey, headers);
    }
    
    public SigningOptions CreateSigningOptions() => new SigningOptions();
    public bool IsRemote => true;
    public SigningServiceMetadata ServiceMetadata => new() { Name = "HSM Signing" };
    
    public void Dispose() => _client?.Dispose();
}
```

### Implementing a Custom Header Contributor

```csharp
public class TimestampHeaderContributor : IHeaderContributor
{
    public HeaderMergeStrategy MergeStrategy => HeaderMergeStrategy.KeepExisting;
    
    public void ContributeProtectedHeaders(
        CoseHeaderMap headers, 
        HeaderContributorContext context)
    {
        // Add timestamp to protected headers
        var label = new CoseHeaderLabel("timestamp");
        headers.SetValue(label, DateTimeOffset.UtcNow.ToUnixTimeSeconds());
    }
    
    public void ContributeUnprotectedHeaders(
        CoseHeaderMap headers, 
        HeaderContributorContext context)
    {
        // No unprotected headers needed
    }
}
```

### Using with Dependency Injection

```csharp
// Register services
services.AddSingleton<ISigningService<CertificateSigningOptions>, 
    LocalCertificateSigningService>(sp =>
{
    var cert = sp.GetRequiredService<X509Certificate2>();
    return new LocalCertificateSigningService(cert);
});

// Inject and use
public class DocumentSigner
{
    private readonly ISigningService<CertificateSigningOptions> _signingService;
    
    public DocumentSigner(ISigningService<CertificateSigningOptions> signingService)
    {
        _signingService = signingService;
    }
    
    public byte[] Sign(byte[] document)
    {
        var factory = new DirectSignatureFactory(_signingService);
        return factory.CreateCoseSign1MessageBytes(document, "application/pdf");
    }
}
```

## Testing Support

All interfaces are designed for easy mocking:

```csharp
[Fact]
public async Task Sign_WithMockedService_ReturnsSignature()
{
    // Arrange
    var mockSigner = new Mock<CoseSigner>();
    var mockService = new Mock<ISigningService<SigningOptions>>();
    mockService.Setup(s => s.GetCoseSigner(It.IsAny<SigningContext>()))
        .Returns(mockSigner.Object);
    
    var factory = new DirectSignatureFactory(mockService.Object);
    
    // Act
    var result = factory.CreateCoseSign1MessageBytes(
        new byte[] { 1, 2, 3 }, 
        "application/octet-stream");
    
    // Assert
    Assert.NotNull(result);
}
```

## See Also

- [CoseSign1](../CoseSign1/README.md) - Factory implementations
- [CoseSign1.Certificates](../CoseSign1.Certificates/README.md) - Certificate-based signing
- [CoseSign1.Validation](../CoseSign1.Validation/README.md) - Validation framework
- [Architecture Overview](../docs/architecture/overview.md) - System architecture
