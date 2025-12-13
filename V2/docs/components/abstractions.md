# CoseSign1.Abstractions Package

**NuGet**: `CoseSign1.Abstractions`  
**Purpose**: Core interfaces and abstractions for the V2 architecture  
**Dependencies**: System.Security.Cryptography.Cose

## Overview

This package defines the foundational interfaces and contracts used throughout the V2 ecosystem. It establishes the abstraction layer that enables dependency injection, testability, and extensibility.

## When to Use

- **Direct dependency**: Required by all other CoseSign1 packages (transitive dependency)
- **Custom implementations**: When creating custom signing services, validators, or header contributors
- **Testing**: When mocking interfaces for unit tests
- **Extensibility**: When building plugins or extensions

## Key Interfaces

### ISigningService

The core abstraction for cryptographic signing operations.

```csharp
public interface ISigningService : IDisposable
{
    /// <summary>
    /// Signs the provided data and returns the signature bytes.
    /// </summary>
    Task<byte[]> SignAsync(byte[] data, CancellationToken cancellationToken = default);
    
    /// <summary>
    /// Gets the COSE algorithm used by this signing service.
    /// </summary>
    CoseAlgorithm Algorithm { get; }
    
    /// <summary>
    /// Gets metadata about the signing service.
    /// </summary>
    SigningServiceMetadata? Metadata { get; }
}
```

**Usage Example**:
```csharp
// Using built-in certificate-based signing service
using var cert = new X509Certificate2("cert.pfx", "password");
using var service = new LocalCertificateSigningService(cert);

byte[] signature = await service.SignAsync(dataToSign);
Console.WriteLine($"Algorithm: {service.Algorithm}");
```

**Custom Implementation**:
```csharp
public class HsmSigningService : ISigningService
{
    private readonly HsmClient _client;
    private readonly string _keyId;
    
    public HsmSigningService(HsmClient client, string keyId)
    {
        _client = client;
        _keyId = keyId;
    }
    
    public async Task<byte[]> SignAsync(byte[] data, CancellationToken ct)
    {
        return await _client.SignAsync(_keyId, data, ct);
    }
    
    public CoseAlgorithm Algorithm => CoseAlgorithm.ES256;
    public SigningServiceMetadata? Metadata => new() 
    { 
        IsRemote = true,
        RequiresNetwork = true 
    };
    
    public void Dispose() => _client?.Dispose();
}
```

### ICoseSign1MessageFactory

Factory abstraction for creating COSE Sign1 messages.

```csharp
public interface ICoseSign1MessageFactory
{
    /// <summary>
    /// Creates a COSE Sign1 message from the provided payload.
    /// </summary>
    Task<CoseSign1Message> CreateAsync(
        byte[] payload, 
        CancellationToken cancellationToken = default);
    
    /// <summary>
    /// Creates a COSE Sign1 message with embedded payload support options.
    /// </summary>
    Task<CoseSign1Message> CreateAsync(
        byte[] payload,
        EmbeddedPayloadSupport embeddedPayloadSupport,
        CancellationToken cancellationToken = default);
}
```

**Usage Example**:
```csharp
// Direct signature (payload embedded)
var directFactory = new DirectSignatureFactory(signingService);
var message = await directFactory.CreateAsync(payload);

// Indirect signature (payload hashed)
var indirectFactory = new IndirectSignatureFactory(signingService);
var hashMessage = await indirectFactory.CreateAsync(payload);
```

**Custom Factory**:
```csharp
public class TimestampedSignatureFactory : ICoseSign1MessageFactory
{
    private readonly ISigningService _service;
    private readonly ITimestampService _timestampService;
    
    public async Task<CoseSign1Message> CreateAsync(
        byte[] payload, 
        CancellationToken ct)
    {
        // Create base signature
        var factory = new DirectSignatureFactory(_service);
        var message = await factory.CreateAsync(payload, ct);
        
        // Add timestamp
        var timestamp = await _timestampService.GetTimestampAsync(ct);
        message.ProtectedHeaders.SetValue(
            new CoseHeaderLabel("timestamp"), 
            new CoseHeaderValue(timestamp));
        
        return message;
    }
}
```

### IHeaderContributor

Extensibility point for adding headers to COSE messages.

```csharp
public interface IHeaderContributor
{
    /// <summary>
    /// Contributes headers to the COSE message.
    /// </summary>
    Task ContributeAsync(
        CoseHeaderMap protectedHeaders,
        CoseHeaderMap unprotectedHeaders,
        byte[] payload,
        SigningContext context,
        CancellationToken cancellationToken = default);
}
```

**Built-in Contributors**:
- `CwtClaimsHeaderContributor`: Adds CWT claims for SCITT compliance
- `CertificateHeaderContributor`: Adds certificate chain

**Custom Implementation**:
```csharp
public class BuildInfoHeaderContributor : IHeaderContributor
{
    public Task ContributeAsync(
        CoseHeaderMap protectedHeaders,
        CoseHeaderMap unprotectedHeaders,
        byte[] payload,
        SigningContext context,
        CancellationToken ct)
    {
        protectedHeaders.SetValue(
            new CoseHeaderLabel("build-version"),
            new CoseHeaderValue(GetBuildVersion()));
        
        protectedHeaders.SetValue(
            new CoseHeaderLabel("build-timestamp"),
            new CoseHeaderValue(DateTimeOffset.UtcNow.ToUnixTimeSeconds()));
        
        return Task.CompletedTask;
    }
    
    private string GetBuildVersion() => 
        Assembly.GetExecutingAssembly().GetName().Version?.ToString() ?? "unknown";
}

// Usage
var factory = new DirectSignatureFactory(
    signingService,
    headerContributors: new[] { new BuildInfoHeaderContributor() });
```

### ISigningKey

Abstraction for cryptographic keys used in signing.

```csharp
public interface ISigningKey : IDisposable
{
    /// <summary>
    /// Gets the algorithm supported by this key.
    /// </summary>
    CoseAlgorithm Algorithm { get; }
    
    /// <summary>
    /// Gets metadata about the signing key.
    /// </summary>
    SigningKeyMetadata? Metadata { get; }
    
    /// <summary>
    /// Signs the data using this key.
    /// </summary>
    byte[] Sign(byte[] data);
}
```

**Usage Example**:
```csharp
// Certificate-based key
using var cert = new X509Certificate2("cert.pfx", "password");
using var key = new CertificateSigningKey(cert);

byte[] signature = key.Sign(data);
```

## Supporting Types

### SigningContext

Provides contextual information during signing operations.

```csharp
public class SigningContext
{
    /// <summary>
    /// Gets or sets the content type of the payload.
    /// </summary>
    public string? ContentType { get; set; }
    
    /// <summary>
    /// Gets or sets additional metadata for the signing operation.
    /// </summary>
    public IDictionary<string, object> Metadata { get; } = new Dictionary<string, object>();
    
    /// <summary>
    /// Gets or sets the timestamp for the signature.
    /// </summary>
    public DateTimeOffset? Timestamp { get; set; }
}
```

### SigningOptions

Configuration options for signing operations.

```csharp
public class SigningOptions
{
    /// <summary>
    /// Gets or sets whether to include the certificate chain.
    /// </summary>
    public bool IncludeCertificateChain { get; set; } = true;
    
    /// <summary>
    /// Gets or sets the embedded payload support mode.
    /// </summary>
    public EmbeddedPayloadSupport EmbeddedPayloadSupport { get; set; } 
        = EmbeddedPayloadSupport.Embedded;
    
    /// <summary>
    /// Gets or sets additional header contributors.
    /// </summary>
    public IList<IHeaderContributor> HeaderContributors { get; set; } 
        = new List<IHeaderContributor>();
}
```

### SigningServiceMetadata

Metadata about a signing service implementation.

```csharp
public class SigningServiceMetadata
{
    /// <summary>
    /// Indicates if the service communicates with a remote system.
    /// </summary>
    public bool IsRemote { get; init; }
    
    /// <summary>
    /// Indicates if network connectivity is required.
    /// </summary>
    public bool RequiresNetwork { get; init; }
    
    /// <summary>
    /// The name or identifier of the service provider.
    /// </summary>
    public string? ProviderName { get; init; }
    
    /// <summary>
    /// Additional metadata properties.
    /// </summary>
    public IDictionary<string, object> AdditionalMetadata { get; init; } 
        = new Dictionary<string, object>();
}
```

### SigningKeyMetadata

Metadata about a cryptographic key.

```csharp
public class SigningKeyMetadata
{
    /// <summary>
    /// The identifier or name of the key.
    /// </summary>
    public string? KeyId { get; init; }
    
    /// <summary>
    /// Indicates if the key is stored in hardware.
    /// </summary>
    public bool IsHardwareBacked { get; init; }
    
    /// <summary>
    /// The location or source of the key.
    /// </summary>
    public string? KeySource { get; init; }
}
```

## Transparency Abstractions

The `Transparency/` folder contains interfaces for transparency service integration:

### ITransparencyService

```csharp
public interface ITransparencyService
{
    /// <summary>
    /// Submits a COSE Sign1 message to the transparency service.
    /// </summary>
    Task<TransparencyReceipt> SubmitAsync(
        CoseSign1Message message, 
        CancellationToken cancellationToken = default);
    
    /// <summary>
    /// Verifies a transparency receipt.
    /// </summary>
    Task<bool> VerifyReceiptAsync(
        TransparencyReceipt receipt, 
        CancellationToken cancellationToken = default);
}
```

## Extension Points

### Custom Signing Service

Create custom signing services for specific key storage systems:

```csharp
public class AzureKeyVaultSigningService : ISigningService
{
    private readonly CryptographyClient _client;
    
    public AzureKeyVaultSigningService(string keyVaultUrl, string keyName)
    {
        var credential = new DefaultAzureCredential();
        _client = new CryptographyClient(
            new Uri($"{keyVaultUrl}/keys/{keyName}"), 
            credential);
    }
    
    public async Task<byte[]> SignAsync(byte[] data, CancellationToken ct)
    {
        var signResult = await _client.SignDataAsync(
            SignatureAlgorithm.ES256, 
            data, 
            ct);
        return signResult.Signature;
    }
    
    public CoseAlgorithm Algorithm => CoseAlgorithm.ES256;
    public SigningServiceMetadata? Metadata => new() 
    { 
        IsRemote = true,
        RequiresNetwork = true,
        ProviderName = "Azure Key Vault"
    };
    
    public void Dispose() { /* No resources to dispose */ }
}
```

### Custom Header Contributor

Add application-specific headers:

```csharp
public class ScittFeedHeaderContributor : IHeaderContributor
{
    private readonly string _feedId;
    
    public ScittFeedHeaderContributor(string feedId)
    {
        _feedId = feedId;
    }
    
    public Task ContributeAsync(
        CoseHeaderMap protectedHeaders,
        CoseHeaderMap unprotectedHeaders,
        byte[] payload,
        SigningContext context,
        CancellationToken ct)
    {
        // Add SCITT feed identifier
        protectedHeaders.SetValue(
            new CoseHeaderLabel("feed"),
            new CoseHeaderValue(_feedId));
        
        // Add content type if specified in context
        if (context.ContentType is not null)
        {
            protectedHeaders.SetValue(
                CoseHeaderLabel.ContentType,
                new CoseHeaderValue(context.ContentType));
        }
        
        return Task.CompletedTask;
    }
}
```

## Dependency Injection Patterns

### Registering Services

```csharp
// Register signing service
services.AddSingleton<ISigningService>(sp =>
{
    var certSource = sp.GetRequiredService<ICertificateSource>();
    var cert = certSource.GetCertificate();
    return new LocalCertificateSigningService(cert);
});

// Register factory
services.AddTransient<ICoseSign1MessageFactory>(sp =>
{
    var signingService = sp.GetRequiredService<ISigningService>();
    var headerContributors = sp.GetServices<IHeaderContributor>();
    return new DirectSignatureFactory(signingService, headerContributors);
});

// Register header contributors
services.AddSingleton<IHeaderContributor, CwtClaimsHeaderContributor>();
services.AddSingleton<IHeaderContributor, BuildInfoHeaderContributor>();
```

### Using in Application

```csharp
public class DocumentSigningService
{
    private readonly ICoseSign1MessageFactory _factory;
    
    public DocumentSigningService(ICoseSign1MessageFactory factory)
    {
        _factory = factory;
    }
    
    public async Task<CoseSign1Message> SignDocumentAsync(byte[] document)
    {
        return await _factory.CreateAsync(document);
    }
}
```

## Testing Support

### Mocking Interfaces

```csharp
[Test]
public async Task SignAsync_WithMockedService_ReturnsValidSignature()
{
    // Arrange
    var mockService = new Mock<ISigningService>();
    mockService.Setup(s => s.SignAsync(It.IsAny<byte[]>(), It.IsAny<CancellationToken>()))
        .ReturnsAsync(new byte[64]); // Mock signature
    mockService.Setup(s => s.Algorithm).Returns(CoseAlgorithm.ES256);
    
    var factory = new DirectSignatureFactory(mockService.Object);
    
    // Act
    var message = await factory.CreateAsync(new byte[] { 1, 2, 3 });
    
    // Assert
    Assert.IsNotNull(message);
    mockService.Verify(s => s.SignAsync(It.IsAny<byte[]>(), It.IsAny<CancellationToken>()), Times.Once);
}
```

### Test Implementations

```csharp
public class TestSigningService : ISigningService
{
    private readonly byte[] _fixedSignature;
    
    public TestSigningService(CoseAlgorithm algorithm = CoseAlgorithm.ES256)
    {
        Algorithm = algorithm;
        _fixedSignature = new byte[64]; // Deterministic signature
    }
    
    public Task<byte[]> SignAsync(byte[] data, CancellationToken ct)
    {
        return Task.FromResult(_fixedSignature);
    }
    
    public CoseAlgorithm Algorithm { get; }
    public SigningServiceMetadata? Metadata => null;
    public void Dispose() { }
}
```

## Best Practices

1. **Dispose Resources**: Always dispose `ISigningService` and `ISigningKey` implementations
   ```csharp
   using var service = new LocalCertificateSigningService(cert);
   ```

2. **Thread Safety**: Implementations should be thread-safe if registered as singletons
   ```csharp
   public class ThreadSafeSigningService : ISigningService
   {
       private readonly SemaphoreSlim _semaphore = new(1, 1);
       
       public async Task<byte[]> SignAsync(byte[] data, CancellationToken ct)
       {
           await _semaphore.WaitAsync(ct);
           try
           {
               // Thread-safe signing operation
           }
           finally
           {
               _semaphore.Release();
           }
       }
   }
   ```

3. **Cancellation Support**: Honor cancellation tokens
   ```csharp
   public async Task<byte[]> SignAsync(byte[] data, CancellationToken ct)
   {
       ct.ThrowIfCancellationRequested();
       // ... signing operation
   }
   ```

4. **Metadata**: Provide meaningful metadata for diagnostics
   ```csharp
   public SigningServiceMetadata? Metadata => new()
   {
       IsRemote = true,
       ProviderName = "MyService",
       AdditionalMetadata = new Dictionary<string, object>
       {
           ["Version"] = "1.0",
           ["Endpoint"] = _endpoint
       }
   };
   ```

## See Also

- [Core Concepts](../architecture/core-concepts.md)
- [CoseSign1 Package](cosesign1.md)
- [Certificates Package](certificates.md)
- [Custom Validators Guide](../guides/custom-validators.md)
