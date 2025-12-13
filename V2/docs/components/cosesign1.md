# CoseSign1 Package

**NuGet**: `CoseSign1`  
**Purpose**: Core signature factories and validation for COSE Sign1 messages  
**Dependencies**: CoseSign1.Abstractions

## Overview

This package provides the concrete implementations of signature factories for creating COSE Sign1 messages. It includes support for both direct signatures (embedded payload) and indirect signatures (payload referenced by hash).

## When to Use

- Creating COSE Sign1 signatures with embedded payloads
- Creating indirect signatures with payload hashes
- Building detached signatures
- Implementing SCITT-compliant signatures
- Any scenario requiring COSE Sign1 message creation

## Core Components

### DirectSignatureFactory

Creates COSE Sign1 messages with the payload embedded in the message.

```csharp
public class DirectSignatureFactory : ICoseSign1MessageFactory
{
    public DirectSignatureFactory(
        ISigningService signingService,
        IEnumerable<IHeaderContributor>? headerContributors = null,
        EmbeddedPayloadSupport embeddedPayloadSupport = EmbeddedPayloadSupport.Embedded);
}
```

**Basic Usage**:
```csharp
using var cert = new X509Certificate2("cert.pfx", "password");
using var service = new LocalCertificateSigningService(cert);
var factory = new DirectSignatureFactory(service);

byte[] payload = Encoding.UTF8.GetBytes("Document content");
CoseSign1Message message = await factory.CreateAsync(payload);

// Message contains the payload
byte[] encodedMessage = message.Encode();
File.WriteAllBytes("document.cose", encodedMessage);
```

**With Header Contributors**:
```csharp
var factory = new DirectSignatureFactory(
    service,
    headerContributors: new IHeaderContributor[]
    {
        new CwtClaimsHeaderContributor(),
        new CertificateHeaderContributor()
    });

var message = await factory.CreateAsync(payload);
```

**Detached Payload**:
```csharp
var factory = new DirectSignatureFactory(
    service,
    embeddedPayloadSupport: EmbeddedPayloadSupport.Detached);

var message = await factory.CreateAsync(payload);

// Message doesn't contain payload
byte[] signature = message.Encode(); // Signature only
// Store payload separately
File.WriteAllBytes("document.bin", payload);
File.WriteAllBytes("document.cose", signature);
```

**Detached with Hint**:
```csharp
// Creates detached signature but includes hint in headers
var factory = new DirectSignatureFactory(
    service,
    embeddedPayloadSupport: EmbeddedPayloadSupport.DetachedButEmbeddedHint);

var message = await factory.CreateAsync(payload);
// Payload not embedded, but hint available for validation
```

### IndirectSignatureFactory

Creates COSE Sign1 messages where the payload is represented by its hash.

```csharp
public class IndirectSignatureFactory : ICoseSign1MessageFactory
{
    public IndirectSignatureFactory(
        ISigningService signingService,
        IEnumerable<IHeaderContributor>? headerContributors = null,
        HashAlgorithmName hashAlgorithm = default);
}
```

**Basic Usage**:
```csharp
using var service = new LocalCertificateSigningService(cert);
var factory = new IndirectSignatureFactory(service);

byte[] payload = File.ReadAllBytes("large-file.bin");
CoseSign1Message hashMessage = await factory.CreateAsync(payload);

// Message contains hash of payload, not payload itself
byte[] encodedMessage = hashMessage.Encode();
```

**Custom Hash Algorithm**:
```csharp
var factory = new IndirectSignatureFactory(
    service,
    hashAlgorithm: HashAlgorithmName.SHA512);

var message = await factory.CreateAsync(payload);
```

**Use Cases**:
- Large files (payload hash reduces message size)
- Privacy requirements (payload not disclosed)
- SCITT transparency logs (hash-based submissions)
- Bandwidth-constrained scenarios

### Embedded Payload Support

The `EmbeddedPayloadSupport` enum controls payload embedding:

```csharp
public enum EmbeddedPayloadSupport
{
    /// <summary>
    /// Payload is embedded in the COSE message.
    /// </summary>
    Embedded,
    
    /// <summary>
    /// Payload is not embedded (detached signature).
    /// </summary>
    Detached,
    
    /// <summary>
    /// Payload is detached but a hint is included in headers.
    /// </summary>
    DetachedButEmbeddedHint
}
```

## Advanced Scenarios

### Creating Signatures with Multiple Header Contributors

```csharp
public class DocumentSigningService
{
    private readonly ISigningService _signingService;
    
    public async Task<CoseSign1Message> SignDocumentAsync(
        byte[] document,
        string issuer,
        string subject)
    {
        var contributors = new List<IHeaderContributor>
        {
            new CwtClaimsHeaderContributor
            {
                Issuer = issuer,
                Subject = subject,
                IssuedAt = DateTimeOffset.UtcNow
            },
            new CertificateHeaderContributor(),
            new ContentTypeHeaderContributor("application/pdf")
        };
        
        var factory = new DirectSignatureFactory(_signingService, contributors);
        return await factory.CreateAsync(document);
    }
}
```

### Batch Signing

```csharp
public async Task<List<CoseSign1Message>> SignBatchAsync(
    IEnumerable<byte[]> documents)
{
    using var service = new LocalCertificateSigningService(cert);
    var factory = new DirectSignatureFactory(service);
    
    var signatures = new List<CoseSign1Message>();
    
    foreach (var doc in documents)
    {
        var message = await factory.CreateAsync(doc);
        signatures.Add(message);
    }
    
    return signatures;
}
```

### Parallel Signing (with thread-safe service)

```csharp
public async Task<CoseSign1Message[]> SignParallelAsync(byte[][] documents)
{
    using var service = new ThreadSafeSigningService(cert);
    var factory = new DirectSignatureFactory(service);
    
    var tasks = documents.Select(doc => factory.CreateAsync(doc));
    return await Task.WhenAll(tasks);
}
```

### Conditional Header Contribution

```csharp
public class ConditionalHeaderContributor : IHeaderContributor
{
    private readonly bool _includeTimestamp;
    private readonly bool _includeCertChain;
    
    public async Task ContributeAsync(
        CoseHeaderMap protectedHeaders,
        CoseHeaderMap unprotectedHeaders,
        byte[] payload,
        SigningContext context,
        CancellationToken ct)
    {
        if (_includeTimestamp)
        {
            protectedHeaders.SetValue(
                new CoseHeaderLabel("timestamp"),
                new CoseHeaderValue(DateTimeOffset.UtcNow.ToUnixTimeSeconds()));
        }
        
        if (_includeCertChain && context.Metadata.ContainsKey("Certificate"))
        {
            var cert = (X509Certificate2)context.Metadata["Certificate"];
            // Add certificate chain...
        }
    }
}
```

## Extension Methods

The package includes several extension methods for working with COSE messages:

### Payload Access

```csharp
// Get payload from embedded message
byte[]? payload = message.GetPayload();

// Check if payload is embedded
bool hasPayload = message.HasEmbeddedPayload();

// Get detached payload hint
string? hint = message.GetDetachedPayloadHint();
```

### Header Access

```csharp
// Get protected header value
var issuer = message.ProtectedHeaders.GetValueOrDefault<string>(
    new CoseHeaderLabel("iss"));

// Get algorithm
CoseAlgorithm algorithm = message.ProtectedHeaders.Algorithm;

// Get content type
string? contentType = message.ProtectedHeaders.ContentType;
```

### Message Inspection

```csharp
// Get message size
int encodedSize = message.Encode().Length;

// Check for specific headers
bool hasCwtClaims = message.ProtectedHeaders.ContainsKey(
    new CoseHeaderLabel("iss"));

// Extract all header labels
var labels = message.ProtectedHeaders.Keys.ToList();
```

## Validation

While this package focuses on creation, it includes basic validation utilities:

### Signature Verification

```csharp
// Verify signature (requires validation package for full features)
public static class CoseSign1Validator
{
    public static bool VerifySignature(
        CoseSign1Message message,
        X509Certificate2 certificate)
    {
        byte[] dataToVerify = message.GetDataToSign();
        byte[] signature = message.Signature.ToArray();
        
        using var ecdsa = certificate.GetECDsaPublicKey();
        return ecdsa!.VerifyData(dataToVerify, signature, HashAlgorithmName.SHA256);
    }
}
```

**Note**: For comprehensive validation, use the `CoseSign1.Validation` package.

## Integration Patterns

### ASP.NET Core Integration

```csharp
// Startup.cs
services.AddSingleton<ISigningService>(sp =>
{
    var config = sp.GetRequiredService<IConfiguration>();
    var cert = LoadCertificate(config["Signing:Certificate"]);
    return new LocalCertificateSigningService(cert);
});

services.AddScoped<ICoseSign1MessageFactory>(sp =>
{
    var signingService = sp.GetRequiredService<ISigningService>();
    var contributors = sp.GetServices<IHeaderContributor>();
    return new DirectSignatureFactory(signingService, contributors);
});

// Controller
public class SigningController : ControllerBase
{
    private readonly ICoseSign1MessageFactory _factory;
    
    public SigningController(ICoseSign1MessageFactory factory)
    {
        _factory = factory;
    }
    
    [HttpPost("sign")]
    public async Task<IActionResult> Sign([FromBody] byte[] payload)
    {
        var message = await _factory.CreateAsync(payload);
        return File(message.Encode(), "application/cose");
    }
}
```

### Background Service

```csharp
public class SigningBackgroundService : BackgroundService
{
    private readonly ISigningService _signingService;
    private readonly ILogger<SigningBackgroundService> _logger;
    
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        var factory = new DirectSignatureFactory(_signingService);
        
        while (!stoppingToken.IsCancellationRequested)
        {
            var payload = await GetNextPayloadAsync(stoppingToken);
            if (payload != null)
            {
                var message = await factory.CreateAsync(payload, stoppingToken);
                await ProcessSignedMessageAsync(message, stoppingToken);
            }
            
            await Task.Delay(TimeSpan.FromSeconds(10), stoppingToken);
        }
    }
}
```

### Azure Functions

```csharp
public class SigningFunction
{
    private readonly ICoseSign1MessageFactory _factory;
    
    public SigningFunction(ICoseSign1MessageFactory factory)
    {
        _factory = factory;
    }
    
    [FunctionName("SignDocument")]
    public async Task<IActionResult> Run(
        [HttpTrigger(AuthorizationLevel.Function, "post")] HttpRequest req,
        ILogger log)
    {
        using var reader = new StreamReader(req.Body);
        byte[] payload = Encoding.UTF8.GetBytes(await reader.ReadToEndAsync());
        
        var message = await _factory.CreateAsync(payload);
        
        return new FileContentResult(message.Encode(), "application/cose");
    }
}
```

## Performance Considerations

### Memory Management

```csharp
// ❌ Inefficient: Creates multiple copies
var payload = File.ReadAllBytes("large-file.bin");
var message = await factory.CreateAsync(payload);
var encoded = message.Encode();
File.WriteAllBytes("output.cose", encoded);

// ✅ Efficient: Minimize allocations
using var fileStream = File.OpenRead("large-file.bin");
using var memoryStream = new MemoryStream();
await fileStream.CopyToAsync(memoryStream);
byte[] payload = memoryStream.ToArray();

var message = await factory.CreateAsync(payload);
await using var outputStream = File.Create("output.cose");
await outputStream.WriteAsync(message.Encode());
```

### Reusing Factories

```csharp
// ✅ Reuse factory for multiple signatures
using var service = new LocalCertificateSigningService(cert);
var factory = new DirectSignatureFactory(service);

foreach (var file in Directory.GetFiles("documents"))
{
    byte[] payload = await File.ReadAllBytesAsync(file);
    var message = await factory.CreateAsync(payload);
    await File.WriteAllBytesAsync($"{file}.cose", message.Encode());
}
```

### Async Patterns

```csharp
// ✅ Use async/await properly
public async Task<CoseSign1Message> SignAsync(byte[] payload)
{
    return await factory.CreateAsync(payload);
}

// ❌ Don't block on async
public CoseSign1Message SignBlocking(byte[] payload)
{
    return factory.CreateAsync(payload).Result; // Avoid!
}
```

## Error Handling

```csharp
public async Task<CoseSign1Message?> TrySignAsync(byte[] payload)
{
    try
    {
        return await factory.CreateAsync(payload);
    }
    catch (CoseSign1Exception ex)
    {
        _logger.LogError(ex, "Failed to create signature");
        return null;
    }
    catch (CryptographicException ex)
    {
        _logger.LogError(ex, "Cryptographic operation failed");
        throw new SigningException("Signature creation failed", ex);
    }
}
```

## Testing

### Unit Testing

```csharp
[Test]
public async Task CreateAsync_WithValidPayload_ReturnsValidMessage()
{
    // Arrange
    var mockService = new Mock<ISigningService>();
    mockService.Setup(s => s.SignAsync(It.IsAny<byte[]>(), default))
        .ReturnsAsync(new byte[64]);
    mockService.Setup(s => s.Algorithm).Returns(CoseAlgorithm.ES256);
    
    var factory = new DirectSignatureFactory(mockService.Object);
    var payload = new byte[] { 1, 2, 3 };
    
    // Act
    var message = await factory.CreateAsync(payload);
    
    // Assert
    Assert.IsNotNull(message);
    Assert.AreEqual(payload, message.GetPayload());
}
```

### Integration Testing

```csharp
[Test]
public async Task EndToEnd_CreateAndVerify_Success()
{
    // Arrange
    using var cert = TestCertificateProvider.GetTestCertificate();
    using var service = new LocalCertificateSigningService(cert);
    var factory = new DirectSignatureFactory(service);
    var payload = Encoding.UTF8.GetBytes("Test payload");
    
    // Act - Create
    var message = await factory.CreateAsync(payload);
    
    // Assert - Verify
    bool isValid = CoseSign1Validator.VerifySignature(message, cert);
    Assert.IsTrue(isValid);
}
```

## Best Practices

1. **Dispose Services**: Always dispose signing services
2. **Reuse Factories**: Create once, use multiple times
3. **Use Appropriate Payload Type**: Embedded for small, indirect for large
4. **Include Necessary Headers**: Use header contributors for metadata
5. **Handle Errors Gracefully**: Catch and log exceptions appropriately
6. **Test Thoroughly**: Unit test with mocks, integration test end-to-end

## See Also

- [Abstractions Package](abstractions.md)
- [Certificates Package](certificates.md)
- [Validation Package](validation.md)
- [Headers Package](headers.md)
- [Direct vs Indirect Signatures Guide](../guides/direct-vs-indirect.md)
