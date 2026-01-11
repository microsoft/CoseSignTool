# CoseSign1.Factories

Core COSE Sign1 message factories for creating direct and indirect signatures.

## Installation

```bash
dotnet add package CoseSign1.Factories --version 2.0.0-preview
```

## Overview

This package provides concrete implementations for creating COSE Sign1 messages. It includes factories for both direct signatures (payload embedded or detached) and indirect signatures (hash-based).

## Key Features

- ✅ **CoseSign1MessageFactory** - Preferred router (selects direct vs indirect by option type)
- ✅ **DirectSignatureFactory** - Create signatures with embedded or detached payloads
- ✅ **IndirectSignatureFactory** - Create hash-based signatures for large payloads
- ✅ **Header Contributors** - Built-in content type and hash envelope headers
- ✅ **Transparency Ready** - Optional integration with transparency services
- ✅ **Stream Support** - Efficient handling of large payloads
- ✅ **Thread-Safe** - Safe for concurrent use

## Quick Start

### Preferred: CoseSign1MessageFactory (Router)

```csharp
using CoseSign1.Certificates;
using CoseSign1.Certificates.ChainBuilders;
using CoseSign1.Factories;
using CoseSign1.Factories.Direct;
using CoseSign1.Factories.Indirect;
using System.Security.Cryptography;

// Create signing service with certificate
using var cert = new X509Certificate2("cert.pfx", "password");
using var chainBuilder = new X509ChainBuilder();
using var service = CertificateSigningService.Create(cert, chainBuilder);

using var factory = new CoseSign1MessageFactory(service);

// Sign payload
byte[] payload = Encoding.UTF8.GetBytes("Document content");
byte[] direct = factory.CreateDirectCoseSign1MessageBytes(
    payload,
    contentType: "text/plain");

byte[] indirect = factory.CreateIndirectCoseSign1MessageBytes(
    payload,
    contentType: "application/octet-stream");

// Save the signature
File.WriteAllBytes("document.direct.cose", direct);
File.WriteAllBytes("document.indirect.cose", indirect);
```

### DirectSignatureFactory (advanced)

```csharp
using CoseSign1.Factories.Direct;

// Assumes 'service' and 'payload' are defined as above.
using var factory = new DirectSignatureFactory(service);
var options = new DirectSignatureOptions { EmbedPayload = false };

byte[] signedMessage = factory.CreateCoseSign1MessageBytes(
    payload, 
    contentType: "application/octet-stream",
    options: options);

// Store payload and signature separately
File.WriteAllBytes("document.bin", payload);
File.WriteAllBytes("document.cose", signedMessage);
```

### IndirectSignatureFactory (advanced)

For large payloads, use indirect signatures which sign a hash of the content:

```csharp
using CoseSign1.Factories.Indirect;

// Create indirect signature factory
// Assumes 'service' is defined as above.
using var factory = new IndirectSignatureFactory(service);

// Sign large file (only hash is embedded in message)
byte[] largePayload = File.ReadAllBytes("large-file.bin");
byte[] signedMessage = factory.CreateCoseSign1MessageBytes(
    largePayload,
    contentType: "application/octet-stream");
```

### Specify Hash Algorithm

```csharp
var options = new IndirectSignatureOptions
{
    HashAlgorithm = HashAlgorithmName.SHA384
};

byte[] signedMessage = factory.CreateCoseSign1MessageBytes(
    payload,
    contentType: "application/json",
    options: options);
```

### Async Operations

```csharp
// Async signing for remote signing services
byte[] signedMessage = await factory.CreateDirectCoseSign1MessageBytesAsync(
    payload,
    contentType: "application/json",
    cancellationToken: cancellationToken);

// Stream-based signing for memory efficiency
using var stream = File.OpenRead("large-file.bin");
byte[] signedMessage = await factory.CreateDirectCoseSign1MessageBytesAsync(
    stream,
    contentType: "application/octet-stream");
```

## Core Types

### DirectSignatureFactory

Creates standard COSE Sign1 messages with payload embedded or detached:

```csharp
public class DirectSignatureFactory : ICoseSign1MessageFactory<DirectSignatureOptions>
{
    // Constructor with signing service
    public DirectSignatureFactory(
        ISigningService<SigningOptions> signingService,
        IReadOnlyList<ITransparencyProvider>? transparencyProviders = null,
        ILogger<DirectSignatureFactory>? logger = null);
    
    // Create signed message
    byte[] CreateCoseSign1MessageBytes(
        byte[] payload,
        string contentType,
        DirectSignatureOptions? options = default);
}
```

### IndirectSignatureFactory

Creates hash-based signatures (COSE Hash Envelope):

```csharp
public class IndirectSignatureFactory : ICoseSign1MessageFactory<IndirectSignatureOptions>
{
    // Constructor with signing service
    public IndirectSignatureFactory(
        ISigningService<SigningOptions> signingService,
        IReadOnlyList<ITransparencyProvider>? transparencyProviders = null,
        ILogger<IndirectSignatureFactory>? logger = null);
    
    // Create signed message with hash
    byte[] CreateCoseSign1MessageBytes(
        byte[] payload,
        string contentType,
        IndirectSignatureOptions? options = default);
}
```

### DirectSignatureOptions

Options for direct signatures:

```csharp
public class DirectSignatureOptions : SigningOptions
{
    // Whether to embed payload in message (default: true)
    public bool EmbedPayload { get; set; } = true;
}
```

### IndirectSignatureOptions

Options for indirect signatures:

```csharp
public class IndirectSignatureOptions : SigningOptions
{
    // Hash algorithm (default: SHA256)
    public HashAlgorithmName HashAlgorithm { get; set; } = HashAlgorithmName.SHA256;
}
```

## Header Contributors

### ContentTypeHeaderContributor

Automatically adds content type to protected headers:

```csharp
// Automatically added by factories
// Results in header: 3 (content type) -> "application/json"
```

### CoseHashEnvelopeHeaderContributor

Adds hash envelope headers for indirect signatures:

```csharp
// Automatically added by IndirectSignatureFactory
// Results in headers:
//   - Hash algorithm indicator
//   - Payload hash
//   - Payload location
```

## Advanced Usage

### With Custom Header Contributors

```csharp
using CoseSign1.Headers;

// Add custom headers via contributors
using var factory = new DirectSignatureFactory(service);

var options = new DirectSignatureOptions
{
    AdditionalHeaderContributors = new IHeaderContributor[]
    {
        new CwtClaimsHeaderContributor(new CwtClaims
        {
            Issuer = "https://example.com",
            Subject = "document-123",
        }),
    },
};

var message = factory.CreateCoseSign1MessageBytes(payload, "application/json", options);
```

### With Transparency Providers

```csharp
using CoseSign1.Transparent.MST;

// Add transparency receipts
var mstProvider = new MstTransparencyProvider(mstClient);
var factory = new DirectSignatureFactory(
    service,
    transparencyProviders: new[] { mstProvider });

// Message will include MST receipt
var message = factory.CreateCoseSign1MessageBytes(payload, "application/json");
```

### Batch Signing

```csharp
// Factory is thread-safe and reusable
using var factory = new DirectSignatureFactory(service);

var signedDocuments = documents.AsParallel()
    .Select(doc => factory.CreateCoseSign1MessageBytes(
        doc.Content, 
        doc.ContentType))
    .ToList();
```

## Reading Signed Messages

```csharp
using System.Security.Cryptography.Cose;

// Decode signed message
byte[] signedBytes = File.ReadAllBytes("document.cose");
CoseSign1Message message = CoseMessage.DecodeSign1(signedBytes);

// Access payload (if embedded)
if (message.Content.HasValue)
{
    byte[] payload = message.Content.Value.ToArray();
    Console.WriteLine(Encoding.UTF8.GetString(payload));
}

// Access headers
var contentType = message.ProtectedHeaders.GetValueOrDefault(
    CoseHeaderLabel.ContentType);
```

## Performance Considerations

1. **Factory Reuse**: Create factory once, reuse for multiple signatures
2. **Stream API**: Use stream overloads for large files
3. **Detached Mode**: For large payloads, consider detached signatures
4. **Indirect Signatures**: For very large files, use hash-based signatures

## See Also

- [CoseSign1.Abstractions](../CoseSign1.Abstractions/README.md) - Core interfaces
- [CoseSign1.Certificates](../CoseSign1.Certificates/README.md) - Certificate-based signing
- [CoseSign1.Headers](../CoseSign1.Headers/README.md) - CWT claims and headers
- [CoseSign1.Validation](../CoseSign1.Validation/README.md) - Signature validation
