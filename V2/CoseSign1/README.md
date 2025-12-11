# CoseSign1

Core COSE Sign1 message factories for creating direct and indirect signatures.

## Overview

This package provides concrete implementations for creating COSE Sign1 messages with embedded or detached payloads, including support for indirect signatures (hash-based).

## Installation

```bash
dotnet add package CoseSign1 --version 2.0.0-preview
```

## Key Features

- ✅ **DirectSignatureFactory** - Create signatures with embedded payloads
- ✅ **IndirectSignatureFactory** - Create hash-based signatures
- ✅ **Detached Signatures** - Support for detached payload mode
- ✅ **Header Contributors** - Extensible header management
- ✅ **SCITT Compatible** - Works with SCITT transparency services

## Quick Start

### Direct Signature (Embedded Payload)

```csharp
using CoseSign1;
using CoseSign1.Certificates.Local;

// Sign with embedded payload
using var cert = new X509Certificate2("cert.pfx", "password");
using var service = new LocalCertificateSigningService(cert);
var factory = new DirectSignatureFactory(service);

byte[] payload = Encoding.UTF8.GetBytes("Document content");
CoseSign1Message message = await factory.CreateAsync(payload);

// Save the signature
byte[] encodedMessage = message.Encode();
File.WriteAllBytes("document.cose", encodedMessage);
```

### Indirect Signature (Hash-Based)

```csharp
using CoseSign1.Indirect;

// Sign large files with hash instead of embedding
var factory = new IndirectSignatureFactory(service);

byte[] largePayload = File.ReadAllBytes("large-file.bin");
CoseSign1Message hashMessage = await factory.CreateAsync(largePayload);

// Message contains hash of payload, not the payload itself
byte[] encodedMessage = hashMessage.Encode();
```

### Detached Signature

```csharp
// Create detached signature (payload stored separately)
var factory = new DirectSignatureFactory(
    service,
    embeddedPayloadSupport: EmbeddedPayloadSupport.Detached);

var message = await factory.CreateAsync(payload);

// Store payload and signature separately
File.WriteAllBytes("document.bin", payload);
File.WriteAllBytes("document.cose", message.Encode());
```

## Advanced Usage

### With Header Contributors

```csharp
using CoseSign1.Headers;

var contributors = new IHeaderContributor[]
{
    new CwtClaimsHeaderContributor(new CwtClaims 
    {
        Issuer = "https://contoso.com",
        Subject = "package:npm/my-package@1.0.0"
    }),
    new CertificateHeaderContributor()
};

var factory = new DirectSignatureFactory(service, contributors);
var message = await factory.CreateAsync(payload);
```

### Batch Signing

```csharp
var factory = new DirectSignatureFactory(service);

var signatures = new List<CoseSign1Message>();
foreach (var document in documents)
{
    var message = await factory.CreateAsync(document);
    signatures.Add(message);
}
```

## Factory Types

### DirectSignatureFactory

Creates COSE Sign1 messages with the payload embedded in the message.

**Best for:**
- Small to medium-sized payloads
- Self-contained signatures
- Scenarios where payload and signature travel together

### IndirectSignatureFactory

Creates COSE Sign1 messages where the payload is represented by its hash.

**Best for:**
- Large files (reduces message size)
- Privacy requirements (payload not disclosed)
- Transparency logs (hash-based submissions)
- Bandwidth-constrained scenarios

## Embedded Payload Modes

```csharp
public enum EmbeddedPayloadSupport
{
    Embedded,              // Payload included in message (default)
    Detached,              // Payload separate, no hint
    DetachedButEmbeddedHint // Payload separate, hint in headers
}
```

## Verification

```csharp
// Decode and verify signature
var message = CoseSign1Message.Decode(encodedMessage);

// For full validation, use CoseSign1.Validation package
var validator = new ValidatorBuilder()
    .WithSignatureValidator()
    .Build();

var result = validator.Validate(message);
```

## When to Use

- ✅ Creating COSE Sign1 signatures
- ✅ Signing documents, artifacts, or data
- ✅ Building SCITT-compliant systems
- ✅ Implementing software supply chain security
- ✅ Creating detached or embedded signatures

## Related Packages

- **CoseSign1.Abstractions** - Core interfaces
- **CoseSign1.Certificates** - Certificate-based signing
- **CoseSign1.Validation** - Message validation
- **CoseSign1.Headers** - CWT claims support

## Documentation

- 📖 [Full Package Documentation](https://github.com/microsoft/CoseSignTool/blob/main/V2/docs/packages/cosesign1.md)
- 📖 [Quick Start Guide](https://github.com/microsoft/CoseSignTool/blob/main/V2/docs/getting-started/quick-start.md)
- 📖 [Examples](https://github.com/microsoft/CoseSignTool/blob/main/V2/docs/examples/README.md)

## Support

- 🐛 [Report Issues](https://github.com/microsoft/CoseSignTool/issues)
- 💬 [Discussions](https://github.com/microsoft/CoseSignTool/discussions)
- 📧 Email: cosesigntool@microsoft.com

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
