# CoseSign1.Abstractions

Core interfaces and abstractions for the CoseSignTool V2 architecture.

## Overview

This package provides the foundational interfaces and contracts used throughout the V2 ecosystem. It establishes the abstraction layer that enables dependency injection, testability, and extensibility.

## Installation

```bash
dotnet add package CoseSign1.Abstractions --version 2.0.0-preview
```

## Key Features

- ✅ **ISigningService** - Core signing abstraction for any signing implementation
- ✅ **ICoseSign1MessageFactory** - Factory pattern for message creation
- ✅ **IHeaderContributor** - Extensibility for adding custom headers
- ✅ **ISigningKey** - Key abstraction for cryptographic operations
- ✅ **Transparency Interfaces** - Support for transparency services
- ✅ **Dependency Injection Ready** - Designed for modern DI patterns

## Quick Start

### Basic Signing Service

```csharp
using CoseSign1.Abstractions;
using System.Security.Cryptography.Cose;

// Use built-in certificate signing service (requires CoseSign1.Certificates)
using var cert = new X509Certificate2("cert.pfx", "password");
using var service = new LocalCertificateSigningService(cert);

byte[] signature = await service.SignAsync(dataToSign);
Console.WriteLine($"Algorithm: {service.Algorithm}");
```

### Custom Signing Service

```csharp
public class MySigningService : ISigningService
{
    public async Task<byte[]> SignAsync(byte[] data, CancellationToken ct)
    {
        // Your custom signing logic
        return await MySigningMethod(data);
    }
    
    public CoseAlgorithm Algorithm => CoseAlgorithm.ES256;
    public SigningServiceMetadata? Metadata => new() { IsRemote = true };
    public void Dispose() { /* cleanup */ }
}
```

### Custom Header Contributor

```csharp
public class TimestampHeaderContributor : IHeaderContributor
{
    public Task ContributeAsync(
        CoseHeaderMap protectedHeaders,
        CoseHeaderMap unprotectedHeaders,
        byte[] payload,
        SigningContext context,
        CancellationToken ct)
    {
        protectedHeaders.SetValue(
            new CoseHeaderLabel("timestamp"),
            new CoseHeaderValue(DateTimeOffset.UtcNow.ToUnixTimeSeconds()));
        
        return Task.CompletedTask;
    }
}
```

## Core Interfaces

### ISigningService

```csharp
public interface ISigningService : IDisposable
{
    Task<byte[]> SignAsync(byte[] data, CancellationToken cancellationToken = default);
    CoseAlgorithm Algorithm { get; }
    SigningServiceMetadata? Metadata { get; }
}
```

### ICoseSign1MessageFactory

```csharp
public interface ICoseSign1MessageFactory
{
    Task<CoseSign1Message> CreateAsync(byte[] payload, CancellationToken cancellationToken = default);
    Task<CoseSign1Message> CreateAsync(byte[] payload, EmbeddedPayloadSupport embeddedPayloadSupport, CancellationToken cancellationToken = default);
}
```

### IHeaderContributor

```csharp
public interface IHeaderContributor
{
    Task ContributeAsync(
        CoseHeaderMap protectedHeaders,
        CoseHeaderMap unprotectedHeaders,
        byte[] payload,
        SigningContext context,
        CancellationToken cancellationToken = default);
}
```

## Dependency Injection

Register services in your application:

```csharp
// Startup.cs or Program.cs
services.AddSingleton<ISigningService>(sp =>
{
    var cert = LoadCertificate();
    return new LocalCertificateSigningService(cert);
});

services.AddTransient<ICoseSign1MessageFactory>(sp =>
{
    var signingService = sp.GetRequiredService<ISigningService>();
    return new DirectSignatureFactory(signingService);
});
```

## When to Use

- ✅ Creating custom signing service implementations
- ✅ Building extensible header contribution logic
- ✅ Implementing dependency injection patterns
- ✅ Writing testable code with mock interfaces
- ✅ Building plugins or extensions for CoseSignTool

## Related Packages

- **CoseSign1** - Concrete implementations of factories
- **CoseSign1.Certificates** - Certificate-based signing services
- **CoseSign1.Validation** - Validation framework
- **CoseSign1.Headers** - CWT claims and SCITT support

## Documentation

- 📖 [Full Package Documentation](https://github.com/microsoft/CoseSignTool/blob/main/V2/docs/packages/abstractions.md)
- 📖 [Architecture Guide](https://github.com/microsoft/CoseSignTool/blob/main/V2/docs/architecture/overview.md)
- 📖 [API Reference](https://github.com/microsoft/CoseSignTool/blob/main/V2/docs/api/README.md)

## Support

- 🐛 [Report Issues](https://github.com/microsoft/CoseSignTool/issues)
- 💬 [Discussions](https://github.com/microsoft/CoseSignTool/discussions)
- 📧 Email: cosesigntool@microsoft.com

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
