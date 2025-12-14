# Signing Services Architecture

This document describes the signing service architecture in CoseSignTool V2.

## Overview

Signing services provide the cryptographic signing operations for COSE Sign1 messages. V2 supports both local and remote signing services through a unified abstraction.

## Service Types

### Local Signing Services

Local signing services perform cryptographic operations using keys available on the local machine.

```csharp
// Local certificate-based signing
using var cert = new X509Certificate2("cert.pfx", "password");
using var service = new LocalCertificateSigningService(cert);
```

**When to use:**
- Development and testing
- On-premises signing
- Direct access to private keys

### Remote Signing Services

Remote signing services delegate cryptographic operations to external services.

```csharp
// Azure Trusted Signing
var service = new AzureTrustedSigningService(options);
```

**When to use:**
- Cloud-based key management
- Hardware Security Modules (HSM)
- Centralized signing infrastructure

## ISigningService Interface

All signing services implement the core `ISigningService<TOptions>` interface:

```csharp
public interface ISigningService<TOptions> : IDisposable
    where TOptions : SigningOptions
{
    CoseAlgorithm Algorithm { get; }
    
    byte[] Sign(ReadOnlySpan<byte> data, TOptions? options = default);
    
    Task<byte[]> SignAsync(
        ReadOnlyMemory<byte> data, 
        TOptions? options = default,
        CancellationToken cancellationToken = default);
}
```

## Certificate Signing Service

The `ICertificateSigningService` extends `ISigningService` with certificate-specific functionality:

```csharp
public interface ICertificateSigningService : ISigningService<SigningOptions>
{
    X509Certificate2 SigningCertificate { get; }
    X509Certificate2Collection? CertificateChain { get; }
}
```

## Creating Custom Signing Services

To create a custom signing service:

1. Implement `ISigningService<TOptions>` or `ICertificateSigningService`
2. Handle key material securely
3. Implement proper disposal

```csharp
public class CustomSigningService : ICertificateSigningService
{
    public CoseAlgorithm Algorithm => CoseAlgorithm.ES256;
    
    public X509Certificate2 SigningCertificate { get; }
    public X509Certificate2Collection? CertificateChain { get; }
    
    public byte[] Sign(ReadOnlySpan<byte> data, SigningOptions? options = default)
    {
        // Custom signing logic
    }
    
    public Task<byte[]> SignAsync(
        ReadOnlyMemory<byte> data,
        SigningOptions? options = default,
        CancellationToken cancellationToken = default)
    {
        return Task.FromResult(Sign(data.Span, options));
    }
    
    public void Dispose()
    {
        // Cleanup resources
    }
}
```

## See Also

- [Certificate Management](certificate-management.md)
- [Remote Signing Guide](../guides/remote-signing.md)
- [CoseSign1.Certificates](../components/certificates.md)
