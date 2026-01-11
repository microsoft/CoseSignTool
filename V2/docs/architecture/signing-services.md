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
using var service = CertificateSigningService.Create(cert);
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

All signing services implement the core `ISigningService<TSigningOptions>` interface.

In V2, signing services **emit a configured `CoseSigner`** (key + headers) which the factories use to produce COSE Sign1 bytes/messages.

```csharp
public interface ISigningService<out TSigningOptions> : IDisposable
    where TSigningOptions : SigningOptions
{
    CoseSigner GetCoseSigner(SigningContext context);

    TSigningOptions CreateSigningOptions();

    bool IsRemote { get; }

    SigningServiceMetadata ServiceMetadata { get; }
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
    public X509Certificate2 SigningCertificate { get; }
    public X509Certificate2Collection? CertificateChain { get; }

    public CoseSigner GetCoseSigner(SigningContext context)
    {
        // 1) Select the key material (SigningCertificate private key, HSM handle, remote key reference, ...)
        // 2) Apply required + additional header contributors (context.AdditionalHeaderContributors)
        // 3) Return a CoseSigner configured for the operation
        throw new NotImplementedException();
    }

    public SigningOptions CreateSigningOptions() => new SigningOptions();

    public bool IsRemote => false;

    public SigningServiceMetadata ServiceMetadata => new SigningServiceMetadata("CustomSigningService");
    
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
