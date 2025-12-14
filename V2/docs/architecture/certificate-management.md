# Certificate Management

This document describes certificate management in CoseSignTool V2.

## Overview

Certificate management in V2 is built around three key concepts:
- **Certificate Sources**: Where certificates come from
- **Chain Builders**: How certificate chains are constructed
- **Signing Key Providers**: How signing keys are obtained

## Certificate Sources

Certificate sources provide certificates from various locations.

### ICertificateSource Interface

```csharp
public interface ICertificateSource
{
    Task<X509Certificate2?> GetCertificateAsync(
        CancellationToken cancellationToken = default);
    
    Task<X509Certificate2Collection?> GetCertificateChainAsync(
        CancellationToken cancellationToken = default);
}
```

### Available Sources

| Source | Description | Use Case |
|--------|-------------|----------|
| `DirectCertificateSource` | In-memory certificate | Testing, direct certificate usage |
| `PfxCertificateSource` | PFX/PKCS#12 file | File-based certificates |
| `WindowsCertificateStoreCertificateSource` | Windows cert store | Windows enterprise environments |
| `LinuxCertificateStoreCertificateSource` | Linux cert paths | Linux/macOS environments |
| `AzureTrustedSigningCertificateSource` | Azure Trusted Signing | Cloud-based signing |

### Example Usage

```csharp
// From PFX file
var source = new PfxCertificateSource("cert.pfx", password);
var cert = await source.GetCertificateAsync();

// From Windows store
var source = new WindowsCertificateStoreCertificateSource(
    thumbprint: "ABC123...",
    storeLocation: StoreLocation.CurrentUser,
    storeName: StoreName.My);
```

## Chain Builders

Chain builders construct certificate chains for embedding in signatures.

### ICertificateChainBuilder Interface

```csharp
public interface ICertificateChainBuilder
{
    X509Certificate2Collection BuildChain(X509Certificate2 certificate);
}
```

### Available Builders

| Builder | Description |
|---------|-------------|
| `X509ChainBuilder` | Uses system chain building with configurable policy |
| `ExplicitCertificateChainBuilder` | Uses explicitly provided certificate collection |

### Example Usage

```csharp
// System chain building
var builder = new X509ChainBuilder(policy =>
{
    policy.RevocationMode = X509RevocationMode.Online;
    policy.VerificationFlags = X509VerificationFlags.AllowUnknownCertificateAuthority;
});
var chain = builder.BuildChain(signingCert);

// Explicit chain
var builder = new ExplicitCertificateChainBuilder(certCollection);
var chain = builder.BuildChain(signingCert);
```

## Signing Key Providers

Signing key providers combine certificate sources and chain builders to provide complete signing capabilities.

### ISigningKeyProvider Interface

```csharp
public interface ISigningKeyProvider
{
    Task<CertificateSigningKey> GetSigningKeyAsync(
        CancellationToken cancellationToken = default);
}
```

### CertificateSigningKey

```csharp
public sealed class CertificateSigningKey
{
    public X509Certificate2 Certificate { get; }
    public X509Certificate2Collection? Chain { get; }
    public AsymmetricAlgorithm PrivateKey { get; }
}
```

## Best Practices

### Certificate Storage
- Never store private keys in source control
- Use secure storage (HSM, Azure Key Vault) for production
- Use environment variables or secure files for passwords

### Chain Building
- Include full chain for better interoperability
- Consider certificate size vs. verification needs
- Test chain validation with different trust stores

### Key Management
- Rotate certificates before expiration
- Use appropriate key sizes (RSA ≥ 2048, ECDSA ≥ 256)
- Consider post-quantum options for future-proofing

## See Also

- [Signing Services](signing-services.md)
- [Certificate Sources Guide](../guides/certificate-sources.md)
- [CoseSign1.Certificates](../components/certificates.md)
