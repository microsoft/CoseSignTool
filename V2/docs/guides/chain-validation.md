# Certificate Chain Validation Guide

This guide explains certificate chain validation in CoseSignTool V2.

## Overview

Certificate chain validation ensures that a signing certificate:
1. Is issued by a trusted Certificate Authority (CA)
2. Has a valid chain to a trusted root
3. Has not been revoked
4. Is within its validity period

## Chain Building

### Automatic Chain Building

CoseSignTool V2 uses the built-in X.509 chain builder wrapper:

```csharp
using CoseSign1.Certificates.ChainBuilders;

using var chainBuilder = new X509ChainBuilder();
bool ok = chainBuilder.Build(signingCertificate);

if (!ok)
{
    // Inspect chainBuilder.ChainStatus for X509ChainStatusFlags values
    foreach (var status in chainBuilder.ChainStatus)
    {
        Console.WriteLine($"{status.Status}: {status.StatusInformation}");
    }
}
else
{
    Console.WriteLine($"Chain length: {chainBuilder.ChainElements.Count}");
}
```

### Chain Building Options

```csharp
using CoseSign1.Certificates.ChainBuilders;

var policy = new X509ChainPolicy
{
    RevocationMode = X509RevocationMode.Online,
    RevocationFlag = X509RevocationFlag.ExcludeRoot,
    VerificationFlags = X509VerificationFlags.NoFlag,
    UrlRetrievalTimeout = TimeSpan.FromSeconds(30),
};

// Optional: provide intermediates
policy.ExtraStore.AddRange(intermediateCertificates);

using var chainBuilder = new X509ChainBuilder(policy);
bool ok = chainBuilder.Build(certificate);
```

## Chain Structure

```
┌─────────────────────────────────────────────────────────────┐
│                   Certificate Chain                         │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  ┌─────────────────────────────────────────────────────┐    │
│  │              Root CA Certificate                    │    │
│  │         (Self-signed, in trust store)               │    │
│  └───────────────────────┬─────────────────────────────┘    │
│                          │                                  │
│                          ▼                                  │
│  ┌─────────────────────────────────────────────────────┐    │
│  │         Intermediate CA Certificate                 │    │
│  │         (Signed by Root CA)                         │    │
│  └───────────────────────┬─────────────────────────────┘    │
│                          │                                  │
│                          ▼                                  │
│  ┌─────────────────────────────────────────────────────┐    │
│  │           Leaf/End-Entity Certificate               │    │
│  │           (Signing certificate)                     │    │
│  └─────────────────────────────────────────────────────┘    │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

## Revocation Checking

### Online Checking (OCSP/CRL)

```csharp
var policy = new X509ChainPolicy
{
    RevocationMode = X509RevocationMode.Online,
    RevocationFlag = X509RevocationFlag.ExcludeRoot
};
```

### Offline Checking (Cached CRLs)

```csharp
var policy = new X509ChainPolicy
{
    RevocationMode = X509RevocationMode.Offline,
    RevocationFlag = X509RevocationFlag.ExcludeRoot
};
```

### No Revocation Checking

```csharp
// Use with caution - only for testing
var policy = new X509ChainPolicy
{
    RevocationMode = X509RevocationMode.NoCheck,
    RevocationFlag = X509RevocationFlag.ExcludeRoot
};
```

## Trust Configuration

### System Trust Store

By default, the system trust store is used:

```csharp
using CoseSign1.Validation.DependencyInjection;
using Microsoft.Extensions.DependencyInjection;
using System.Security.Cryptography.Cose;

var services = new ServiceCollection();
var validation = services.ConfigureCoseValidation();

// Uses Windows/macOS/Linux system trust store for chain building
validation.EnableCertificateTrust(cert => cert
    .UseSystemTrust()
    );

using var sp = services.BuildServiceProvider();
using var scope = sp.CreateScope();

var validator = scope.ServiceProvider
    .GetRequiredService<ICoseSign1ValidatorFactory>()
    .Create();
```

### Custom Trust Roots

For custom PKI or specific trust requirements:

```csharp
var trustedRoots = new X509Certificate2Collection();
trustedRoots.Add(new X509Certificate2("my-root-ca.cer"));

var services = new ServiceCollection();
var validation = services.ConfigureCoseValidation();

validation.EnableCertificateTrust(cert => cert
    .UseCustomRootTrust(trustedRoots)
    );

using var sp = services.BuildServiceProvider();
using var scope = sp.CreateScope();

var validator = scope.ServiceProvider
    .GetRequiredService<ICoseSign1ValidatorFactory>()
    .Create();
```

### Pinned Certificates

Pinning is an application-specific policy (for example, enforcing an exact certificate thumbprint).
Implement this as a custom validator that extracts the signing certificate and applies your policy.

## Validation Pipeline Integration

### Add to Validation Builder

```csharp
var message = CoseMessage.DecodeSign1(signature);

var services = new ServiceCollection();
var validation = services.ConfigureCoseValidation();

validation.EnableCertificateTrust(cert => cert
    .UseSystemTrust()
    .WithRevocationMode(X509RevocationMode.Online)
    );

using var sp = services.BuildServiceProvider();
using var scope = sp.CreateScope();

var validator = scope.ServiceProvider
    .GetRequiredService<ICoseSign1ValidatorFactory>()
    .Create();


var results = message.Validate(validator);
var signatureResult = results.Signature;
var trustResult = results.Trust;
```

### Validation Results

```csharp
var trustResult = message.Validate(validator).Trust;

if (!trustResult.IsValid)
{
    foreach (var failure in trustResult.Failures)
    {
        if (failure.ErrorCode == "CHAIN_BUILD_FAILED")
        {
            Console.WriteLine($"Chain error: {failure.Message}");
        }
        else if (string.Equals(failure.ErrorCode, X509ChainStatusFlags.Revoked.ToString(), StringComparison.OrdinalIgnoreCase))
        {
            Console.WriteLine($"Certificate revoked: {failure.Message}");
        }
    }
}
```

## Common Chain Validation Errors

| Error | Cause | Resolution |
|-------|-------|------------|
| `UntrustedRoot` | Root CA not in trust store | Add root CA to trust store |
| `PartialChain` | Missing intermediate certificate | Provide intermediate certificates |
| `Revoked` | Certificate has been revoked | Use different certificate |
| `NotTimeValid` | Certificate expired or not yet valid | Check system time, renew certificate |
| `InvalidNameConstraints` | Certificate violates name constraints | Check certificate configuration |
| `RevocationOffline` | Cannot check revocation | Enable network access or skip revocation |

## CLI Usage

### Verify with Chain Validation

```bash
# Default: validates chain with online revocation check
CoseSignTool verify signed.cose

# With custom trust roots (repeatable)
CoseSignTool verify signed.cose --trust-roots custom-root.cer

# Disable revocation check (not recommended)
CoseSignTool verify signed.cose --revocation-mode none
```

### Inspect Certificate Chain

```bash
# Inspect output includes certificate chain details
CoseSignTool inspect signed.cose
```

## Including Certificates in Signatures

Certificate-based signing in V2 adds X.509 key material headers by default:

- `x5t` (certificate thumbprint)
- `x5chain` (leaf-first certificate chain)

These headers are required for certificate-based verification (the verifier resolves the signing certificate by matching `x5t` to a certificate in `x5chain`).

If you want a signature with no X.509 material (for example, a key-only signature with `kid` + embedded COSE_Key), use `sign-akv-key` instead of certificate-based signing.

## Best Practices

### Production

```csharp
var policy = new X509ChainPolicy
{
    RevocationMode = X509RevocationMode.Online,
    RevocationFlag = X509RevocationFlag.ExcludeRoot,
    VerificationFlags = X509VerificationFlags.NoFlag // Strict
};
```

### Development/Testing

```csharp
var policy = new X509ChainPolicy
{
    RevocationMode = X509RevocationMode.NoCheck,
    // Allow self-signed for testing
    VerificationFlags = X509VerificationFlags.AllowUnknownCertificateAuthority
};
```

## Handling Intermediate Certificates

### Providing Intermediates

```csharp
var intermediates = new X509Certificate2Collection();
intermediates.Add(new X509Certificate2("intermediate.cer"));

var policy = new X509ChainPolicy();
policy.ExtraStore.AddRange(intermediates);
```

### Extracting from Signature

```csharp
using CoseSign1.Certificates.Extensions;
using System.Security.Cryptography.Cose;

var message = CoseMessage.DecodeSign1(signature);

if (message.TryGetCertificateChain(out var chain))
{
    // Chain is leaf-first
    var leafCert = chain[0];
    var intermediates = new X509Certificate2Collection(chain.Cast<X509Certificate2>().Skip(1).ToArray());
}
```

## Cross-Platform Considerations

| Platform | Trust Store | Notes |
|----------|-------------|-------|
| Windows | Windows Certificate Store | Rich UI management |
| macOS | Keychain | System and login keychains |
| Linux | OpenSSL ca-certificates | /etc/ssl/certs |

### Linux-Specific Setup

```bash
# Add custom CA to system trust
sudo cp custom-ca.crt /usr/local/share/ca-certificates/
sudo update-ca-certificates
```

## Security Recommendations

1. **Always check revocation** in production
2. **Use explicit trust roots** when possible
3. **Include full chain** in signatures for portability
4. **Monitor certificate expiration** dates
5. **Have renewal process** before certificates expire

## See Also

- [Certificate Sources](certificate-sources.md)
- [Security Guide](security.md)
- [Validation Framework](../architecture/validation-framework.md)
- [Certificate Management Architecture](../architecture/certificate-management.md)
