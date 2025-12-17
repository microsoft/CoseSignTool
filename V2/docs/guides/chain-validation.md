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

CoseSignTool V2 automatically builds certificate chains:

```csharp
using CoseSign1.Certificates;

var chainBuilder = new CertificateChainBuilder();
var chain = chainBuilder.Build(signingCertificate);

if (chain.IsValid)
{
    Console.WriteLine($"Chain has {chain.Certificates.Count} certificates");
}
```

### Chain Building Options

```csharp
var options = new ChainBuildOptions
{
    // Revocation checking
    RevocationMode = X509RevocationMode.Online,
    RevocationFlag = X509RevocationFlag.EntireChain,
    
    // Verification flags
    VerificationFlags = X509VerificationFlags.NoFlag,
    
    // Additional certificates to consider
    AdditionalStore = intermediateCertificates,
    
    // Time for validation (default: now)
    VerificationTime = DateTimeOffset.UtcNow
};

var chain = chainBuilder.Build(certificate, options);
```

## Chain Structure

```
┌─────────────────────────────────────────────────────────────┐
│                   Certificate Chain                          │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  ┌─────────────────────────────────────────────────────┐    │
│  │              Root CA Certificate                     │    │
│  │         (Self-signed, in trust store)               │    │
│  └───────────────────────┬─────────────────────────────┘    │
│                          │                                   │
│                          ▼                                   │
│  ┌─────────────────────────────────────────────────────┐    │
│  │         Intermediate CA Certificate                  │    │
│  │         (Signed by Root CA)                         │    │
│  └───────────────────────┬─────────────────────────────┘    │
│                          │                                   │
│                          ▼                                   │
│  ┌─────────────────────────────────────────────────────┐    │
│  │           Leaf/End-Entity Certificate                │    │
│  │           (Signing certificate)                      │    │
│  └─────────────────────────────────────────────────────┘    │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

## Revocation Checking

### Online Checking (OCSP/CRL)

```csharp
var options = new ChainBuildOptions
{
    RevocationMode = X509RevocationMode.Online,
    RevocationFlag = X509RevocationFlag.EntireChain
};
```

### Offline Checking (Cached CRLs)

```csharp
var options = new ChainBuildOptions
{
    RevocationMode = X509RevocationMode.Offline
};
```

### No Revocation Checking

```csharp
// Use with caution - only for testing
var options = new ChainBuildOptions
{
    RevocationMode = X509RevocationMode.NoCheck
};
```

## Trust Configuration

### System Trust Store

By default, the system trust store is used:

```csharp
// Uses Windows/macOS/Linux system trust store
var validator = new CertificateChainValidator();
```

### Custom Trust Roots

For custom PKI or specific trust requirements:

```csharp
var trustedRoots = new X509Certificate2Collection();
trustedRoots.Add(new X509Certificate2("my-root-ca.cer"));

var validator = new CertificateChainValidator(trustedRoots);
```

### Pinned Certificates

Pinning is an application-specific policy (for example, enforcing an exact certificate thumbprint).
Implement this as a custom validator that extracts the signing certificate and applies your policy.

## Validation Pipeline Integration

### Add to Validation Builder

```csharp
var message = CoseMessage.DecodeSign1(signature);

var validator = Cose.Sign1Message()
    .AddCertificateValidator(b => b
        .ValidateSignature()
        .ValidateChain(revocationMode: X509RevocationMode.Online))
    .Build();

var result = await validator.ValidateAsync(message);
```

### Validation Results

```csharp
var result = await validator.ValidateAsync(message);

if (!result.IsValid)
{
    foreach (var failure in result.Failures)
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

# With custom trust root
CoseSignTool verify signed.cose --trust-root custom-root.cer

# Skip revocation check (not recommended)
CoseSignTool verify signed.cose --skip-revocation
```

### Inspect Certificate Chain

```bash
# Show certificate chain details
CoseSignTool inspect signed.cose --show-chain
```

## Including Certificates in Signatures

### Include Full Chain

```csharp
var options = new SigningOptions
{
    IncludeCertificateChain = true  // Include full chain in signature
};

var factory = new DirectSignatureFactory(signingService, options);
```

### Include Only Leaf Certificate

```csharp
var options = new SigningOptions
{
    IncludeCertificateChain = false  // Only leaf certificate
};
```

## Best Practices

### Production

```csharp
var options = new ChainBuildOptions
{
    RevocationMode = X509RevocationMode.Online,
    RevocationFlag = X509RevocationFlag.EntireChain,
    VerificationFlags = X509VerificationFlags.NoFlag // Strict
};
```

### Development/Testing

```csharp
var options = new ChainBuildOptions
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

var options = new ChainBuildOptions
{
    AdditionalStore = intermediates
};
```

### Extracting from Signature

```csharp
var message = CoseMessage.DecodeSign1(signature);
var certs = message.UnprotectedHeaders.GetCertificates();

// First cert is usually leaf, rest are chain
var leafCert = certs.First();
var intermediates = new X509Certificate2Collection(certs.Skip(1).ToArray());
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
