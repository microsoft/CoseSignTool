# Certificate Sources Guide

This guide explains the different certificate sources available in CoseSignTool V2 and how to use them.

## Overview

CoseSignTool V2 supports multiple certificate sources for signing operations, allowing flexibility in how you manage and access signing certificates.

## Available Certificate Sources

### 1. PFX Files

Load certificates from PKCS#12 (.pfx/.p12) files:

```csharp
using CoseSign1.Certificates;

var source = new PfxCertificateSource("path/to/certificate.pfx", password);
var cert = source.GetCertificate();
```

**CLI Usage:**
```bash
cosesigntool sign x509 pfx document.json --pfx cert.pfx
```

> **Note:** Set the password via the `COSESIGNTOOL_PFX_PASSWORD` environment variable for security.

### 2. Certificate Store (Windows)

Access certificates from the Windows Certificate Store:

```csharp
var source = new CertificateStoreCertificateSource(
    StoreName.My,
    StoreLocation.CurrentUser,
    thumbprint);
var cert = source.GetCertificate();
```

**CLI Usage:**
```bash
cosesigntool sign x509 certstore document.json ^
    --thumbprint ABC123... ^
    --store-name My ^
    --store-location CurrentUser
```

### 3. PEM Files

Load certificates and keys from PEM files:

```csharp
var source = new PemCertificateSource(
    certPath: "certificate.pem",
    keyPath: "private-key.pem",
    keyPassword: password);
var cert = source.GetCertificate();
```

**CLI Usage:**
```bash
cosesigntool sign x509 pem document.json ^
    --cert-file certificate.pem ^
    --key-file private-key.pem
```

### 4. Azure Trusted Signing

Use certificates from Azure Trusted Signing:

```csharp
using CoseSign1.Certificates.AzureTrustedSigning;

var options = new AzureTrustedSigningOptions
{
    Endpoint = new Uri("https://myaccount.codesigning.azure.net"),
    AccountName = "myaccount",
    CertificateProfileName = "myprofile",
    Credential = new DefaultAzureCredential()
};

var source = new AzureTrustedSigningCertificateSource(options);
var cert = await source.GetCertificateAsync();
```

**CLI Usage:**
```bash
cosesigntool sign x509 ats document.json ^
    --ats-endpoint https://myaccount.codesigning.azure.net ^
    --ats-account-name myaccount ^
    --ats-cert-profile-name myprofile
```

### 5. Ephemeral Certificates

Generate temporary self-signed certificates for testing:

```csharp
var source = new EphemeralCertificateSource();
var cert = source.GetCertificate();
```

**CLI Usage:**
```bash
cosesigntool sign x509 ephemeral document.json
```

> **Warning:** Ephemeral certificates are for testing only. Do not use in production.

## Certificate Source Interface

All certificate sources implement a common interface:

```csharp
public interface ICertificateSource
{
    /// <summary>
    /// Gets the signing certificate.
    /// </summary>
    X509Certificate2 GetCertificate();
    
    /// <summary>
    /// Gets the certificate chain.
    /// </summary>
    X509Certificate2Collection GetChain();
}
```

For async sources:

```csharp
public interface IAsyncCertificateSource
{
    Task<X509Certificate2> GetCertificateAsync(CancellationToken cancellationToken = default);
    Task<X509Certificate2Collection> GetChainAsync(CancellationToken cancellationToken = default);
}
```

## Creating Custom Certificate Sources

Implement `ICertificateSource` for your custom source:

```csharp
public class VaultCertificateSource : ICertificateSource
{
    private readonly string _vaultUrl;
    private readonly string _certificateName;
    
    public VaultCertificateSource(string vaultUrl, string certificateName)
    {
        _vaultUrl = vaultUrl;
        _certificateName = certificateName;
    }
    
    public X509Certificate2 GetCertificate()
    {
        // Retrieve certificate from your vault
        var certBytes = RetrieveFromVault(_vaultUrl, _certificateName);
        return new X509Certificate2(certBytes);
    }
    
    public X509Certificate2Collection GetChain()
    {
        // Return the certificate chain
        var chain = new X509Certificate2Collection();
        chain.Add(GetCertificate());
        // Add intermediate certificates...
        return chain;
    }
}
```

## Certificate Chain Building

V2 provides chain-building helpers based on `X509ChainPolicy`.

```csharp
using CoseSign1.Certificates.ChainBuilders;
using System.Security.Cryptography.X509Certificates;

using var chainBuilder = new X509ChainBuilder();
bool ok = chainBuilder.Build(leafCertificate);

IReadOnlyCollection<X509Certificate2> chain = chainBuilder.ChainElements;
```

To customize revocation behavior or add intermediates, provide a custom `X509ChainPolicy`:

```csharp
var policy = new X509ChainPolicy
{
    RevocationMode = X509RevocationMode.Online,
    RevocationFlag = X509RevocationFlag.EntireChain,
    VerificationFlags = X509VerificationFlags.NoFlag,
};

policy.ExtraStore.AddRange(intermediateCerts);

using var chainBuilder = new X509ChainBuilder(policy);
bool ok = chainBuilder.Build(leafCertificate);
```

## Certificate Requirements

For COSE signing, certificates must have:

| Requirement | Description |
|-------------|-------------|
| Private Key | Must have access to private key for signing |
| Key Usage | Digital Signature key usage |
| Valid Period | Must be within validity period |
| Chain | Should have valid chain to trusted root |

### Algorithm Support

| Algorithm | Certificate Type |
|-----------|-----------------|
| ES256 | ECDSA P-256 |
| ES384 | ECDSA P-384 |
| ES512 | ECDSA P-521 |
| PS256 | RSA 2048+ |
| PS384 | RSA 2048+ |
| PS512 | RSA 2048+ |
| ML-DSA-* | Post-Quantum (Windows only) |

## Security Best Practices

### PFX Files
- Store PFX files securely
- Use environment variables for passwords
- Never commit passwords to source control

### Certificate Store
- Use appropriate store location (CurrentUser for user context)
- Protect private keys with strong passwords
- Consider HSM-backed keys for production

### Azure Trusted Signing
- Use Managed Identity when possible
- Follow least-privilege access principles
- Enable logging for audit purposes

### PEM Files
- Set appropriate file permissions
- Encrypt private key files
- Use secure key management

## Troubleshooting

### Common Issues

**"Cannot find certificate"**
- Verify thumbprint is correct
- Check store name and location
- Ensure certificate is installed

**"Access denied to private key"**
- Run as administrator if needed
- Check certificate permissions
- Verify key is exportable if needed

**"Certificate chain validation failed"**
- Install intermediate certificates
- Check certificate validity period
- Verify revocation status

## See Also

- [Certificate Management Architecture](../architecture/certificate-management.md)
- [Azure Trusted Signing](../components/azure-trusted-signing.md)
- [Security Guide](security.md)
