# CoseSign1.Certificates

Certificate-based signing and validation for COSE Sign1 messages with full X.509 support.

## Overview

Comprehensive X.509 certificate support for COSE signing operations, including local and remote signing, certificate chain management, and certificate-based validation.

## Installation

```bash
dotnet add package CoseSign1.Certificates --version 2.0.0-preview
```

## Key Features

- ✅ **Local Certificate Signing** - Sign with local X.509 certificates
- ✅ **Certificate Sources** - File, Store, Base64 certificate sources
- ✅ **Chain Building** - Automatic certificate chain construction
- ✅ **Certificate Validators** - Signature, expiration, chain, EKU, SAN validation
- ✅ **PKI Integration** - Full X.509 PKI support
- ✅ **Detached Signature Support** - Validate detached signatures

## Quick Start

### Sign with Certificate from File

```csharp
using CoseSign1.Certificates.Local;

using var cert = new X509Certificate2("cert.pfx", "password");
using var service = new LocalCertificateSigningService(cert);

var factory = new DirectSignatureFactory(service);
var message = await factory.CreateAsync(payload);
```

### Sign with Certificate from Store

```csharp
using CoseSign1.Certificates;

using var store = new X509Store(StoreName.My, StoreLocation.CurrentUser);
store.Open(OpenFlags.ReadOnly);

var cert = store.Certificates
    .Find(X509FindType.FindByThumbprint, "ABC123...", false)
    .FirstOrDefault();

using var service = new LocalCertificateSigningService(cert!);
var factory = new DirectSignatureFactory(service);
```

### Certificate Sources

```csharp
// From file
using var certSource = new FileCertificateSource("cert.pfx", "password");

// From Windows certificate store
using var storeSource = new StoreCertificateSource(
    "1234567890ABCDEF",
    StoreName.My,
    StoreLocation.CurrentUser);

// From base64-encoded string
using var base64Source = new Base64CertificateSource(certBase64, password);

var cert = certSource.GetCertificate();
using var service = new LocalCertificateSigningService(cert!);
```

## Validation

### Basic Certificate Validation

```csharp
using CoseSign1.Certificates.Validation;
using CoseSign1.Validation;

var validator = new ValidatorBuilder()
    .WithSignatureValidator()
    .WithExpirationValidator()
    .Build();

var result = validator.Validate(message);

if (!result.Success)
{
    foreach (var failure in result.Failures)
    {
        Console.WriteLine($"{failure.Code}: {failure.Message}");
    }
}
```

### Certificate Chain Validation

```csharp
var policy = new X509ChainPolicy
{
    RevocationMode = X509RevocationMode.Online,
    RevocationFlag = X509RevocationFlag.EntireChain
};

var validator = new ValidatorBuilder()
    .WithSignatureValidator()
    .WithChainValidator(policy, trustedRootCerts)
    .Build();
```

### EKU Policy Validation

```csharp
// Require code signing EKU
var validator = new ValidatorBuilder()
    .WithSignatureValidator()
    .WithEkuPolicy("1.3.6.1.5.5.7.3.3") // Code Signing
    .Build();

// Multiple EKUs
var validator = new ValidatorBuilder()
    .WithEkuPolicy(
        "1.3.6.1.5.5.7.3.3",           // Code Signing
        "1.3.6.1.4.1.311.10.3.13"      // Lifetime Signing
    )
    .Build();
```

### SAN Policy Validation

```csharp
var validator = new ValidatorBuilder()
    .WithSanPolicy(
        allowedDnsNames: new[] { "*.contoso.com" },
        allowedEmailAddresses: new[] { "*@contoso.com" }
    )
    .Build();
```

## Certificate Chain Building

```csharp
using CoseSign1.Certificates.ChainBuilders;

var chainBuilder = new CertificateChainBuilder()
    .WithPolicy(new X509ChainPolicy
    {
        RevocationMode = X509RevocationMode.Online
    })
    .WithRootCertificates(trustedRoots)
    .WithIntermediateCertificates(intermediates);

using var chain = chainBuilder.Build();
bool isValid = chain.Build(certificate);
```

## Advanced Scenarios

### Custom Certificate Source

```csharp
public class ConfigCertificateSource : CertificateSourceBase
{
    private readonly IConfiguration _config;
    
    public override X509Certificate2? GetCertificate()
    {
        var path = _config["Certificate:Path"];
        var password = _config["Certificate:Password"];
        return new X509Certificate2(path, password);
    }
}
```

### Signing with Full Chain

```csharp
var options = new CertificateSigningOptions
{
    IncludeCertificateChain = true,
    ChainBuildingOptions = new X509ChainPolicy
    {
        RevocationMode = X509RevocationMode.Online
    }
};

using var service = new LocalCertificateSigningService(cert, options);
```

### Detached Signature Validation

```csharp
byte[] payload = File.ReadAllBytes("document.bin");
byte[] signature = File.ReadAllBytes("document.cose");

var message = CoseSign1Message.Decode(signature);
var validator = new CertificateDetachedSignatureValidator(payload);
var result = validator.Validate(message);
```

## Extension Methods

```csharp
// Certificate extensions
string sha256 = cert.GetSha256Thumbprint();
bool canSign = cert.HasDigitalSignatureKeyUsage();
bool isValid = cert.IsValidNow();
bool hasSigning = cert.HasExtendedKeyUsage("1.3.6.1.5.5.7.3.3");

// Message extensions
X509Certificate2? cert = message.GetSigningCertificate();
IEnumerable<X509Certificate2> chain = message.GetCertificateChain();
string? thumbprint = message.GetCertificateThumbprint();
```

## Common EKU OIDs

| OID | Usage |
|-----|-------|
| `1.3.6.1.5.5.7.3.1` | Server Authentication |
| `1.3.6.1.5.5.7.3.2` | Client Authentication |
| `1.3.6.1.5.5.7.3.3` | Code Signing |
| `1.3.6.1.5.5.7.3.4` | Email Protection |
| `1.3.6.1.4.1.311.10.3.13` | Lifetime Signing |

## When to Use

- ✅ Signing with X.509 certificates
- ✅ Certificate-based validation
- ✅ PKI integration
- ✅ Enterprise certificate management
- ✅ Code signing scenarios
- ✅ Building trust chains

## Related Packages

- **CoseSign1.Abstractions** - Core interfaces
- **CoseSign1** - Message factories
- **CoseSign1.Validation** - Validation framework
- **CoseSign1.Certificates.AzureTrustedSigning** - Azure cloud signing

## Documentation

- 📖 [Full Package Documentation](https://github.com/microsoft/CoseSignTool/blob/main/V2/docs/packages/certificates.md)
- 📖 [Certificate Management Guide](https://github.com/microsoft/CoseSignTool/blob/main/V2/docs/guides/certificate-management.md)
- 📖 [Validation Guide](https://github.com/microsoft/CoseSignTool/blob/main/V2/docs/guides/validation.md)

## Support

- 🐛 [Report Issues](https://github.com/microsoft/CoseSignTool/issues)
- 💬 [Discussions](https://github.com/microsoft/CoseSignTool/discussions)
- 📧 Email: cosesigntool@microsoft.com

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
