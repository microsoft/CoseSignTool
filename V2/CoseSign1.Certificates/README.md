# CoseSign1.Certificates

Certificate-based signing and validation for COSE Sign1 messages with full X.509 support.

## Installation

```bash
dotnet add package CoseSign1.Certificates --version 2.0.0-preview
```

## Overview

Comprehensive X.509 certificate support for COSE signing operations, including local and remote signing, certificate chain management, and certificate-based validation.

## Key Features

- ✅ **CertificateSigningService.Create()** - Factory methods for local and remote certificate signing
- ✅ **Certificate Sources** - PFX, Windows Store, Linux Store, Direct
- ✅ **Chain Building** - Automatic and explicit certificate chain construction
- ✅ **Certificate Validators** - Signature, expiration, chain, EKU, CN validation
- ✅ **Remote Signing** - Base classes for cloud/HSM signing
- ✅ **ML-DSA Support** - Post-quantum cryptography ready

## Quick Start

### Sign with Certificate from File

```csharp
using CoseSign1.Certificates;
using CoseSign1.Certificates.ChainBuilders;
using CoseSign1.Direct;

// Load certificate with private key
using var cert = new X509Certificate2("cert.pfx", "password");

// Create signing service using factory method
using var chainBuilder = new X509ChainBuilder();
using var service = CertificateSigningService.Create(cert, chainBuilder);

// Create factory and sign
using var factory = new DirectSignatureFactory(service);
byte[] signedMessage = factory.CreateCoseSign1MessageBytes(
    payload, 
    contentType: "application/json");
```

### Sign with Certificate from Windows Store

```csharp
using CoseSign1.Certificates;
using CoseSign1.Certificates.ChainBuilders;

// Find certificate by thumbprint
using var source = new WindowsCertificateStoreCertificateSource(
    thumbprint: "ABC123DEF456...",
    storeName: StoreName.My,
    storeLocation: StoreLocation.CurrentUser);

var cert = source.GetCertificate();
using var chainBuilder = new X509ChainBuilder();
using var service = CertificateSigningService.Create(cert!, chainBuilder);
```

### Sign with Certificate from Linux Store

```csharp
using CoseSign1.Certificates;
using CoseSign1.Certificates.ChainBuilders;

// Load from Linux certificate store
using var source = new LinuxCertificateStoreCertificateSource(
    certificatePath: "/etc/ssl/certs/my-cert.crt",
    keyPath: "/etc/ssl/private/my-key.pem");

var cert = source.GetCertificate();
using var chainBuilder = new X509ChainBuilder();
using var service = CertificateSigningService.Create(cert!, chainBuilder);
```

## Certificate Sources

### DirectCertificateSource

Use when you already have a certificate in memory:

```csharp
using var source = new DirectCertificateSource(certificate);
```

### PfxCertificateSource

Load from PFX/PKCS#12 file:

```csharp
using var source = new PfxCertificateSource("cert.pfx", "password");
var cert = source.GetCertificate();
```

### WindowsCertificateStoreCertificateSource

Load from Windows certificate store:

```csharp
using var source = new WindowsCertificateStoreCertificateSource(
    thumbprint: "ABC123DEF456...",
    storeName: StoreName.My,
    storeLocation: StoreLocation.CurrentUser);
```

### LinuxCertificateStoreCertificateSource

Load from Linux certificate store (PEM files):

```csharp
using var source = new LinuxCertificateStoreCertificateSource(
    certificatePath: "/path/to/cert.pem",
    keyPath: "/path/to/key.pem");
```

## Certificate Chain Building

### Automatic Chain Building

```csharp
using CoseSign1.Certificates.ChainBuilders;

// Uses system certificate store
using var chainBuilder = new X509ChainBuilder();
X509Certificate2Collection chain = chainBuilder.BuildChain(certificate);
```

### Explicit Chain

```csharp
// Provide certificates explicitly
var intermediateCerts = new X509Certificate2Collection { intermediate1, intermediate2 };
using var chainBuilder = new ExplicitCertificateChainBuilder(intermediateCerts);
X509Certificate2Collection chain = chainBuilder.BuildChain(leafCertificate);
```

## Certificate Validation

### Basic Signature Validation

```csharp
using CoseSign1.Certificates.Extensions;

// Verify signature using certificate in message
bool isValid = message.VerifySignature();
```

### Validate Certificate Properties

```csharp
using CoseSign1.Certificates.Validation;
using CoseSign1.Validation;

// Build validation pipeline
var validator = Cose.Sign1Message()
    .ValidateCertificateSignature()
    .ValidateCertificate(cert => cert
        .NotExpired()
        .HasCommonName("My Trusted Signer")
        .HasEnhancedKeyUsage("1.3.6.1.5.5.7.3.3")) // Code signing
    .Build();
var signatureResult = validator.Validate(message, ValidationStage.Signature);
if (!signatureResult.IsValid)
{
    foreach (var failure in signatureResult.Failures)
    {
        Console.WriteLine($"{failure.ErrorCode}: {failure.Message}");
    }
}

var postSignatureResult = validator.Validate(message, ValidationStage.PostSignature);
if (!postSignatureResult.IsValid)
{
    foreach (var failure in postSignatureResult.Failures)
    {
        Console.WriteLine($"{failure.ErrorCode}: {failure.Message}");
    }
}
```

### Certificate Chain Validation

```csharp
var validator = Cose.Sign1Message()
    .ValidateCertificateSignature()
    .ValidateCertificateChain(options =>
    {
        options.AllowUntrusted = false;
        options.TrustUserRoots = true;
        options.CustomRoots = trustedRoots;
    })
    .Build();
```

## Certificate Validators

### CertificateSignatureValidator

Verifies the cryptographic signature using the certificate:

```csharp
var validator = new CertificateSignatureValidator();
var result = validator.Validate(message, ValidationStage.Signature);
```

### CertificateExpirationValidator

Checks certificate is within validity period:

```csharp
// Validate against current time
var validator = new CertificateExpirationValidator();

// Validate against specific time
var validator = new CertificateExpirationValidator(asOfDate);
```

### CertificateChainValidator

Validates the full certificate chain:

```csharp
var validator = new CertificateChainValidator(
    chainBuilder,
    allowUntrusted: false,
    customRoots: trustedCertificates);
```

### CertificateCommonNameValidator

Validates certificate Common Name:

```csharp
var validator = new CertificateCommonNameValidator("Expected CN");
```

### CertificateKeyUsageValidator

Validates Key Usage and Enhanced Key Usage:

```csharp
// By EKU OID
var validator = new CertificateKeyUsageValidator("1.3.6.1.5.5.7.3.3");

// By X509KeyUsageFlags
var validator = new CertificateKeyUsageValidator(
    X509KeyUsageFlags.DigitalSignature);
```

### CertificatePredicateValidator

Custom predicate-based validation:

```csharp
var validator = new CertificatePredicateValidator(
    cert => cert.Subject.Contains("Contoso"),
    failureMessage: "Certificate must be from Contoso");
```

## Advanced Usage

### Remote Signing Service

Create custom remote signing by extending base classes:

```csharp
public class MyCloudSigningService : CertificateSigningService
{
    private readonly ICloudSigningClient _client;
    
    public MyCloudSigningService(ICloudSigningClient client)
    {
        _client = client;
    }
    
    protected override ICertificateSigningKey GetSigningKey(SigningContext context)
    {
        return new RemoteSigningKey(_client, this);
    }
    
    public override bool IsRemote => true;
}
```

### Certificate Header Contributor

Add X5T and X5Chain headers automatically:

```csharp
using CoseSign1.Certificates;

// CertificateHeaderContributor is automatically used by
// CertificateSigningService.Create() to add:
// - X5T (certificate thumbprint)
// - X5Chain (full certificate chain)
```

### Detached Signature Validation

Validate signature when payload is stored separately:

```csharp
// Preferred: use CertificateSignatureValidator with the detached payload
var validator = new CertificateSignatureValidator(
    detachedPayload: originalPayload,
    allowUnprotectedHeaders: false);

var result = validator.Validate(message, ValidationStage.Signature);

// Or, when using the fluent builder:
// var result = Cose.Sign1Message()
//     .ValidateCertificateSignature(originalPayload, allowUnprotectedHeaders: false)
//     .Build()
//     .Validate(message, ValidationStage.Signature);
```

## Supported Algorithms

| Algorithm | Key Type | Notes |
|-----------|----------|-------|
| ES256 | ECDSA P-256 | Recommended |
| ES384 | ECDSA P-384 | |
| ES512 | ECDSA P-521 | |
| PS256 | RSA-PSS | |
| PS384 | RSA-PSS | |
| PS512 | RSA-PSS | |
| RS256 | RSA PKCS#1 | Legacy support |
| ML-DSA | ML-DSA (FIPS 204) | Post-quantum |

## See Also

- [CoseSign1](../CoseSign1/README.md) - Signature factories
- [CoseSign1.Validation](../CoseSign1.Validation/README.md) - Validation framework
- [CoseSign1.Certificates.AzureTrustedSigning](../CoseSign1.Certificates.AzureTrustedSigning/README.md) - Azure integration
- [CoseSign1.Headers](../CoseSign1.Headers/README.md) - CWT claims
