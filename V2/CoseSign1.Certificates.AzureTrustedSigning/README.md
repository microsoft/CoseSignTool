# CoseSign1.Certificates.AzureTrustedSigning

Azure Trusted Signing integration for COSE Sign1 V2 architecture.

## Overview

This package provides a remote signing service implementation for [Azure Trusted Signing](https://learn.microsoft.com/azure/trusted-signing/), Microsoft's cloud-based code signing service. Azure Trusted Signing provides:

- **Secure Key Storage**: FIPS 140-2 Level 3 HSM-backed keys
- **Certificate Management**: Automated certificate lifecycle management
- **Compliance**: Built-in support for industry standards (SCITT, etc.)
- **Algorithms**: RSA signing operations (ECDSA not currently supported by Azure SDK)

## Installation

```bash
dotnet add package CoseSign1.Certificates.AzureTrustedSigning
```

## Prerequisites

1. **Azure Trusted Signing Account**: Set up an Azure Trusted Signing account and certificate profile
2. **Azure SDK**: This package uses `Azure.Developer.TrustedSigning.CryptoProvider` (version 0.1.60)
3. **Authentication**: Configure Azure credentials (service principal, managed identity, or interactive)
4. **Target Framework**: Requires .NET 8.0 or later (Azure SDK requirement)

## Quick Start

### Basic Usage

```csharp
using Azure.Identity;
using CoseSign1.Abstractions;
using CoseSign1.Certificates.AzureTrustedSigning;
using CoseSign1;

// 1. Configure Azure Trusted Signing parameters
var endpointUrl = "https://your-account.azure-trusted-signing.net";
var certificateProfile = "YourCertificateProfile";
var credential = new DefaultAzureCredential();

// 2. Create the signing service
using var signingService = new AzureTrustedSigningService(
    endpointUrl,
    certificateProfile,
    credential);

// 3. Create a factory with the signing service
var factory = new DirectSignatureFactory(signingService);

// 4. Sign your payload
byte[] payload = Encoding.UTF8.GetBytes("Hello, Azure Trusted Signing!");
var message = await factory.CreateCoseSign1MessageAsync(payload);

// 5. Verify the signature
bool isValid = message.Verify();
Console.WriteLine($"Signature valid: {isValid}");
```

### SCITT Compliance

Azure Trusted Signing certificates include Microsoft-specific EKU extensions that enable proper SCITT compliance:

```csharp
using Azure.Identity;
using CoseSign1.Certificates.AzureTrustedSigning;
using CoseSign1.Certificates.AzureTrustedSigning.Extensions;

// Create signing service
using var signingService = new AzureTrustedSigningService(
    "https://your-account.azure-trusted-signing.net",
    "YourCertificateProfile",
    new DefaultAzureCredential());

// Get the certificate chain for DID:X509 generation
// Note: This creates a temporary AzSignContext just to fetch the cert chain
using var tempContext = new AzSignContext(
    "https://your-account.azure-trusted-signing.net",
    "YourCertificateProfile",
    new DefaultAzureCredential());
using var certSource = new AzureTrustedSigningCertificateSource(tempContext);
var certChain = certSource.GetCertificateChain();

// Configure options for SCITT compliance
var options = signingService.CreateSigningOptions()
    .ConfigureForAzureScitt(certChain);

// Sign with SCITT-compliant CWT claims
var factory = new DirectSignatureFactory(signingService);
var message = await factory.CreateCoseSign1MessageAsync(
    payload,
    options: options);
```

The `ConfigureForAzureScitt` extension method automatically:
- Generates DID:X509 issuer with Azure-specific EKU policy
- Creates proper CWT claims (iss, iat, nbf)
- Enables SCITT compliance mode

### Custom CWT Claims

Customize CWT claims while maintaining SCITT compliance:

```csharp
var options = signingService.CreateSigningOptions()
    .ConfigureForAzureScitt(certChain, claims =>
    {
        claims.Subject = "my-subject";
        claims.Audience = "my-audience";
        claims.Expiration = DateTimeOffset.UtcNow.AddHours(1).ToUnixTimeSeconds();
    });
```

### With Transparency Services

Combine Azure Trusted Signing with transparency providers (e.g., MST):

```csharp
using Azure.Identity;
using CoseSign1.Transparent.MST;

// Create transparency provider
var mstProvider = new MstTransparencyProvider(
    serviceUrl: "https://your-mst-service.azure.net",
    credential: new DefaultAzureCredential());

// Create signing service
using var signingService = new AzureTrustedSigningService(
    "https://your-account.azure-trusted-signing.net",
    "YourCertificateProfile",
    new DefaultAzureCredential());

// Create factory with both signing service and transparency
var factory = new DirectSignatureFactory(
    signingService,
    transparencyProviders: new[] { mstProvider });

// Single-call: Sign + Add transparency proof
var message = await factory.CreateCoseSign1MessageAsync(payload);

// The message now has both:
// 1. Azure Trusted Signing signature
// 2. MST transparency receipt in unprotected headers
```

## DID:X509 with EKU Policy

Azure Trusted Signing certificates use the DID:X509 EKU policy format:

```
did:x509:0:sha256:{base64url-hash}::eku:{microsoft-oid}
```

Example:
```
did:x509:0:sha256:WE4P5dd8DnLHSkyHaIjhp4udlkF9LqoKwCvu9gl38jk::eku:1.3.6.1.4.1.311.10.3.13
```

The library automatically:
- Detects Microsoft EKUs (starting with 1.3.6.1.4.1.311)
- Selects the "deepest greatest" EKU (most specific)
- Formats according to the [DID:X509 specification](https://github.com/microsoft/did-x509/blob/main/specification.md#eku-policy)

Manual DID generation:

```csharp
using Azure.Identity;
using CoseSign1.Certificates.AzureTrustedSigning;

// Create a temporary context to fetch certificate chain
using var tempContext = new AzSignContext(
    "https://your-account.azure-trusted-signing.net",
    "YourCertificateProfile",
    new DefaultAzureCredential());
using var certSource = new AzureTrustedSigningCertificateSource(tempContext);
var certChain = certSource.GetCertificateChain();

string did = AzureTrustedSigningDidX509.Generate(certChain);
Console.WriteLine($"DID:X509 Identifier: {did}");
```

## Architecture Integration

This package integrates with the V2 architecture pattern:

```
┌─────────────────────────────────────┐
│   DirectSignatureFactory            │
│   (ICoseSign1MessageFactory)        │
└────────────┬────────────────────────┘
             │
             ▼
┌─────────────────────────────────────┐
│   AzureTrustedSigningService        │
│   (ISigningService)                 │
│   - IsRemote = true                 │
│   - GetCoseSigner()                 │
│   - Stores: endpoint, profile, cred │
└────────────┬────────────────────────┘
             │ Creates per operation
             ▼
┌─────────────────────────────────────┐
│   AzSignContext (Azure SDK)         │
│   - Per-operation instance          │
└────────────┬────────────────────────┘
             │
             ▼
┌─────────────────────────────────────┐
│   AzureTrustedSigningCertSource     │
│   (RemoteCertificateSource)         │
│   - SignDataWithRsa/Ecdsa()         │
│   - GetCertificateChain()           │
└────────────┬────────────────────────┘
             │
             ▼
┌─────────────────────────────────────┐
│   Azure HSMs (FIPS 140-2 L3)        │
│   - Remote signing operations       │
└─────────────────────────────────────┘
```

Key design principles:
- **Service-level config**: Endpoint, profile, and credential stored once
- **Per-operation context**: New AzSignContext created for each signing operation
- **Remote operations**: All signing happens in Azure HSMs
- **Certificate management**: Automatic chain building
- **Thread-safe**: Can be used across multiple operations
- **Disposable**: Proper resource cleanup per operation

## Supported Algorithms

| Algorithm | Support | Notes |
|-----------|---------|-------|
| RSA       | ✅ Yes  | RSA-PSS and PKCS#1 v1.5 |
| ECDSA     | ✅ Yes  | P-256, P-384, P-521 |
| ML-DSA    | ❌ No   | Post-quantum support coming in future Azure releases |

## Error Handling

```csharp
try
{
    var message = await factory.CreateCoseSign1MessageAsync(payload);
}
catch (InvalidOperationException ex) when (ex.Message.Contains("certificate chain"))
{
    // Azure Trusted Signing configuration issue
    Console.WriteLine("Check Azure Trusted Signing certificate profile");
}
catch (NotSupportedException ex) when (ex.Message.Contains("ML-DSA"))
{
    // Algorithm not supported by Azure Trusted Signing
    Console.WriteLine("Azure Trusted Signing does not support this algorithm yet");
}
```

## Configuration Options

### Custom Chain Builder

Provide a custom certificate chain builder:

```csharp
using CoseSign1.Certificates.ChainBuilders;

var chainBuilder = new CustomChainBuilder();
var signingService = new AzureTrustedSigningService(
    signContext,
    chainBuilder: chainBuilder);
```

### Service Metadata

Customize service metadata for logging or auditing:

```csharp
var metadata = new SigningServiceMetadata(
    name: "Production Azure Signing",
    description: "Production signing with audit trail",
    additionalMetadata: new Dictionary<string, object>
    {
        ["Environment"] = "Production",
        ["Owner"] = "SecurityTeam@example.com"
    });

var signingService = new AzureTrustedSigningService(
    signContext,
    serviceMetadata: metadata);
```

## Best Practices

1. **Reuse Service Instances**: `AzureTrustedSigningService` is thread-safe and can be reused across operations
2. **Per-Operation Contexts**: `AzSignContext` is created per signing operation automatically
3. **Dispose Properly**: Always dispose of the service when done (disposes per-operation resources)
4. **Cache Credentials**: Reuse `TokenCredential` instances (e.g., `DefaultAzureCredential`)
5. **Monitor Costs**: Each signing operation calls Azure Trusted Signing APIs
6. **Use SCITT**: Enable SCITT compliance for supply chain security

## Migration from V1

V1 pattern (two-step):
```csharp
// V1: Create context
var signContext = new AzSignContext(
    endpointUrl: "https://your-account.azure-trusted-signing.net",
    certProfileName: "YourCertificateProfile",
    tokenCredential: new DefaultAzureCredential());

// V1: Get key provider
var keyProvider = new AzureTrustedSigningCoseSigningKeyProvider(signContext);

// V1: Sign
var signer = new CoseSign1MessageFactory(keyProvider);
var message = signer.CreateCoseSign1Message(payload);
```

V2 pattern (integrated):
```csharp
// V2: Create signing service (reusable, creates contexts per operation)
using var signingService = new AzureTrustedSigningService(
    "https://your-account.azure-trusted-signing.net",
    "YourCertificateProfile",
    new DefaultAzureCredential());

// V2: Create factory and sign
var factory = new DirectSignatureFactory(signingService);
var message = await factory.CreateCoseSign1MessageAsync(payload);

// Bonus: Add transparency in single call
var factory = new DirectSignatureFactory(
    signingService,
    transparencyProviders: new[] { mstProvider });
var message = await factory.CreateCoseSign1MessageAsync(payload);
```

Key improvements in V2:
- Service stores configuration, creates contexts per operation (better resource management)
- Single-call pattern for signed + transparent messages
- Cleaner separation of concerns
- Better async support
- Integrated transparency support
- SCITT compliance built-in

## Related Packages

- `CoseSign1.Abstractions`: Core V2 interfaces
- `CoseSign1.Certificates`: Certificate-based signing foundation
- `CoseSign1`: Direct and indirect signature factories
- `CoseSign1.Transparent.MST`: Microsoft Signing Transparency
- `DIDx509`: DID:X509 identifier generation and validation

## Links

- [Azure Trusted Signing Documentation](https://learn.microsoft.com/azure/trusted-signing/)
- [DID:X509 Specification](https://github.com/microsoft/did-x509/blob/main/specification.md)
- [SCITT Architecture](https://datatracker.ietf.org/doc/draft-ietf-scitt-architecture/)
- [COSE RFC 9052](https://datatracker.ietf.org/doc/rfc9052/)

## License

Copyright (c) Microsoft Corporation. Licensed under the MIT License.
