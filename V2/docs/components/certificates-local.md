# CoseSign1.Certificates.Local

**Package**: `CoseSign1.Certificates.Local`  
**Purpose**: Ephemeral certificate generation and local cryptographic key management

## Overview

`CoseSign1.Certificates.Local` provides a comprehensive framework for generating ephemeral (in-memory) X.509 certificates and managing cryptographic keys locally. It supports RSA, ECDSA, and post-quantum ML-DSA algorithms, making it ideal for testing, development, and scenarios requiring on-the-fly certificate generation.

## Key Features

- **Ephemeral Certificate Generation**: Create certificates entirely in memory
- **Certificate Chain Factory**: Generate complete certificate hierarchies (Root → Intermediate → Leaf)
- **Multi-Algorithm Support**: RSA, ECDSA, and ML-DSA (post-quantum)
- **Fluent API**: Intuitive builder pattern for certificate configuration
- **Key Provider Abstraction**: Extensible key generation architecture

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                 CoseSign1.Certificates.Local                │
├─────────────────────────────────────────────────────────────┤
│  ┌─────────────────────┐  ┌─────────────────────────────┐  │
│  │ EphemeralCertificate│  │   CertificateChainFactory   │  │
│  │      Factory        │  │                             │  │
│  │                     │  │  Root → Intermediate → Leaf │  │
│  └─────────┬───────────┘  └─────────────┬───────────────┘  │
│            │                            │                   │
│            └──────────┬─────────────────┘                   │
│                       ▼                                     │
│  ┌─────────────────────────────────────────────────────┐   │
│  │              IPrivateKeyProvider                     │   │
│  │         (SoftwareKeyProvider default)                │   │
│  └─────────────────────┬───────────────────────────────┘   │
│                        ▼                                    │
│  ┌──────────────┐ ┌──────────────┐ ┌────────────────────┐  │
│  │RsaGeneratedKey│ │EcdsaGenerated│ │ MldsaGeneratedKey  │  │
│  │              │ │    Key       │ │   (Post-Quantum)   │  │
│  └──────────────┘ └──────────────┘ └────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
```

## Core Components

### EphemeralCertificateFactory

The primary factory for creating single certificates with configurable options.

```csharp
using CoseSign1.Certificates.Local;

// Create factory with default software key provider
var factory = new EphemeralCertificateFactory();

// Create certificate with defaults (RSA-2048, 1 year validity)
using var cert = factory.CreateCertificate();

// Create certificate with custom options
using var cert = factory.CreateCertificate(options => options
    .WithSubjectName("CN=My Certificate, O=My Organization")
    .WithKeyAlgorithm(KeyAlgorithm.ECDSA)
    .WithKeySize(384)
    .WithValidity(TimeSpan.FromDays(365))
    .WithHashAlgorithm(CertificateHashAlgorithm.SHA384)
    .ForCodeSigning());
```

### CertificateChainFactory

Creates complete certificate chains with proper issuer relationships.

```csharp
using CoseSign1.Certificates.Local;

var factory = new CertificateChainFactory();

// Create default 3-tier chain (Root → Intermediate → Leaf)
var chain = factory.CreateChain();

// Create 2-tier chain (Root → Leaf, no intermediate)
var chain = factory.CreateChain(options => options.WithoutIntermediate());

// Create chain with custom configuration
var chain = factory.CreateChain(options => options
    .WithRootName("CN=My Root CA")
    .WithIntermediateName("CN=My Intermediate CA")
    .WithLeafName("CN=My Signing Certificate")
    .WithKeyAlgorithm(KeyAlgorithm.ECDSA)
    .WithKeySize(384)
    .WithValidity(
        rootValidity: TimeSpan.FromDays(3650),
        intermediateValidity: TimeSpan.FromDays(1825),
        leafValidity: TimeSpan.FromDays(365))
    .WithLeafEkus("1.3.6.1.5.5.7.3.3")); // CodeSigning
```

### IPrivateKeyProvider

Abstraction for key generation, enabling custom key providers (HSM, TPM, etc.).

```csharp
public interface IPrivateKeyProvider
{
    string ProviderName { get; }
    bool SupportsAlgorithm(KeyAlgorithm algorithm);
    IGeneratedKey GenerateKey(KeyAlgorithm algorithm, int? keySize = null);
    Task<IGeneratedKey> GenerateKeyAsync(KeyAlgorithm algorithm, int? keySize = null, CancellationToken cancellationToken = default);
}
```

### SoftwareKeyProvider

Default implementation generating keys in software memory.

```csharp
var keyProvider = new SoftwareKeyProvider();

// Check algorithm support
bool supportsRsa = keyProvider.SupportsAlgorithm(KeyAlgorithm.RSA);      // true
bool supportsEcdsa = keyProvider.SupportsAlgorithm(KeyAlgorithm.ECDSA);  // true
bool supportsMldsa = keyProvider.SupportsAlgorithm(KeyAlgorithm.MLDSA);  // true

// Generate keys
using var rsaKey = keyProvider.GenerateKey(KeyAlgorithm.RSA, 4096);
using var ecdsaKey = keyProvider.GenerateKey(KeyAlgorithm.ECDSA, 384);
using var mldsaKey = keyProvider.GenerateKey(KeyAlgorithm.MLDSA, 65);
```

## Supported Algorithms

### Key Algorithms

| Algorithm | Enum Value | Key Sizes | Description |
|-----------|------------|-----------|-------------|
| RSA | `KeyAlgorithm.RSA` | 1024-16384 | RSA with RSASSA-PSS |
| ECDSA | `KeyAlgorithm.ECDSA` | 256, 384, 521 | ECDSA with NIST curves |
| ML-DSA | `KeyAlgorithm.MLDSA` | 44, 65, 87 | Post-quantum (FIPS 204) |

### Hash Algorithms

| Algorithm | Enum Value | Usage |
|-----------|------------|-------|
| SHA-256 | `CertificateHashAlgorithm.SHA256` | Default, good for most uses |
| SHA-384 | `CertificateHashAlgorithm.SHA384` | Higher security |
| SHA-512 | `CertificateHashAlgorithm.SHA512` | Maximum security |

## Certificate Options

### CertificateOptions Extensions

```csharp
// Subject and identity
.WithSubjectName("CN=Name, O=Org, C=US")

// Key configuration
.WithKeyAlgorithm(KeyAlgorithm.RSA)
.WithKeySize(4096)
.WithHashAlgorithm(CertificateHashAlgorithm.SHA384)

// Validity period
.WithValidity(TimeSpan.FromDays(365))
.WithNotBeforeOffset(TimeSpan.FromMinutes(-5)) // Clock skew tolerance

// CA configuration
.AsCertificateAuthority(pathLengthConstraint: 1)

// Key usage
.WithKeyUsage(X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment)

// Enhanced Key Usage (EKU)
.WithEnhancedKeyUsages("1.3.6.1.5.5.7.3.3")
.ForCodeSigning()           // Shorthand for code signing EKU
.ForTlsAuthentication()     // Server + Client auth EKUs
.WithLifetimeSigning()      // Microsoft lifetime signing EKU

// Subject Alternative Names (SAN)
.WithDnsSan("example.com")
.WithEmailSan("admin@example.com")
.WithUriSan("https://example.com")

// Chain relationship
.SignedBy(issuerCertificate)

// Custom extensions
.WithExtension(customExtension)
```

### CertificateChainOptions Extensions

```csharp
// Subject names
.WithRootName("CN=Root CA")
.WithIntermediateName("CN=Intermediate CA")
.WithLeafName("CN=Leaf Certificate")
.WithoutIntermediate()  // 2-tier chain

// Algorithm and key size
.WithKeyAlgorithm(KeyAlgorithm.ECDSA)
.WithKeySize(384)

// Validity periods
.WithValidity(
    rootValidity: TimeSpan.FromDays(3650),
    intermediateValidity: TimeSpan.FromDays(1825),
    leafValidity: TimeSpan.FromDays(365))

// Output configuration
.LeafFirstOrder()    // Return chain in leaf-first order
.ForPfxExport()      // Only leaf has private key (for PFX export)

// Leaf EKUs
.WithLeafEkus("1.3.6.1.5.5.7.3.3", "1.3.6.1.4.1.311.10.3.13")
```

## Post-Quantum Cryptography (ML-DSA)

> ⚠️ **Platform Note**: ML-DSA support is currently **Windows only** in .NET 10. Linux and macOS support may be added in future .NET releases.

The library provides full support for ML-DSA (Module Lattice Digital Signature Algorithm) as defined in FIPS 204.

```csharp
// Create ML-DSA certificate
var factory = new EphemeralCertificateFactory();
using var cert = factory.CreateCertificate(options => options
    .WithSubjectName("CN=Post-Quantum Signer")
    .WithKeyAlgorithm(KeyAlgorithm.MLDSA)
    .WithKeySize(65));  // ML-DSA-65

// Create ML-DSA chain
var chainFactory = new CertificateChainFactory();
var chain = chainFactory.CreateChain(options => options
    .WithKeyAlgorithm(KeyAlgorithm.MLDSA)
    .WithKeySize(87));  // ML-DSA-87 for higher security
```

### ML-DSA Parameter Sets

| Parameter Set | Security Level | OID |
|--------------|----------------|-----|
| ML-DSA-44 | NIST Level 2 | 2.16.840.1.101.3.4.3.17 |
| ML-DSA-65 | NIST Level 3 | 2.16.840.1.101.3.4.3.18 |
| ML-DSA-87 | NIST Level 5 | 2.16.840.1.101.3.4.3.19 |

### MLDsaCertificateUtils

Utility class for working with ML-DSA certificates:

```csharp
// Check if certificate uses ML-DSA
bool isPqc = MLDsaCertificateUtils.IsMLDsaCertificate(cert);

// Get the parameter set
int? parameterSet = MLDsaCertificateUtils.GetParameterSet(cert); // 44, 65, or 87

// Get algorithm OID
string oid = MLDsaCertificateUtils.GetAlgorithmOid(65); // "2.16.840.1.101.3.4.3.18"
```

## Integration with CoseSignTool

The library is used by `CoseSignTool.Local.Plugin` to provide the `sign-ephemeral` command:

```csharp
// EphemeralSigningCommandProvider uses these factories internally
var signingProvider = new EphemeralSigningCommandProvider();

// Configure via JSON
var config = EphemeralCertificateConfig.LoadFromFile("config.json");

// Or configure programmatically
signingProvider.Initialize(options =>
{
    options["algorithm"] = "MLDSA";
    options["key-size"] = "65";
    options["subject"] = "CN=Test Signer";
});
```

## Testing Support

The library is designed for testing scenarios:

```csharp
// In test setup
var factory = new EphemeralCertificateFactory();
using var testCert = factory.CreateCertificate(o => o
    .WithSubjectName("CN=Test Certificate")
    .WithValidity(TimeSpan.FromHours(1)));

// Use for signing tests
var signingKey = new CertificateSigningKey(testCert);
```

## Thread Safety

- `EphemeralCertificateFactory` is thread-safe for concurrent certificate creation
- `CertificateChainFactory` is thread-safe
- `SoftwareKeyProvider` is thread-safe
- Generated keys (`IGeneratedKey`) should be disposed after use

## Performance Considerations

1. **Key Generation**: ML-DSA key generation is slower than RSA/ECDSA
2. **Chain Creation**: Creates 3 certificates; use `WithoutIntermediate()` for faster 2-tier chains
3. **Memory**: All keys are held in memory; dispose certificates when done
4. **Caching**: Consider caching chains for repeated test scenarios

## Security Notes

⚠️ **Important**: Certificates generated by this library are for testing and development only:

1. Keys exist only in memory and cannot be recovered
2. Certificate chains are not published to any trust store
3. Signatures cannot be verified by external parties
4. Do NOT use for production signing

For production scenarios, use:
- `CoseSignTool.Local.Plugin` with real certificates
- `CoseSignTool.AzureTrustedSigning.Plugin` for cloud-based signing
- Hardware Security Modules (HSM) for key protection

## Dependencies

- `System.Security.Cryptography.X509Certificates`
- `System.Security.Cryptography.Cose`
- `Microsoft.Extensions.Logging.Abstractions`
