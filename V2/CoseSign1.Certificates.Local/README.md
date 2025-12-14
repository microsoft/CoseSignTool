# CoseSign1.Certificates.Local

Extensible local certificate factory for creating ephemeral certificates for signing operations.

## Features

- **Ephemeral Certificates**: Create in-memory certificates for testing and development
- **Multiple Algorithms**: RSA, ECDSA, and ML-DSA (Post-Quantum) support
- **Certificate Chains**: Build complete certificate hierarchies (root → intermediate → leaf)
- **Pluggable Key Providers**: Extension points for TPM, HSM, and Confidential Compute keys
- **Fluent API**: Intuitive builder pattern for certificate configuration

## Quick Start

```csharp
// Create a simple ephemeral certificate
var factory = new EphemeralCertificateFactory();
var cert = factory.CreateCertificate(options => options
    .WithSubjectName("CN=My Test Certificate")
    .WithKeyAlgorithm(KeyAlgorithm.RSA)
    .WithValidity(TimeSpan.FromDays(365)));

// Create a certificate chain
var chainFactory = new CertificateChainFactory();
var chain = chainFactory.CreateChain(options => options
    .WithRootName("CN=Test Root CA")
    .WithIntermediateName("CN=Test Intermediate CA")
    .WithLeafName("CN=Test Leaf")
    .WithKeyAlgorithm(KeyAlgorithm.ECDSA));
```

## Extensibility

### Custom Key Providers

Implement `IPrivateKeyProvider` to use custom key storage:

```csharp
public class TpmKeyProvider : IPrivateKeyProvider
{
    public AsymmetricAlgorithm GenerateKey(KeyAlgorithm algorithm, int? keySize)
    {
        // Generate key in TPM
    }
}

// Use with factory
var factory = new EphemeralCertificateFactory(new TpmKeyProvider());
```

## Supported Algorithms

| Algorithm | Key Sizes | Notes |
|-----------|-----------|-------|
| RSA | 2048, 3072, 4096 | Default: 2048 |
| ECDSA | 256, 384, 521 | Default: 256 |
| ML-DSA | 44, 65, 87 | Post-Quantum (.NET 10+) |

## Related Packages

- `CoseSign1.Certificates` - Certificate-based signing and validation
- `CoseSignTool` - CLI tool with ephemeral signing support
