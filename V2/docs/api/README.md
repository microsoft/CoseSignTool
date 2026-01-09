# API Reference

This section provides API reference documentation for the CoseSignTool V2 libraries.

## Core Packages

### CoseSign1.Abstractions

Core interfaces and types for COSE signing operations.

| Type | Description |
|------|-------------|
| `ISigningService<TSigningOptions>` | Signing service abstraction that produces `CoseSigner` instances |
| `IHeaderContributor` | Interface for adding headers to signatures |
| `SigningOptions` | Base per-operation options (headers, AAD, transparency toggles) |
| `CoseSign1.Abstractions.Transparency.ITransparencyProvider` | Transparency provider abstraction |

### CoseSign1

Direct signature implementation.

| Type | Description |
|------|-------------|
| `DirectSignatureFactory` | Creates COSE_Sign1 messages via direct signing |
| `IndirectSignatureFactory` | Creates COSE hash-envelope (indirect) signatures |
| `CoseSign1MessageFactory` | Routes to the correct factory based on options |
| `System.Security.Cryptography.Cose.CoseSign1Message` | COSE_Sign1 message type used across V2 |

Indirect signing is implemented in the `CoseSign1` package under the `CoseSign1.Indirect` namespace.

## Certificate Packages

### CoseSign1.Certificates

Certificate management and chain building.

| Type | Description |
|------|-------------|
| `CertificateSigningService` | Signing with certificates (local or remote sources) |
| `X509ChainBuilder` | Helper for building chains using `X509ChainPolicy` |

### CoseSign1.Certificates.AzureTrustedSigning

Azure Trusted Signing integration.

| Type | Description |
|------|-------------|
| `AzureTrustedSigningService` | Azure signing service |
| `AzureTrustedSigningOptions` | Configuration options |

## Transparency Packages

### CoseSign1.Transparent.MST

Microsoft's Signing Transparency integration.

| Type | Description |
|------|-------------|
| `MstTransparencyProvider` | MST provider implementation |
| `CodeTransparencyVerifierAdapter` | Adapter for verifying receipts with Code Transparency |

## Header Packages

### CoseSign1.Headers

Header contribution and management.

| Type | Description |
|------|-------------|
| `CwtClaimsHeaderContributor` | Adds CWT claims to headers |
| `CertificateHeaderContributor` | Adds certificates to headers |

## Validation

### CoseSign1.Validation

| Type | Description |
|------|-------------|
| `Cose.Sign1Message()` | Entry point for building staged validators |
| `ICoseSign1Validator` | Validates a `CoseSign1Message` and returns staged results |
| `CoseSign1ValidationResult` | Staged results: Resolution, Trust, Signature, PostSignaturePolicy, Overall |
| `ValidationResult` | Per-stage result (Success/Failure/NotApplicable + metadata) |
| `ValidationStage` | Stage identifiers used by orchestration/validators |

## COSE Algorithm Identifiers

V2 primarily uses integer COSE algorithm identifiers (per the IANA COSE registry) in places like metadata and some header contributors.

Common values used by V2:

| Algorithm | COSE ID |
|----------|---------|
| ES256 | -7 |
| ES384 | -35 |
| ES512 | -36 |
| PS256 | -37 |
| PS384 | -38 |
| PS512 | -39 |

When working directly with .NET COSE signing/verification APIs, use `System.Security.Cryptography.Cose.CoseAlgorithm` and related types.

## Common Patterns

### Creating a Signature

```csharp
using CoseSign1.Certificates;
using CoseSign1.Certificates.ChainBuilders;
using CoseSign1.Direct;

// 1. Create signing service
using var chainBuilder = new X509ChainBuilder();
using var service = CertificateSigningService.Create(certificate, chainBuilder);

// 2. Create factory
var factory = new DirectSignatureFactory(service);

// 3. Sign
byte[] signature = factory.CreateCoseSign1MessageBytes(payload, contentType);
```

### Validating a Signature

```csharp
using CoseSign1.Validation;
using System.Security.Cryptography.Cose;

// 1. Decode COSE
var message = CoseSign1Message.DecodeSign1(signature);

// 2. Build validator
var validator = Cose.Sign1Message()
    .ValidateCertificate(cert => cert
        .ValidateChain())
    .Build();

// 3. Validate
var result = message.Validate(validator);

// 4. Check result
if (result.Overall.IsValid)
{
    // Signature is valid
}
```

### Adding Custom Headers

```csharp
// 1. Create contributor
public class MyHeaderContributor : IHeaderContributor
{
    public HeaderMergeStrategy MergeStrategy => HeaderMergeStrategy.Fail;
    
    public void ContributeProtectedHeaders(CoseHeaderMap headers, HeaderContributorContext context)
    {
        headers.Add(new CoseHeaderLabel("my-header"), "value");
    }
    
    public void ContributeUnprotectedHeaders(CoseHeaderMap headers, HeaderContributorContext context)
    {
        // Add unprotected headers if needed
    }
}

// 2. Use with factory
var options = new DirectSignatureOptions
{
    AdditionalHeaderContributors = new[] { new MyHeaderContributor() }
};

byte[] signature = factory.CreateCoseSign1MessageBytes(payload, contentType, options);
```

## See Also

- [Architecture Overview](../architecture/)
- [Getting Started](../getting-started/quick-start.md)
- [Guides](../guides/)
