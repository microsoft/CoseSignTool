# API Reference

This section provides API reference documentation for CoseSignTool V2 packages.

## Core Packages

### CoseSign1.Abstractions

Core interfaces and types for COSE signing operations.

| Type | Description |
|------|-------------|
| `ISigningService` | Interface for signing operations |
| `IValidator` | Interface for signature validation |
| `IHeaderContributor` | Interface for adding headers to signatures |
| `CoseAlgorithm` | COSE algorithm identifiers |
| `ValidationResult` | Result of validation operations |

### CoseSign1

Direct signature implementation.

| Type | Description |
|------|-------------|
| `DirectSignatureFactory` | Creates COSE_Sign1 messages |
| `CoseSign1MessageReader` | Reads and parses COSE_Sign1 messages |

### CoseIndirectSignature

Indirect (hash envelope) signature implementation.

| Type | Description |
|------|-------------|
| `IndirectSignatureFactory` | Creates indirect signatures |
| `CoseHashEnvelope` | Hash envelope payload structure |

## Certificate Packages

### CoseSign1.Certificates

Certificate management and chain building.

| Type | Description |
|------|-------------|
| `CertificateChainBuilder` | Builds certificate chains |
| `ICertificateSource` | Interface for certificate sources |
| `LocalSigningService` | Signing with local certificates |

### CoseSign1.Certificates.AzureTrustedSigning

Azure Trusted Signing integration.

| Type | Description |
|------|-------------|
| `AzureTrustedSigningService` | Azure signing service |
| `AzureTrustedSigningOptions` | Configuration options |

## Transparency Packages

### CoseSign1.Transparent

Transparency service abstractions.

| Type | Description |
|------|-------------|
| `ITransparencyProvider` | Interface for transparency services |
| `ITransparencyReceipt` | Transparency receipt interface |

### CoseSign1.Transparent.MST

Microsoft's Signing Transparency integration.

| Type | Description |
|------|-------------|
| `MstTransparencyProvider` | MST provider implementation |
| `MstOptions` | MST configuration options |

## Header Packages

### CoseSign1.Headers

Header contribution and management.

| Type | Description |
|------|-------------|
| `CwtClaimsHeaderContributor` | Adds CWT claims to headers |
| `CertificateHeaderContributor` | Adds certificates to headers |

## Validation Types

### ValidationResult

```csharp
public class ValidationResult
{
    public bool IsValid { get; }
    public IReadOnlyList<ValidationError> Errors { get; }
    
    public static ValidationResult Success();
    public static ValidationResult Failure(string message);
    public static ValidationResult Failure(ValidationFailureCode code, string message);
}
```

### ValidationFailureCode

```csharp
public enum ValidationFailureCode
{
    None,
    SignatureMismatch,
    CertificateExpired,
    CertificateRevoked,
    ChainBuildFailed,
    UntrustedRoot,
    InvalidAlgorithm,
    MissingRequiredHeader,
    PayloadMismatch,
    // ... additional codes
}
```

## Algorithm Constants

### CoseAlgorithm

```csharp
public static class CoseAlgorithm
{
    // ECDSA
    public const int ES256 = -7;   // ECDSA w/ SHA-256
    public const int ES384 = -35;  // ECDSA w/ SHA-384
    public const int ES512 = -36;  // ECDSA w/ SHA-512
    
    // RSA-PSS
    public const int PS256 = -37;  // RSASSA-PSS w/ SHA-256
    public const int PS384 = -38;  // RSASSA-PSS w/ SHA-384
    public const int PS512 = -39;  // RSASSA-PSS w/ SHA-512
    
    // ML-DSA (Windows only)
    public const int MlDsa44 = -48;
    public const int MlDsa65 = -49;
    public const int MlDsa87 = -50;
}
```

## Common Patterns

### Creating a Signature

```csharp
// 1. Create signing service
ISigningService service = new LocalSigningService(certificate);

// 2. Create factory
var factory = new DirectSignatureFactory(service);

// 3. Sign
byte[] signature = factory.CreateCoseSign1MessageBytes(payload, contentType);
```

### Validating a Signature

```csharp
// 1. Build validator
var validator = ValidationBuilder.Create()
    .AddSignatureValidator()
    .AddCertificateChainValidator()
    .Build();

// 2. Validate
var result = await validator.ValidateAsync(signature);

// 3. Check result
if (result.IsValid)
{
    // Signature is valid
}
```

### Adding Custom Headers

```csharp
// 1. Create contributor
public class MyHeaderContributor : IHeaderContributor
{
    public int Order => 50;
    
    public void ContributeProtectedHeaders(CoseHeaderMap headers, HeaderContext context)
    {
        headers.Add(new CoseHeaderLabel("my-header"), "value");
    }
    
    public void ContributeUnprotectedHeaders(CoseHeaderMap headers, HeaderContext context)
    {
        // Add unprotected headers if needed
    }
}

// 2. Use with factory
var factory = new DirectSignatureFactory(
    service,
    headerContributors: new[] { new MyHeaderContributor() });
```

## See Also

- [Architecture Overview](../architecture/)
- [Getting Started](../getting-started/quick-start.md)
- [Guides](../guides/)
