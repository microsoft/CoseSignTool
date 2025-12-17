# API Reference

This section provides API reference documentation for CoseSignTool V2 packages.

## Core Packages

### CoseSign1.Abstractions

Core interfaces and types for COSE signing operations.

| Type | Description |
|------|-------------|
| `ISigningService<TSigningOptions>` | Interface for signing operations |
| `IValidator<T>` | Interface for validation |
| `IHeaderContributor` | Interface for adding headers to signatures |
| `CoseAlgorithm` | COSE algorithm identifiers |
| `ValidationResult` | Result of validation operations |

### CoseSign1

Direct signature implementation.

| Type | Description |
|------|-------------|
| `DirectSignatureFactory` | Creates COSE_Sign1 messages |
| `CoseMessage.DecodeSign1(...)` | Parses COSE_Sign1 messages (from `System.Security.Cryptography.Cose`) |

### CoseSign1.Indirect

Indirect (hash envelope) signing.

| Type | Description |
|------|-------------|
| `IndirectSignatureFactory` | Creates indirect signatures |
| `CoseHashEnvelopeHeaderContributor` | Adds COSE hash-envelope headers during signing |

## Certificate Packages

### CoseSign1.Certificates

Certificate management and chain building.

| Type | Description |
|------|-------------|
| `ICertificateChainBuilder` | Builds certificate chains |
| `ICertificateSource` | Interface for certificate sources |
| `CertificateSigningService` | Signing with certificates (local or remote sources) |

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
| `CodeTransparencyClient` | Azure Code Transparency client used by MST |

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
public sealed class ValidationResult
{
    public bool IsValid { get; init; }
    public string ValidatorName { get; init; } = string.Empty;
    public IReadOnlyList<ValidationFailure> Failures { get; init; } = Array.Empty<ValidationFailure>();

    public static ValidationResult Success(string validatorName, IDictionary<string, object>? metadata = null);
    public static ValidationResult Failure(string validatorName, params ValidationFailure[] failures);
    public static ValidationResult Failure(string validatorName, string message, string? errorCode = null);
}

public sealed class ValidationFailure
{
    public string Message { get; init; } = string.Empty;
    public string? ErrorCode { get; init; }
    public string? PropertyName { get; init; }
    public object? AttemptedValue { get; init; }
    public Exception? Exception { get; init; }
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
using CoseSign1.Certificates.Validation;
using CoseSign1.Validation;
using System.Security.Cryptography.Cose;

// 1. Decode COSE
var message = CoseMessage.DecodeSign1(signature);

// 2. Build validator
var validator = Cose.Sign1Message()
    .AddCertificateValidator(b => b
        .ValidateSignature()
        .ValidateChain())
    .Build();

// 3. Validate
var result = await validator.ValidateAsync(message);

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
var factory = new DirectSignatureFactory(
    service,
    headerContributors: new[] { new MyHeaderContributor() });
```

## See Also

- [Architecture Overview](../architecture/)
- [Getting Started](../getting-started/quick-start.md)
- [Guides](../guides/)
