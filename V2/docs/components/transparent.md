# CoseSign1.Transparent

Transparency service abstractions and provider interfaces for CoseSignTool V2.

## Overview

CoseSign1.Transparent provides the core abstractions for integrating COSE signatures with transparency services. Transparency services enable public auditability of signed artifacts by publishing cryptographic commitments to append-only logs.

## Installation

```bash
dotnet add package CoseSign1.Transparent --version 2.0.0-preview
```

## Key Concepts

### Transparency Services

Transparency services (also known as "notaries" or "transparency logs") provide:

- **Append-Only Logs** - Immutable record of signed artifacts
- **Public Auditability** - Anyone can verify inclusion
- **Non-Repudiation** - Signers cannot deny publishing
- **Tamper Evidence** - Any modification is detectable

### Transparency Receipts

When a signature is submitted to a transparency service, it returns a "receipt" that:

1. Proves the signature was included in the log
2. Contains a timestamp from the service
3. Is signed by the transparency service
4. Can be embedded in the COSE signature headers

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                  CoseSign1.Transparent                   │
│                    (Abstractions)                        │
├─────────────────────────────────────────────────────────┤
│  ITransparencyProvider                                   │
│  ITransparencyReceipt                                    │
│  TransparencyOptions                                     │
└─────────────────────────────────────────────────────────┘
                            │
           ┌────────────────┼────────────────┐
           ▼                ▼                ▼
┌──────────────────┐ ┌──────────────────┐ ┌──────────────────┐
│ CoseSign1.       │ │ CoseSign1.       │ │   Custom         │
│ Transparent.MST  │ │ Transparent.CTS  │ │   Provider       │
└──────────────────┘ └──────────────────┘ └──────────────────┘
```

## ITransparencyProvider Interface

The core interface for transparency service integration:

```csharp
public interface ITransparencyProvider
{
    /// <summary>
    /// Gets or creates a transparency receipt for the given COSE signature.
    /// </summary>
    Task<ITransparencyReceipt> GetReceiptAsync(
        byte[] coseSignature,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Verifies that a signature has a valid transparency receipt.
    /// </summary>
    Task<bool> VerifyReceiptAsync(
        byte[] coseSignature,
        ITransparencyReceipt receipt,
        CancellationToken cancellationToken = default);
}
```

## ITransparencyReceipt Interface

Represents a receipt from a transparency service:

```csharp
public interface ITransparencyReceipt
{
    /// <summary>
    /// The raw receipt bytes (service-specific format).
    /// </summary>
    byte[] ReceiptBytes { get; }

    /// <summary>
    /// When the receipt was issued.
    /// </summary>
    DateTimeOffset Timestamp { get; }

    /// <summary>
    /// The transparency service that issued the receipt.
    /// </summary>
    string ServiceIdentifier { get; }
}
```

## Available Implementations

### Microsoft's Signing Transparency (MST)

Microsoft's Signing Transparency service for signed artifacts:

```csharp
using CoseSign1.Transparent.MST;

var provider = new MstTransparencyProvider(options);
```

See [MST Documentation](mst.md) for details.

### SCITT-compatible Services

The CodeTransparency (CTS) implementation supports SCITT-compatible services:

```csharp
using CoseSign1.Transparent.CTS;

var provider = new CtsTransparencyProvider(options);
```

## Usage with Signatures

### Adding Transparency During Signing

```csharp
var factory = new DirectSignatureFactory(signingService);
var signature = factory.CreateCoseSign1MessageBytes(payload);

// Add transparency
var provider = new MstTransparencyProvider(options);
var receipt = await provider.GetReceiptAsync(signature);

// Receipt can be stored with or embedded in the signature
```

### Verifying Transparency

```csharp
// Verify signature has valid transparency receipt
var isTransparent = await provider.VerifyReceiptAsync(signature, receipt);
```

## Custom Provider Implementation

To implement a custom transparency provider:

```csharp
public class MyTransparencyProvider : ITransparencyProvider
{
    public async Task<ITransparencyReceipt> GetReceiptAsync(
        byte[] coseSignature,
        CancellationToken cancellationToken = default)
    {
        // Submit to your transparency service
        // Return receipt
    }

    public async Task<bool> VerifyReceiptAsync(
        byte[] coseSignature,
        ITransparencyReceipt receipt,
        CancellationToken cancellationToken = default)
    {
        // Verify receipt against your service
    }
}
```

## See Also

- [MST Component](mst.md)
- [SCITT Compliance Guide](../guides/scitt-compliance.md)
- [Validation Framework](../architecture/validation-framework.md)
