# CoseSign1.Transparent.MST

Microsoft's Signing Transparency (MST) integration for CoseSignTool V2.

## Overview

CoseSign1.Transparent.MST provides integration with Microsoft's Signing Transparency service, enabling public auditability and non-repudiation for COSE signatures.

## Installation

```bash
dotnet add package CoseSign1.Transparent.MST --version 2.0.0-preview
```

## What is Microsoft's Signing Transparency (MST)?

Microsoft's Signing Transparency (MST) is a transparency service that:

- **Publishes cryptographic commitments** to an append-only log
- **Issues signed receipts** proving inclusion in the log
- **Enables public verification** that artifacts were signed and logged
- **Provides tamper evidence** for signed artifacts

## Quick Start

### Verifying with MST Receipt

```csharp
using CoseSign1.Transparent.MST;

// Configure MST verification options
var mstOptions = new MstOptions
{
    ServiceUri = new Uri("https://mst.microsoft.com"),
    VerifyReceipt = true
};

var provider = new MstTransparencyProvider(mstOptions);

// Verify a signature has a valid MST receipt
bool isValid = await provider.VerifyReceiptAsync(signature, receipt);
```

### CLI Usage

With the MST plugin installed, additional options are available on the `verify` command:

```bash
# Verify signature with MST receipt validation
CoseSignTool verify signed.cose \
    --mst-service-uri https://mst.microsoft.com \
    --verify-mst-receipt

# Verify and require a valid MST receipt
CoseSignTool verify signed.cose \
    --mst-service-uri https://mst.microsoft.com \
    --require-mst-receipt
```

## MstOptions Configuration

| Property | Description | Default |
|----------|-------------|---------|
| `ServiceUri` | MST service endpoint | Required |
| `VerifyReceipt` | Whether to verify receipt signatures | `true` |
| `RequireReceipt` | Fail validation if no receipt present | `false` |
| `TimeoutSeconds` | Request timeout | `30` |

## MST Receipts

### Receipt Structure

MST receipts contain:

- **Inclusion Proof** - Cryptographic proof the signature is in the log
- **Log Timestamp** - When the entry was added to the log
- **Service Signature** - MST's signature over the receipt

### Embedding Receipts

Receipts can be embedded in COSE signature unprotected headers:

```csharp
// Get receipt from MST
var receipt = await provider.GetReceiptAsync(signature);

// Receipt bytes can be added to unprotected headers
// during signature creation or as a counter-signature
```

## Verification Process

When verifying with MST:

1. **Extract Receipt** - Get MST receipt from signature headers
2. **Verify Receipt Signature** - Confirm MST signed the receipt
3. **Verify Inclusion** - Confirm the signature is in the log
4. **Check Timestamp** - Validate receipt timestamp is acceptable

```
┌─────────────────────────────────────────────────────────┐
│                 MST Verification Flow                    │
├─────────────────────────────────────────────────────────┤
│                                                          │
│  COSE Signature ─┬─► Extract Receipt                     │
│                  │                                       │
│                  ▼                                       │
│           Verify Receipt ─► Check MST Signature          │
│                  │                                       │
│                  ▼                                       │
│           Verify Inclusion ─► Validate Merkle Proof      │
│                  │                                       │
│                  ▼                                       │
│           Check Timestamp ─► Within Acceptable Range     │
│                  │                                       │
│                  ▼                                       │
│             ✓ Valid                                      │
│                                                          │
└─────────────────────────────────────────────────────────┘
```

## Integration with Validators

Add MST validation to the validation pipeline:

```csharp
using CoseSign1.Transparent.MST.Validators;

var validator = ValidationBuilder.Create()
    .AddSignatureValidator()
    .AddCertificateChainValidator()
    .AddMstReceiptValidator(mstOptions)
    .Build();

var result = await validator.ValidateAsync(signature);
```

## Security Considerations

- **Trust** - Ensure you trust the MST service endpoint
- **Timestamp Validation** - Consider acceptable timestamp ranges
- **Network Security** - Use HTTPS and validate certificates
- **Caching** - Be cautious about caching receipt verifications

## Error Handling

```csharp
try
{
    var result = await provider.VerifyReceiptAsync(signature, receipt);
}
catch (MstServiceException ex)
{
    // Handle MST service errors
    Console.WriteLine($"MST Error: {ex.Message}");
}
catch (MstReceiptValidationException ex)
{
    // Handle invalid receipt
    Console.WriteLine($"Invalid Receipt: {ex.Message}");
}
```

## See Also

- [Transparency Overview](transparent.md)
- [SCITT Compliance](../guides/scitt-compliance.md)
- [MST Plugin](../plugins/mst-plugin.md)
- [Validation Framework](../architecture/validation-framework.md)
