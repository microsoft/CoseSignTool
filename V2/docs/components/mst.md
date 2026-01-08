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

### Verifying MST Proofs

```csharp
using Azure.Security.CodeTransparency;
using CoseSign1.Transparent.MST;
using System.Security.Cryptography.Cose;

var client = new CodeTransparencyClient(new Uri("https://dataplane.codetransparency.azure.net"));
var provider = new MstTransparencyProvider(client);

// A CoseSign1Message that already contains an MST receipt in its unprotected headers
CoseSign1Message messageWithReceipt = /* ... */;

var result = await provider.VerifyTransparencyProofAsync(messageWithReceipt);
bool isValid = result.IsValid;
```

### CLI Usage

With the MST plugin installed, additional options are available on the `verify` command:

```bash
# Verify receipt against an MST endpoint
CoseSignTool verify signed.cose \
    --mst-endpoint https://dataplane.codetransparency.azure.net

# Require a receipt to be present (no network call)
CoseSignTool verify signed.cose \
    --require-receipt

# Require a receipt and verify it against an endpoint
CoseSignTool verify signed.cose \
    --require-receipt \
    --mst-endpoint https://dataplane.codetransparency.azure.net
```

## Verification Options

Advanced verification behavior can be configured via `CodeTransparencyVerificationOptions`.

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
using Azure.Security.CodeTransparency;
using CoseSign1.Transparent.MST;
using CoseSign1.Transparent.MST.Validation;
using CoseSign1.Validation;
using System.Security.Cryptography.Cose;

var client = new CodeTransparencyClient(new Uri("https://dataplane.codetransparency.azure.net"));
var provider = new MstTransparencyProvider(client);

var validator = Cose.Sign1Message()
    .AddMstReceiptValidator(b => b.UseProvider(provider))
    .Build();

CoseSign1Message message = /* ... */;
var result = await validator.ValidateAsync(message, ValidationStage.KeyMaterialTrust);
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
    var result = await provider.VerifyTransparencyProofAsync(messageWithReceipt);
}
catch (Azure.RequestFailedException ex)
{
    Console.WriteLine($"MST service error: {ex.Message}");
}
```

## See Also

- [Transparency Overview](transparent.md)
- [SCITT Compliance](../guides/scitt-compliance.md)
- [MST Plugin](../plugins/mst-plugin.md)
- [Validation Framework](../architecture/validation-framework.md)
