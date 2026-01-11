# Detached Signatures Guide

This guide explains detached signatures in CoseSignTool V2.

## Overview

A detached signature is a COSE signature where the payload is not embedded in the signature structure. Instead, the payload field in the COSE structure is `nil`, and the original payload must be provided separately during verification.

> **Important:** Unlike indirect signatures, detached signatures **require the original payload to verify the signature itself**. This is because the payload is part of the data that was signed—it's just not stored in the signature file. Without the payload, signature verification will fail.

## When to Use Detached Signatures

| Use Case | Reason |
|----------|--------|
| Existing files | Don't want to modify or wrap the original file |
| Large files | Avoid duplicating payload in signature |
| Separate storage | Store signature independently from data |
| Multiple signatures | Different parties sign the same payload |

## Creating Detached Signatures

### Programmatic API

```csharp
using CoseSign1.Factories;
using CoseSign1.Factories.Direct;

using var factory = new CoseSign1MessageFactory(signingService);

// Create detached signature
byte[] signature = factory.CreateCoseSign1MessageBytes(
    payload,
    "application/json",
    new DirectSignatureOptions { EmbedPayload = false });

// Save signature separately from payload
await File.WriteAllBytesAsync("document.json.sig", signature);
```

### CLI Usage

```bash
# Create detached signature
CoseSignTool sign-pfx document.json ^
    --pfx cert.pfx ^
    --signature-type detached ^
    --output document.json.sig
```

## Verifying Detached Signatures

> **Note:** The payload is **required** to verify a detached signature. Without it, the cryptographic signature cannot be validated because the payload was part of the signed data.

### Programmatic API

```csharp
using CoseSign1.Certificates.Validation;
using System.Security.Cryptography.Cose;

// Load signature and payload separately
var signature = await File.ReadAllBytesAsync("document.json.sig");
var payload = await File.ReadAllBytesAsync("document.json");

// Payload is REQUIRED - it's part of the signed data
var message = CoseMessage.DecodeSign1(signature);
var result = message.Validate(builder => builder
    .WithOptions(o => o.WithDetachedPayload(payload))
    .ValidateCertificate(cert => cert.ValidateChain()));

if (result.Overall.IsValid)
{
    Console.WriteLine("Signature verified for provided payload");
}
```

### CLI Usage

```bash
# Verify detached signature
CoseSignTool verify document.json.sig --payload document.json
```

## Detached vs Embedded Comparison

```
┌─────────────────────────────────────────────────────────────┐
│                   Embedded Signature                        │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  ┌─────────────────────────────────────────────────────┐    │
│  │                   COSE_Sign1                        │    │
│  │  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐    │    │
│  │  │  Protected  │ │ Unprotected │ │   Payload   │    │    │
│  │  │  Headers    │ │  Headers    │ │   (Data)    │    │    │
│  │  └─────────────┘ └─────────────┘ └─────────────┘    │    │
│  └─────────────────────────────────────────────────────┘    │
│                                                             │
└─────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────┐
│                   Detached Signature                        │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  ┌──────────────────────────┐    ┌──────────────────────┐   │
│  │       COSE_Sign1         │    │      Payload         │   │
│  │  ┌─────────┐ ┌─────────┐ │    │      (Data)          │   │
│  │  │Protected│ │Unprot.  │ │    │    (Separate)        │   │
│  │  │Headers  │ │Headers  │ │    │                      │   │
│  │  └─────────┘ └─────────┘ │    │                      │   │
│  │  (nil payload)           │    │                      │   │
│  └──────────────────────────┘    └──────────────────────┘   │
│           ▲                               │                 │
│           └───────── Linked ──────────────┘                 │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

## COSE Structure

### Embedded Payload

```
COSE_Sign1 = [
    protected,      ; Protected headers
    unprotected,    ; Unprotected headers
    payload,        ; Actual payload bytes
    signature       ; Signature value
]
```

### Detached Payload

```
COSE_Sign1 = [
    protected,      ; Protected headers
    unprotected,    ; Unprotected headers
    nil,            ; Payload is nil (not included)
    signature       ; Signature value
]
```

## Signature File Conventions

Common conventions for detached signature files:

| Original File | Signature File |
|--------------|----------------|
| `document.json` | `document.json.sig` |
| `package.tar.gz` | `package.tar.gz.cose` |
| `image.png` | `image.png.cose-sig` |

## Multiple Signatures

Detached signatures enable multiple parties to sign the same payload:

```bash
# Developer signs
CoseSignTool sign-pfx artifact.bin ^
    --pfx developer.pfx ^
    --signature-type detached ^
    --output artifact.bin.dev-sig

# QA signs
CoseSignTool sign-pfx artifact.bin ^
    --pfx qa.pfx ^
    --signature-type detached ^
    --output artifact.bin.qa-sig

# Security signs
CoseSignTool sign-pfx artifact.bin ^
    --pfx security.pfx ^
    --signature-type detached ^
    --output artifact.bin.sec-sig
```

Verify all signatures:

```bash
CoseSignTool verify artifact.bin.dev-sig --payload artifact.bin
CoseSignTool verify artifact.bin.qa-sig --payload artifact.bin
CoseSignTool verify artifact.bin.sec-sig --payload artifact.bin
```

## Content Type Binding

The content type header binds the signature to a specific interpretation:

```csharp
// Sign JSON document
var jsonSig = factory.CreateCoseSign1MessageBytes(
    jsonPayload,
    "application/json",
    new DirectSignatureOptions { EmbedPayload = false });

// Sign binary data
var binSig = factory.CreateCoseSign1MessageBytes(
    binaryPayload,
    "application/octet-stream",
    new DirectSignatureOptions { EmbedPayload = false });
```

## Streaming Verification

Detached signatures require the payload bytes to verify. If you need a streaming-friendly workflow for large files, use indirect signatures.

```csharp
using CoseSign1.Certificates.Extensions;
using System.Security.Cryptography.Cose;

// Load signature + payload
var signatureBytes = File.ReadAllBytes("large-file.bin.sig");
var payloadBytes = File.ReadAllBytes("large-file.bin");

var message = CoseMessage.DecodeSign1(signatureBytes);
bool isValid = message.VerifySignature(payloadBytes);
```

## Security Considerations

### Payload Binding

The signature is bound to:
- **Payload content** - Any modification invalidates signature
- **Content type** - Verifier should check expected content type
- **Protected headers** - Algorithm, key ID, etc.

### Payload Availability

During verification:
- Payload must be available and accessible
- Payload path/location must be known
- Payload integrity relies on signature verification

### Time-of-Check vs Time-of-Use

Be careful about TOCTOU issues:

```csharp
using CoseSign1.Certificates.Extensions;
using System.Security.Cryptography.Cose;

var message = CoseMessage.DecodeSign1(signature);

// ❌ Bad: Read payload, verify, then use different read
var payload1 = File.ReadAllBytes(path); // For verification
bool ok1 = message.VerifySignature(payload1);
var payload2 = File.ReadAllBytes(path); // For use - might differ!

// ✅ Good: Read once, verify, use same bytes
var payload = File.ReadAllBytes(path);
bool ok = message.VerifySignature(payload);
// Use 'payload' variable, not another read
```

## Error Handling

### Missing Payload

```csharp
using CoseSign1.Certificates.Extensions;
using System.Security.Cryptography.Cose;

var message = CoseMessage.DecodeSign1(detachedSignature);

// For detached signatures, the payload is required. Without it, verification returns false.
if (!message.VerifySignature(payload: null))
{
    Console.Error.WriteLine("Payload required for detached signature verification");
}
```

### Payload Mismatch

```csharp
using CoseSign1.Certificates.Extensions;
using System.Security.Cryptography.Cose;

var message = CoseMessage.DecodeSign1(signature);
bool ok = message.VerifySignature(wrongPayload);
if (!ok)
{
    Console.Error.WriteLine("Provided payload does not match signed content");
}
```

## Best Practices

1. **Use consistent naming** - Establish conventions for signature file names
2. **Include content type** - Always specify content type header
3. **Verify before use** - Always verify signature before trusting payload
4. **Handle missing payloads** - Gracefully handle verification without payload
5. **Document relationships** - Document which signatures go with which payloads

## See Also

- [Direct vs Indirect Signatures](direct-vs-indirect.md)
- [Validation Framework](../architecture/validation-framework.md)
- [CLI Reference](../cli/README.md)
