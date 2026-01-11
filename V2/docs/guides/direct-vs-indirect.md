# Direct vs Indirect Signatures Guide

This guide explains the difference between direct and indirect signatures in CoseSignTool V2 and when to use each.

## Overview

CoseSignTool V2 supports two signing modes:

- **Direct Signatures** - The payload is included in or bound to the signature
- **Indirect Signatures** - A hash of the payload is signed instead of the payload itself

## Direct Signatures

### How They Work

```
┌─────────────────────────────────────────────────────────────┐
│                    Direct Signature                         │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  ┌────────────────┐                                         │
│  │    Payload     │                                         │
│  │    (Data)      │                                         │
│  └───────┬────────┘                                         │
│          │                                                  │
│          ▼                                                  │
│  ┌────────────────┐    ┌────────────────┐                   │
│  │   Protected    │    │   Private      │                   │
│  │   Headers +    │──▶│     Key        │ ───▶ Signature    │
│  │   Payload      │    └────────────────┘                   │
│  └────────────────┘                                         │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### When to Use

- Small to medium payloads (< 10 MB)
- When payload should be bundled with signature
- Simple verification workflows
- General-purpose signing

### Example

```csharp
using CoseSign1.Factories;
using CoseSign1.Factories.Direct;

using var factory = new CoseSign1MessageFactory(signingService);

// Embedded payload
byte[] embeddedSignature = factory.CreateDirectCoseSign1MessageBytes(
    payload,
    "application/json");

// Detached payload (payload not embedded in signature)
byte[] detachedSignature = factory.CreateCoseSign1MessageBytes(
    payload,
    "application/json",
    new DirectSignatureOptions { EmbedPayload = false });
```

### CLI Usage

```bash
# Embedded direct signature
CoseSignTool sign-pfx document.json --pfx cert.pfx --signature-type embedded --output signed.cose

# Detached direct signature
CoseSignTool sign-pfx document.json --pfx cert.pfx --signature-type detached --output signed.cose
```

## Indirect Signatures

### How They Work

```
┌─────────────────────────────────────────────────────────────┐
│                   Indirect Signature                        │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  ┌────────────────┐                                         │
│  │    Payload     │                                         │
│  │    (Data)      │                                         │
│  └───────┬────────┘                                         │
│          │                                                  │
│          ▼                                                  │
│  ┌────────────────┐                                         │
│  │   Hash(SHA256) │                                         │
│  └───────┬────────┘                                         │
│          │                                                  │
│          ▼                                                  │
│  ┌────────────────┐    ┌────────────────┐                   │
│  │   Protected    │    │   Private      │                   │
│  │   Headers +    │──▶│     Key        │ ───▶ Signature    │
│  │   Hash Envelope│    └────────────────┘                   │
│  └────────────────┘                                         │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### Hash Envelope Structure

Indirect signatures use a "hash envelope" payload:

```cbor
{
    "algorithm": "SHA-256",       ; Hash algorithm
    "hash": h'abc123...',         ; Hash of original payload
    "location": "file.json"       ; Optional: where to find payload
}
```

### When to Use

- **Large payloads** - Sign gigabyte files efficiently
- **Streaming** - Sign without loading entire payload
- **Remote signing** - Only hash crosses network
- **SCITT compliance** - Required for some workflows
- **Storage efficiency** - Small signature, large payload

### Example

```csharp
using CoseSign1.Factories;
using CoseSign1.Factories.Indirect;

using var factory = new CoseSign1MessageFactory(signingService);

// Create indirect signature (in-memory payload)
byte[] signature = factory.CreateIndirectCoseSign1MessageBytes(
    payload,
    "application/json");

// Or from stream (memory efficient)
using var stream = File.OpenRead("large-file.bin");
byte[] streamSignature = await factory.CreateIndirectCoseSign1MessageBytesAsync(
    stream,
    "application/octet-stream");
```

### CLI Usage

```bash
# Indirect signature
CoseSignTool sign-pfx large-file.bin ^
    --pfx cert.pfx ^
    --signature-type indirect ^
    --hash-algorithm SHA256 ^
    --output signed.cose
```

## Comparison

| Feature | Direct (Embedded) | Direct (Detached) | Indirect |
|---------|-------------------|-------------------|----------|
| Payload in signature | Yes | No | No (hash only) |
| Signature size | Varies with payload | Small | Small (fixed) |
| Memory usage | Payload size | Hash size | Hash size |
| Streaming support | No | No | Yes |
| Signature verification | Self-contained | Requires payload | Self-contained |
| Payload verification | N/A (embedded) | Requires payload | Requires payload |
| SCITT compliance | Limited | Limited | Full support |

> **Key Distinction:**
> - **Detached signatures** require the original payload to verify the *signature itself* (the payload is part of the signed data)
> - **Indirect signatures** can verify the *signature* without the payload (the hash envelope is the signed data), but require the payload to verify it *matches the signed hash*

## Verification

### Direct Signature Verification

```csharp
using CoseSign1.Certificates.Extensions;
using System.Security.Cryptography.Cose;

var message = CoseMessage.DecodeSign1(signature);

// Embedded - payload in signature, fully self-contained
bool isValid = message.VerifySignature();

// Detached - payload REQUIRED to verify signature
// (the payload is part of the signed data structure)
bool isValidDetached = message.VerifySignature(detachedPayload);
```

### Indirect Signature Verification

Indirect signatures have two verification steps:

1. **Signature verification** - Verify the signature over the hash envelope (no payload needed)
2. **Payload verification** - Verify the payload matches the signed hash (payload required)

Indirect signatures sign a *hash envelope* instead of the original payload.

- Signature verification is self-contained (the signed bytes are the hash envelope), so you can verify the COSE signature without the original payload.
- Payload verification is a separate step: compute the expected hash of the payload using the algorithm encoded in the message headers, then compare it to the signed hash content.

For most callers, the CLI provides this end-to-end verification via `cosesigntool verify` with `--payload` (and `--signature-only` to skip payload verification).

### CLI Verification

```bash
# Direct signature (embedded) - fully self-contained
CoseSignTool verify signed.cose

# Direct signature (detached) - payload REQUIRED to verify signature
CoseSignTool verify signed.cose --payload document.json

# Indirect signature - payload needed to verify hash match
# (signature itself can be verified without payload)
CoseSignTool verify signed.cose --payload large-file.bin

# Indirect signature - verify signature only (no payload verification)
CoseSignTool verify signed.cose --signature-only
```

## Supported Hash Algorithms

| Algorithm | OID | Recommended |
|-----------|-----|-------------|
| SHA-256 | 2.16.840.1.101.3.4.2.1 | Yes |
| SHA-384 | 2.16.840.1.101.3.4.2.2 | Yes |
| SHA-512 | 2.16.840.1.101.3.4.2.3 | Yes |
| SHA3-256 | 2.16.840.1.101.3.4.2.8 | Yes |
| SHA3-384 | 2.16.840.1.101.3.4.2.9 | Yes |
| SHA3-512 | 2.16.840.1.101.3.4.2.10 | Yes |

## Use Case Examples

### Signing Large Files

```csharp
// Efficient signing of large files
using var stream = File.OpenRead("installer-4gb.exe");

var factory = new IndirectSignatureFactory(signingService);
var signature = await factory.CreateIndirectSignatureBytesAsync(
    stream,
    HashAlgorithmName.SHA384,
    "application/octet-stream");

await File.WriteAllBytesAsync("installer.sig", signature);
```

### Container Image Signing

```csharp
// Sign container image by digest
var imageDigest = "sha256:abc123...";

var factory = new IndirectSignatureFactory(signingService);
var signature = factory.CreateIndirectSignatureFromDigest(
    imageDigest,
    "application/vnd.oci.image.manifest.v1+json");
```

### Software Bill of Materials

```csharp
// Sign SBOM indirectly
var factory = new IndirectSignatureFactory(signingService);
var signature = factory.CreateIndirectSignatureBytes(
    sbomBytes,
    HashAlgorithmName.SHA256,
    "application/spdx+json");
```

## Security Considerations

### Hash Algorithm Selection

- Use SHA-384 or SHA-512 for long-term security
- SHA-256 is acceptable for most current uses
- Consider SHA3 for highest security margins

### Hash Collision Resistance

Indirect signatures rely on hash collision resistance:
- Use approved algorithms only
- Monitor for algorithm weaknesses
- Plan for algorithm agility

### Payload Binding

Ensure payload location/identification is clear:
- Include content type in headers
- Consider including payload identifier
- Document payload retrieval process

## See Also

- [Detached Signatures](detached-signatures.md)
- [SCITT Compliance](scitt-compliance.md)
- [Security Guide](security.md)
- [Indirect Signature Plugin](../plugins/indirect-plugin.md)
