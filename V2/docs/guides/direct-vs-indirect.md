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
│                    Direct Signature                          │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  ┌────────────────┐                                          │
│  │    Payload     │                                          │
│  │    (Data)      │                                          │
│  └───────┬────────┘                                          │
│          │                                                   │
│          ▼                                                   │
│  ┌────────────────┐    ┌────────────────┐                   │
│  │   Protected    │    │   Private      │                   │
│  │   Headers +    │───▶│     Key        │───▶ Signature     │
│  │   Payload      │    └────────────────┘                   │
│  └────────────────┘                                          │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

### When to Use

- Small to medium payloads (< 10 MB)
- When payload should be bundled with signature
- Simple verification workflows
- General-purpose signing

### Example

```csharp
using CoseSign1;

var factory = new DirectSignatureFactory(signingService);

// Embedded payload
byte[] signature = factory.CreateCoseSign1MessageBytes(
    payload, 
    "application/json");

// Detached payload (payload not in signature)
byte[] signature = factory.CreateCoseSign1MessageBytes(
    payload, 
    "application/json",
    isDetached: true);
```

### CLI Usage

```bash
# Embedded direct signature
CoseSignTool sign-pfx document.json --pfx-file cert.pfx --signature-type embedded --output signed.cose

# Detached direct signature
CoseSignTool sign-pfx document.json --pfx-file cert.pfx --signature-type detached --output signed.cose
```

## Indirect Signatures

### How They Work

```
┌─────────────────────────────────────────────────────────────┐
│                   Indirect Signature                         │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  ┌────────────────┐                                          │
│  │    Payload     │                                          │
│  │    (Data)      │                                          │
│  └───────┬────────┘                                          │
│          │                                                   │
│          ▼                                                   │
│  ┌────────────────┐                                          │
│  │   Hash(SHA256) │                                          │
│  └───────┬────────┘                                          │
│          │                                                   │
│          ▼                                                   │
│  ┌────────────────┐    ┌────────────────┐                   │
│  │   Protected    │    │   Private      │                   │
│  │   Headers +    │───▶│     Key        │───▶ Signature     │
│  │   Hash Envelope│    └────────────────┘                   │
│  └────────────────┘                                          │
│                                                              │
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
using CoseIndirectSignature;

var factory = new IndirectSignatureFactory(signingService);

// Create indirect signature
byte[] signature = factory.CreateIndirectSignatureBytes(
    payload,
    HashAlgorithmName.SHA256,
    "application/json");

// Or from stream (memory efficient)
using var stream = File.OpenRead("large-file.bin");
byte[] signature = await factory.CreateIndirectSignatureBytesAsync(
    stream,
    HashAlgorithmName.SHA256,
    "application/octet-stream");
```

### CLI Usage

```bash
# Indirect signature
CoseSignTool sign-pfx large-file.bin ^
    --pfx-file cert.pfx ^
    --signature-type indirect ^
    --hash-algorithm SHA256 ^
    --output signed.cose
```

## Comparison

| Feature | Direct | Indirect |
|---------|--------|----------|
| Payload in signature | Yes (embedded) or No (detached) | No (hash only) |
| Signature size | Varies with payload | Fixed (small) |
| Memory usage | Payload size | Hash size |
| Streaming support | No | Yes |
| Verification | Self-contained | Needs original payload |
| SCITT compliance | Limited | Full support |

## Verification

### Direct Signature Verification

```csharp
// Embedded - payload in signature
var result = validator.Validate(signature);

// Detached - provide payload separately
var result = validator.Validate(signature, detachedPayload);
```

### Indirect Signature Verification

```csharp
// Must provide original payload for hash comparison
var result = validator.ValidateIndirect(signature, originalPayload);

// Or from stream
using var stream = File.OpenRead("large-file.bin");
var result = await validator.ValidateIndirectAsync(signature, stream);
```

### CLI Verification

```bash
# Direct signature (embedded)
CoseSignTool verify signed.cose

# Direct signature (detached)
CoseSignTool verify signed.cose --payload document.json

# Indirect signature (automatically detected from signature)
CoseSignTool verify signed.cose --payload large-file.bin
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
