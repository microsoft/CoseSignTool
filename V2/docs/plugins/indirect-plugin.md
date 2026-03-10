# Indirect Signatures

CoseSignTool V2 supports indirect (hash envelope) signatures via the standard `--signature-type indirect` mode.
No separate plugin is required.

## Overview

Indirect signatures sign a hash of the payload rather than embedding/signing the payload bytes directly.
This enables efficient signing and verification of large files.

## CLI Options

Indirect signatures are controlled by the standard signing option:

| Option | Description |
|--------|-------------|
| `--signature-type indirect` | Create an indirect (hash envelope) signature (this is the default signature type) |

The payload hash algorithm is currently fixed to SHA-256 and is not configurable via a CLI option.

## Usage

### Create an Indirect Signature

```bash
cosesigntool sign x509 pfx large-file.bin \
    --pfx cert.pfx \
    --signature-type indirect \
    -o large-file.sig
```

### Verify an Indirect Signature

```bash
# Verify signature AND (if provided) verify that payload matches the signed hash
cosesigntool verify x509 large-file.sig --payload large-file.bin

# Verify signature only (no payload needed)
cosesigntool verify x509 large-file.sig --signature-only
```

## When to Use Indirect Signatures

Use indirect signatures when:

- **Large files** - Signing files larger than available memory
- **Streaming** - Payload can be streamed rather than loaded entirely
- **Network efficiency** - Only hash crosses network for remote signing
- **SCITT compliance** - Some SCITT workflows require indirect signatures

## How It Works

1. The payload is hashed using the specified algorithm
2. A "hash envelope" is created containing:
   - Hash algorithm identifier
   - Hash value
   - Optional payload location hint
3. The hash envelope is signed instead of the payload

```
┌─────────────────────────────────────────────────────────────┐
│                   Indirect Signature                        │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  ┌────────────┐     ┌────────────────┐     ┌────────────┐   │
│  │  Payload   │───▶│  Hash(SHA384)  │────▶│  Sign      │   │
│  │  (Large)   │     │                │     │  Hash      │   │
│  └────────────┘     └────────────────┘     └────────────┘   │
│                                                   │         │
│                                                   ▼         │
│                                            ┌────────────┐   │
│                                            │ Signature  │   │
│                                            │ (Small)    │   │
│                                            └────────────┘   │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

## Verification

Indirect signatures have two distinct verification steps:

### 1. Signature Verification (No Payload Needed)

The signature over the hash envelope can be verified without the original payload:

```bash
cosesigntool verify x509 large-file.sig --signature-only
```

This confirms:
- The signature is cryptographically valid
- The signing certificate is trusted
- The hash envelope hasn't been tampered with

### 2. Payload Verification (Requires Payload)

To verify the payload matches the signed hash:

```bash
cosesigntool verify x509 large-file.sig --payload large-file.bin
```

This additionally confirms:
- The payload hashes to the value in the signed hash envelope

> **Key Difference from Detached Signatures:**
> - **Detached signatures** require the payload to verify the *signature itself*
> - **Indirect signatures** can verify the *signature* without the payload, but need the payload to verify it *matches the signed hash*

## See Also

- [Direct vs Indirect Signatures](../guides/direct-vs-indirect.md)
- [SCITT Compliance](../guides/scitt-compliance.md)
- [CLI Reference](../cli/README.md)
