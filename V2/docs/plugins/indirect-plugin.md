# CoseSignTool.IndirectSignature.Plugin

The Indirect Signature plugin adds support for indirect (hash envelope) signatures to the CoseSignTool CLI.

## Overview

Indirect signatures sign a hash of the payload rather than the payload itself, enabling efficient signing of large files.

## Installation

The plugin is included with CoseSignTool by default.

## Options Added

The plugin adds support for indirect signatures via the `--signature-type` option:

| Option | Description |
|--------|-------------|
| `--signature-type indirect` | Create an indirect (hash envelope) signature |
| `--hash-algorithm <alg>` | Hash algorithm for indirect signatures |

## Supported Hash Algorithms

| Algorithm | Description |
|-----------|-------------|
| `SHA256` | SHA-256 (default) |
| `SHA384` | SHA-384 |
| `SHA512` | SHA-512 |
| `SHA3-256` | SHA3-256 |
| `SHA3-384` | SHA3-384 |
| `SHA3-512` | SHA3-512 |

## Usage

### Create Indirect Signature

```bash
CoseSignTool sign-pfx large-file.bin ^
    --pfx-file cert.pfx ^
    --signature-type indirect ^
    --hash-algorithm SHA384 ^
    --output large-file.sig
```

### Verify Indirect Signature

```bash
# Verify signature AND that payload matches the signed hash
CoseSignTool verify large-file.sig --payload large-file.bin

# Verify signature only (no payload needed)
CoseSignTool verify large-file.sig --signature-only
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
│                   Indirect Signature                         │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  ┌────────────┐     ┌────────────────┐     ┌────────────┐   │
│  │  Payload   │────▶│  Hash(SHA384)  │────▶│  Sign      │   │
│  │  (Large)   │     │                │     │  Hash      │   │
│  └────────────┘     └────────────────┘     └────────────┘   │
│                                                   │          │
│                                                   ▼          │
│                                            ┌────────────┐   │
│                                            │ Signature  │   │
│                                            │ (Small)    │   │
│                                            └────────────┘   │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

## Verification

Indirect signatures have two distinct verification steps:

### 1. Signature Verification (No Payload Needed)

The signature over the hash envelope can be verified without the original payload:

```bash
CoseSignTool verify large-file.sig --signature-only
```

This confirms:
- The signature is cryptographically valid
- The signing certificate is trusted
- The hash envelope hasn't been tampered with

### 2. Payload Verification (Requires Payload)

To verify the payload matches the signed hash:

```bash
CoseSignTool verify large-file.sig --payload large-file.bin
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
