# CoseSignTool.MST.Plugin

**Package**: `CoseSignTool.MST.Plugin`  
**Purpose**: Microsoft's Signing Transparency (MST) verification for the CoseSignTool CLI

## Overview

This plugin provides Microsoft's Signing Transparency (MST) integration, enabling:
- Verification of MST transparency receipts embedded in COSE signatures
- Automatic MST receipt attachment during signing operations
- Supply chain transparency compliance

## What is Microsoft's Signing Transparency?

Microsoft's Signing Transparency (MST) is a transparency service that provides:
- **Immutable Audit Log**: All signatures are recorded in a tamper-evident log
- **Public Verifiability**: Anyone can verify that a signature was properly logged
- **Cryptographic Receipts**: Proof of inclusion in the transparency log
- **Supply Chain Integrity**: Supports SCITT (Supply Chain Integrity, Transparency and Trust)

## Verification Options

This plugin adds options to the `verify` command for MST receipt validation.

### Options Added to `verify` Command

| Option | Required | Description |
|--------|----------|-------------|
| `--require-receipt` | No | Require an MST transparency receipt in the signature |
| `--mst-endpoint` | No | MST service endpoint URL for receipt verification |
| `--verify-receipt` | No | Verify the receipt against the MST service (default: true when endpoint provided) |
| `--mst-trust-mode` | No | Trust mode: `online` (query endpoint for signing keys) or `offline` (use manually provided signing keys) |
| `--mst-trust-file` | No | Offline trust file (JSON) containing signing keys for one or more MST issuers |
| `--mst-trusted-key` | No | Offline trusted key entry. Repeatable. Format: `<mst-endpoint>=<path-to-jwk-or-jwks-json>` |

**Examples**:
```bash
# Verify signature and require MST receipt
CoseSignTool verify signed.cose --require-receipt

# Verify receipt against specific endpoint
CoseSignTool verify signed.cose --require-receipt --mst-endpoint https://custom.codetransparency.azure.net

# Explicit online mode (query endpoint for signing keys)
CoseSignTool verify signed.cose --require-receipt --mst-trust-mode online --mst-endpoint https://custom.codetransparency.azure.net

# Offline mode (pinned keys, no network fallback)
CoseSignTool verify signed.cose --require-receipt --mst-trust-mode offline --mst-endpoint https://custom.codetransparency.azure.net --mst-trusted-key https://custom.codetransparency.azure.net=signing-key.jwk.json

# Offline mode with a trust file (many keys/issuers)
CoseSignTool verify signed.cose --require-receipt --mst-trust-mode offline --mst-endpoint https://custom.codetransparency.azure.net --mst-trust-file mst-trust.json

# Verify signature structure only (skip receipt verification)
CoseSignTool verify signed.cose --require-receipt --verify-receipt false

# Output as JSON for scripting
CoseSignTool verify signed.cose --require-receipt -f json
```

## Transparency Provider

The plugin also contributes a transparency provider that can be used during signing operations to automatically add MST receipts to signatures.

### Configuration

When used with other signing plugins, MST receipts can be automatically added:

```bash
# The --mst-endpoint option enables MST receipt inclusion
CoseSignTool sign-pfx document.json --pfx cert.pfx --mst-endpoint https://dataplane.codetransparency.azure.net
```

## Verification Output

### Success Output

```
MST Transparency Verification
-----------------------------
  Signature: signed.cose
  Found 1 MST receipt(s) in signature
    Receipt 1: 256 bytes
  MST receipt verification complete
✓ MST transparency verification complete
```

### No Receipt Found

```
MST Transparency Verification
-----------------------------
  Signature: signed.cose
⚠ No MST transparency receipt found in signature
  This signature was not submitted to Microsoft's Signing Transparency
```

### JSON Output

```json
{
  "type": "section_start",
  "title": "MST Transparency Verification"
},
{
  "type": "keyvalue",
  "key": "Signature",
  "value": "signed.cose"
},
{
  "type": "success",
  "message": "Found 1 MST receipt(s) in signature"
}
```

## MST Receipt Structure

MST receipts are COSE Sign1 messages that contain:
- **Inclusion Proof**: Merkle proof of inclusion in the transparency log
- **Signed Tree Head**: Current state of the Merkle tree
- **Leaf Hash**: Hash of the original signature entry
- **Timestamp**: When the entry was added to the log

The receipt is embedded in the original signature's unprotected headers.

## Integration with SCITT

MST is designed to work with SCITT (Supply Chain Integrity, Transparency and Trust) workflows:

1. **Sign**: Create a COSE Sign1 signature
2. **Submit**: Submit to MST service
3. **Receive Receipt**: Get inclusion proof
4. **Embed**: Receipt is embedded in signature
5. **Verify**: Recipients can verify transparency

## Security Considerations

1. **Receipt Verification**: Always verify receipts against the transparency service
2. **Clock Sync**: Ensure system clocks are synchronized for timestamp validation
3. **Network Security**: Use HTTPS for all transparency service communications
4. **Receipt Freshness**: Consider how old receipts are acceptable for your use case

## Bypassing Certificate Validation with Receipt Verification

When using MST receipt verification, you may want to **bypass traditional X.509 certificate chain validation** because the transparency receipt provides an alternative trust anchor.

### Why Bypass Certificate Validation?

MST receipt verification provides:
- **Proof of Logging**: The signature was submitted to and accepted by the transparency service
- **Tamper Evidence**: Any modification would invalidate the inclusion proof
- **Time-stamping**: Cryptographic proof of when the signature was logged
- **Supply Chain Trust**: Trust is anchored in the transparency service, not certificate authorities

This means certificate chain validation may be redundant or even counterproductive when:
- The signing certificate has expired (but the receipt proves it was valid at signing time)
- The certificate was issued by a private/internal CA not in system trust stores
- You want to decouple trust from traditional PKI infrastructure

### How to Bypass Certificate Validation

Use `--allow-untrusted` to skip certificate chain validation while still requiring MST receipt verification:

```bash
# Verify with MST receipt only - bypass certificate chain validation
CoseSignTool verify signed.cose --require-receipt --allow-untrusted

# Verify with MST receipt and endpoint verification - bypass certificate chain
CoseSignTool verify signed.cose --require-receipt --mst-endpoint https://dataplane.codetransparency.azure.net --allow-untrusted
```

### Provider Activation Behavior

| Options | Active Providers | Trust Model |
|---------|-----------------|-------------|
| (none) | X509 | Certificate chain trust |
| `--require-receipt` | X509, MST | Both certificate AND receipt |
| `--allow-untrusted` | (none) | No validation |
| `--require-receipt --allow-untrusted` | MST | Receipt trust only ✓ |
| `--mst-endpoint <url>` | X509, MST | Both certificate AND receipt |
| `--mst-endpoint <url> --allow-untrusted` | MST | Receipt trust only ✓ |

### Recommended Usage Patterns

**Production with Full Validation** (certificate + receipt):
```bash
CoseSignTool verify signed.cose --require-receipt --mst-endpoint https://...
```

**Receipt-Only Trust** (recommended for supply chain scenarios):
```bash
CoseSignTool verify signed.cose --require-receipt --mst-endpoint https://... --allow-untrusted
```

**Development/Testing** (ephemeral certificates):
```bash
CoseSignTool verify signed.cose --allow-untrusted
```

## Default Endpoints

| Environment | Endpoint |
|-------------|----------|
| Production | `https://dataplane.codetransparency.azure.net` |
| Custom | Configure via `--endpoint` option |

## Error Codes

| Exit Code | Meaning |
|-----------|---------|
| 0 | Success - receipt verified |
| 1 | File not found |
| 2 | No MST receipt in signature |
| 3 | Failed to extract receipt |
| 4 | Verification error |
