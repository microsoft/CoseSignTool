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

**Examples**:
```bash
# Verify signature and require MST receipt
CoseSignTool verify signed.cose --require-receipt

# Verify receipt against specific endpoint
CoseSignTool verify signed.cose --require-receipt --mst-endpoint https://custom.codetransparency.azure.net

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
