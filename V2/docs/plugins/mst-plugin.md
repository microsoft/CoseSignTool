# CoseSignTool.MST.Plugin

**Package**: `CoseSignTool.MST.Plugin`  
**Purpose**: Microsoft Signing Transparency (MST) receipt verification (and optional receipt attachment during signing)

## Overview

This plugin integrates Microsoft Signing Transparency (MST) with CoseSignTool:

- Verification: validate SCITT receipts via `verify scitt`
- Signing: attach MST receipts when the transparency provider is present (default service endpoint)

## Verify (MST Receipt Trust)

MST verification is exposed as a dedicated verify root:

```bash
cosesigntool verify scitt [<signature>] [options]
```

### Options

| Option | Description |
|--------|-------------|
| `--issuer-offline-keys <issuer=path>` | Pinned SCITT issuer signing keys JWKS JSON file for offline-only receipt verification |
| `--issuer <host-or-url>` | Allowed SCITT issuer host(s). Repeatable |

At least one of `--issuer-offline-keys` or `--issuer` is required.

### Examples

```bash
# Trust a specific ledger instance (repeatable)
cosesigntool verify scitt signed.cose --issuer esrp-cts-cp.confidential-ledger.azure.com

# Offline-only verification using pinned keys
cosesigntool verify scitt signed.cose --issuer-offline-keys esrp-cts-cp.confidential-ledger.azure.com=esrp-cts-cp.confidential-ledger.azure.com.jwks.json

# JSON output
cosesigntool verify scitt signed.cose --issuer esrp-cts-cp.confidential-ledger.azure.com -f json
```

## Signing (Receipt Attachment)

When the MST transparency provider is loaded, signing operations can include MST receipts.
The current CLI uses the default MST endpoint:

- `https://dataplane.codetransparency.azure.net`

If you need a custom MST endpoint, it must be configured at the transparency provider level (not via a CLI flag).

## See Also

- [Verify Command](../cli/verify.md)
- [Components: MST](../components/mst.md)
- [Plugins Overview](README.md)

Run `cosesigntool verify scitt --help` for the authoritative set of MST verification options.
