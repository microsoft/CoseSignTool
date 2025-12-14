# Verify Command

The `verify` command validates COSE Sign1 signatures.

## Synopsis

```bash
CoseSignTool verify <signature-file> [options]
```

## Description

The `verify` command validates a COSE Sign1 signature file, checking:

1. **Signature validity** - Cryptographic signature verification
2. **Certificate chain** - Certificate chain building and validation
3. **Certificate status** - Expiration and revocation checks
4. **Payload integrity** - For detached signatures

## Arguments

| Argument | Description |
|----------|-------------|
| `<signature-file>` | Path to the COSE signature file to verify |

## Options

### Core Options

| Option | Description |
|--------|-------------|
| `--payload <file>` | Path to payload file (required for detached signatures, optional for indirect) |
| `--signature-only` | Verify signature only, skip payload verification (indirect signatures only) |
| `--trust-root <file>` | Custom trusted root certificate |
| `--skip-revocation` | Skip certificate revocation checking |
| `--output-format <format>` | Output format: `text`, `json`, `xml`, `quiet` |

### Certificate Options

| Option | Description |
|--------|-------------|
| `--allow-untrusted` | Allow signatures from untrusted roots |
| `--allow-expired` | Allow expired certificates |
| `--require-eku <oid>` | Require specific Extended Key Usage |

### Plugin Options

Additional options may be available from installed plugins:

**MST Plugin:**
| Option | Description |
|--------|-------------|
| `--mst-service-uri <uri>` | MST service endpoint |
| `--verify-mst-receipt` | Verify MST receipt |
| `--require-mst-receipt` | Require valid MST receipt |

## Examples

### Basic Verification (Embedded Signature)

```bash
CoseSignTool verify signed.cose
```

### Verify Detached Signature

For detached signatures, the payload is **required** to verify the signature:

```bash
CoseSignTool verify document.sig --payload document.json
```

### Verify Indirect Signature

Indirect signatures can be verified with or without the payload:

```bash
# Full verification: signature + payload hash match
CoseSignTool verify indirect.sig --payload large-file.bin

# Signature-only verification (no payload needed)
CoseSignTool verify indirect.sig --signature-only
```

### Verify with Custom Trust Root

```bash
CoseSignTool verify signed.cose --trust-root my-root-ca.cer
```

### JSON Output

```bash
CoseSignTool verify signed.cose --output-format json
```

### Verify with MST Receipt (requires MST plugin)

```bash
CoseSignTool verify signed.cose ^
    --mst-service-uri https://mst.microsoft.com ^
    --verify-mst-receipt
```

### Verify with MST Receipt Only (Bypass Certificate Validation)

When using MST transparency receipts, you can bypass traditional certificate chain validation.
The receipt verification provides an alternative trust anchor - see [MST Plugin Documentation](../plugins/mst-plugin.md#bypassing-certificate-validation-with-receipt-verification) for details.

```bash
# Trust the MST receipt instead of certificate chain
CoseSignTool verify signed.cose --require-receipt --allow-untrusted

# With endpoint verification
CoseSignTool verify signed.cose --require-receipt --mst-endpoint https://... --allow-untrusted
```

## Trust Models

CoseSignTool supports different trust models depending on your security requirements:

| Trust Model | Options | Description |
|-------------|---------|-------------|
| Certificate Chain | (default) | Traditional PKI - trust anchored in X.509 certificate authorities |
| Certificate + Receipt | `--require-receipt` | Both certificate chain AND MST receipt must be valid |
| Receipt Only | `--require-receipt --allow-untrusted` | Trust anchored in MST transparency service only |
| No Validation | `--allow-untrusted` | No trust validation (development/testing only) |

**Recommendation**: For supply chain scenarios, use "Receipt Only" trust (`--require-receipt --allow-untrusted`) to decouple trust from traditional PKI infrastructure.

## Output

### Text Format (default)

```
Verification Result: VALID

Signature Details:
  Algorithm: ES384
  Content Type: application/json

Certificate:
  Subject: CN=My Signing Cert
  Issuer: CN=My CA
  Valid From: 2024-01-01
  Valid To: 2025-01-01
  Thumbprint: ABC123...
```

### JSON Format

```json
{
  "isValid": true,
  "algorithm": "ES384",
  "contentType": "application/json",
  "certificate": {
    "subject": "CN=My Signing Cert",
    "issuer": "CN=My CA",
    "thumbprint": "ABC123...",
    "validFrom": "2024-01-01T00:00:00Z",
    "validTo": "2025-01-01T00:00:00Z"
  }
}
```

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Signature is valid |
| 1 | Signature is invalid |
| 2 | Error (file not found, etc.) |

## See Also

- [Inspect Command](inspect.md) - View signature details
- [Output Formats](output-formats.md) - Output format options
- [CLI Reference](README.md) - Full CLI documentation
