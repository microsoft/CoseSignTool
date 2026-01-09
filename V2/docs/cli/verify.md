# Verify Command

The `verify` command validates COSE Sign1 signatures.

## Synopsis

```bash
CoseSignTool verify <signature-file> [options]
```

## Description

The `verify` command validates a COSE Sign1 signature file.

Verification is staged and runs in a secure-by-default order:

1. **Key material resolution** - Parse/extract candidate signing key material from headers.
2. **Key material trust** - Evaluate trust/identity/policy (trust policies are evaluated *before* signature verification).
3. **Signature** - Cryptographic signature verification.
4. **Post-signature** - Additional policy that depends on a verified signature.

Verification is composed from multiple validators:
- Signature validation is orchestrated so that **at least one applicable signature validator must succeed**.
- X.509-related validation (chain, expiry, EKU, etc.) is only applicable when the message includes certificate headers (`x5t` + `x5chain`).
- Plugins can contribute additional verification providers and signature validators (for example, key-only signatures identified by `kid`).

## Arguments

| Argument | Description |
|----------|-------------|
| `<signature-file>` | Path to the COSE signature file to verify |

## Options

### Core Options

| Option | Description |
|--------|-------------|
| `--payload <file>` | Path to payload file (required for detached signatures, optional for indirect) |
| `--signature-only` | For indirect signatures: verify the signature but skip verifying the payload hash match (does not apply to detached signatures) |
| `-r, --trust-roots <files>` | Custom trusted root certificate(s) in PEM or DER format |
| `--trust-pfx <file>` | PFX/PKCS#12 file containing trusted root certificate(s) |
| `--trust-pfx-password-file <file>` | Path to file containing PFX password (more secure) |
| `--trust-pfx-password-env <name>` | Environment variable containing PFX password (default: `COSESIGNTOOL_TRUST_PFX_PASSWORD`) |
| `--revocation-mode <none|offline|online>` | Certificate revocation checking mode (default: `online`) |
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
| `--mst-endpoint <uri>` | MST service endpoint |
| `--verify-receipt` | Verify MST receipt (default: true) |
| `--require-receipt` | Fail if no receipt is present |

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
# Single certificate file
CoseSignTool verify signed.cose --trust-roots my-root-ca.cer

# Multiple certificate files
CoseSignTool verify signed.cose -r root1.pem -r root2.pem
```

### Verify with PFX Trust Store

PFX files can contain multiple certificates, making them convenient for managing trust bundles:

```bash
# PFX with password from environment variable (default: COSESIGNTOOL_TRUST_PFX_PASSWORD)
set COSESIGNTOOL_TRUST_PFX_PASSWORD=mypassword
CoseSignTool verify signed.cose --trust-pfx trust-bundle.pfx

# PFX with password from file
CoseSignTool verify signed.cose --trust-pfx trust-bundle.pfx --trust-pfx-password-file password.txt

# PFX with password from custom environment variable
CoseSignTool verify signed.cose --trust-pfx trust-bundle.pfx --trust-pfx-password-env MY_PFX_PASSWORD
```

> **Security Note**: Avoid passing passwords directly on the command line as they may be logged in shell history. Use environment variables or password files instead.

### JSON Output

```bash
CoseSignTool verify signed.cose --output-format json
```

### Verify with MST Receipt (requires MST plugin)

```bash
CoseSignTool verify signed.cose ^
  --require-receipt ^
  --mst-endpoint https://dataplane.codetransparency.azure.net
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
| 0 | Verified successfully |
| 2 | Invalid arguments |
| 3 | File not found (signature or payload) |
| 21 | Signature cryptographic verification failed |
| 22 | Verification failed (resolution, post-signature, payload hash mismatch, unexpected error) |
| 24 | Signing key material not trusted (trust stage failed) |

## See Also

- [Inspect Command](inspect.md) - View signature details
- [Output Formats](output-formats.md) - Output format options
- [CLI Reference](README.md) - Full CLI documentation
