# CoseSignTool CLI Reference

CoseSignTool is a command-line tool for creating and verifying COSE Sign1 signatures. It supports a plugin architecture for extensibility and multiple output formats for automation.

## Commands

| Command | Description |
|---------|-------------|
| `sign-ephemeral` | Sign with an ephemeral test certificate (development only) |
| `sign-pfx` | Sign with a PFX certificate file (requires Local plugin) |
| `sign-pem` | Sign with PEM certificate and key files (requires Local plugin) |
| `sign-store` | Sign with a certificate from the system store (requires Local plugin) |
| `sign-ats` | Sign with Azure Trusted Signing (requires ATS plugin) |
| `verify` | Verify a COSE Sign1 signature |
| `inspect` | Inspect COSE Sign1 signature details |

## Global Options

| Option | Alias | Description |
|--------|-------|-------------|
| `--output-format <format>` | `-o` | Output format: `text`, `json`, `xml`, `quiet` |
| `--verbose` | `-v` | Enable verbose output |
| `--version` | | Display version information |
| `--help` | `-h` | Show help and usage information |

## Quick Start

```bash
# Sign a file with an ephemeral test certificate
echo "Hello, COSE!" | cosesigntool sign-ephemeral -o signed.cose

# Verify the signature
cosesigntool verify signed.cose --allow-untrusted

# Inspect signature details
cosesigntool inspect signed.cose

# Get JSON output for automation
cosesigntool inspect signed.cose --output-format json
```

## Output Formats

CoseSignTool supports multiple output formats:

- **text** (default) - Human-readable output with colors and sections
- **json** - Structured JSON for programmatic consumption
- **xml** - XML output for XML-based toolchains
- **quiet** - Minimal output, errors only

See [Output Formats](output-formats.md) for detailed documentation.

## Command Reference

- [Inspect Command](inspect.md) - View signature details with full decoding
- [Output Formats](output-formats.md) - Output format options and JSON schema

## Signing Options

### Signature Types

The `--signature-type` option (alias `-d`) controls how the payload is included:

| Type | Description |
|------|-------------|
| `embedded` | Payload is included in the COSE message (default) |
| `detached` | Payload is external; only hash/signature is stored |

```bash
# Create an embedded signature (default)
cosesigntool sign-ephemeral payload.bin -o embedded.cose

# Create a detached signature
cosesigntool sign-ephemeral payload.bin -o detached.cose --signature-type detached
# or using the short alias
cosesigntool sign-ephemeral payload.bin -o detached.cose -d detached
```

### Content Type

Specify the content type of the payload:

```bash
cosesigntool sign-ephemeral data.json -o signed.cose --content-type application/json
```

## Plugin Commands

CoseSignTool uses a plugin architecture. Additional signing commands are available when plugins are installed:

### Local Plugin

```bash
# Sign with a PFX file
cosesigntool sign-pfx payload.bin --pfx cert.pfx --pfx-password secret -o signed.cose

# Sign with PEM files
cosesigntool sign-pem payload.bin --cert cert.pem --key key.pem -o signed.cose

# Sign with certificate store (Windows)
cosesigntool sign-store payload.bin --thumbprint ABC123... -o signed.cose
```

### Azure Trusted Signing Plugin

```bash
# Sign with Azure Trusted Signing
cosesigntool sign-ats payload.bin \
  --endpoint https://account.codesigning.azure.net \
  --account myaccount \
  --profile myprofile \
  -o signed.cose
```

## Exit Codes

| Code | Description |
|------|-------------|
| 0 | Success |
| 1 | Error (invalid input, verification failure, etc.) |

## Examples

### CI/CD Integration

```yaml
# GitHub Actions example
- name: Verify signature
  run: |
    cosesigntool verify artifact.cose --allow-untrusted
    
- name: Check signature details
  run: |
    result=$(cosesigntool inspect artifact.cose -o json)
    echo "Algorithm: $(echo $result | jq -r '.protectedHeaders.algorithm.name')"
```

### PowerShell Automation

```powershell
# Inspect and check certificate expiration
$result = cosesigntool inspect signed.cose -o json | ConvertFrom-Json

foreach ($cert in $result.certificates) {
    if ($cert.isExpired) {
        Write-Warning "Certificate expired: $($cert.subject)"
    }
}
```

### Bash Scripting

```bash
# Check if signature is SCITT compliant
issuer=$(cosesigntool inspect signed.cose -o json | jq -r '.cwtClaims.issuer // empty')
if [ -n "$issuer" ]; then
    echo "SCITT compliant signature with issuer: $issuer"
else
    echo "No CWT claims found - not SCITT compliant"
fi
```

## See Also

- [Quick Start Guide](../getting-started/quick-start.md)
- [Architecture Overview](../architecture/overview.md)
- [Plugin Development](../guides/cli-plugins.md)
