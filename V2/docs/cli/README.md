# CLI Reference

CoseSignTool provides a command-line interface for signing, verifying, and inspecting COSE Sign1 messages.

## Installation

```bash
# Install globally
dotnet tool install -g CoseSignTool

# Verify installation
cosesigntool --help
```

---

## Global Options

These options apply to all commands:

| Option | Description |
|--------|-------------|
| `-q`, `--quiet` | Suppress informational messages (errors still shown) |
| `-vv` | Debug verbosity (level 3) |
| `-vvv` | Trace verbosity (level 4) |
| `--verbosity <N>` | Set verbosity level (0-4) |
| `--log-file <path>` | Write logs to file |
| `--log-file-append` | Append to existing log file |
| `-f`, `--output-format <format>` | Output format: text, json, xml, quiet |
| `--additional-plugin-dir <path>` | Load plugins from additional directory |
| `-h`, `--help` | Show help |
| `--verbose` | Show detailed help including all options and examples |
| `--version` | Show version |

### Output Formats

| Format | Description |
|--------|-------------|
| `text` | Human-readable output with Unicode symbols |
| `json` | JSON output for automation |
| `xml` | XML output |
| `quiet` | Minimal output (exit code only) |

---

## Commands

### verify

Verify a COSE Sign1 signature.

```bash
cosesigntool verify <signature> [options]
```

**Arguments:**
- `<signature>` - Path to signature file (or `-` for stdin)

**Options:**
| Option | Description |
|--------|-------------|
| `-p`, `--payload <payload>` | Payload file for detached/indirect verification |
| `--signature-only` | Verify signature only; skip payload/hash verification |
| `--allow-online-verify` | Allow Azure Key Vault network calls to fetch public key by `kid` when needed |
| `--require-az-key` | Require an Azure Key Vault key-only signature (`kid` + `COSE_Key`) |
| `-r`, `--trust-roots <trust-roots>` | Trusted root certificate(s) in PEM or DER format (repeatable) |
| `--trust-pfx <trust-pfx>` | Trusted roots from a PFX/PKCS#12 file |
| `--trust-pfx-password-file <file>` | Password file for `--trust-pfx` |
| `--trust-pfx-password-env <env>` | Env var name for `--trust-pfx` password (default: `COSESIGNTOOL_TRUST_PFX_PASSWORD`) |
| `--trust-system-roots` | Trust system certificate store roots (default: true) |
| `--allow-untrusted` | Allow self-signed or otherwise untrusted roots |
| `-s`, `--subject-name <subject-name>` | Required subject name (CN) in the signing certificate |
| `-i`, `--issuer-name <issuer-name>` | Required issuer name (CN) in the signing certificate |
| `--revocation-mode <none|offline|online>` | Certificate revocation check mode (default: online) |
| `--require-receipt` | Require an MST transparency receipt in the signature |
| `--mst-endpoint <mst-endpoint>` | MST service endpoint URL for receipt verification |
| `--verify-receipt` | Verify receipt against MST service (default: true when endpoint provided) |
| `--mst-trust-mode <offline|online>` | MST trust mode (default: online) |
| `--mst-trust-file <mst-trust-file>` | Offline trust list JSON (replaces individual trusted keys) |
| `--mst-trusted-key <mst-trusted-key>` | Offline trusted key mapping (repeatable): `<mst-endpoint>=<path-to-jwk-or-jwks-json>` |

**Examples:**
```bash
# Verify embedded signature
cosesigntool verify document.cose

# Verify detached signature
cosesigntool verify document.sig --payload document.txt

# Verify with custom trust roots
cosesigntool verify document.cose --trust-roots ca-bundle.pem

# JSON output for scripting
cosesigntool verify document.cose --output-format json
```

---

### inspect

Inspect a COSE Sign1 message structure.

```bash
cosesigntool inspect [<file>] [options]
```

**Arguments:**
- `<file>` - Path to COSE signature file (use `-` or omit to read from stdin)

**Options:**
| Option | Description |
|--------|-------------|
| `-x`, `--extract-payload <path>` | Extract embedded payload (only works for embedded signatures). Use `-` for stdout |

**Examples:**
```bash
# Basic inspection
cosesigntool inspect document.cose

# Extract embedded payload
cosesigntool inspect document.cose --extract-payload extracted.bin

# JSON output
cosesigntool inspect document.cose --output-format json
```

---

### sign-pfx

Sign with a PFX/PKCS#12 certificate file.

```bash
cosesigntool sign-pfx [<payload>] [options]
```

**Arguments:**
- `<payload>` - Payload to sign (file path or `-` for stdin)

**Required Options:**
| Option | Description |
|--------|-------------|
| `--pfx <file>` | Path to PFX certificate file |

**Optional:**
| Option | Description |
|--------|-------------|
| `--pfx-password-file <file>` | File containing PFX password |
| `--pfx-password-env <env>` | Name of env var containing the PFX password (default: `COSESIGNTOOL_PFX_PASSWORD`) |
| `--pfx-password-prompt` | Prompt for the PFX password |
| `--output`, `-o` | Output file path |
| `--signature-type`, `-t` | Type: `embedded`, `detached`, `indirect` |
| `--content-type`, `-c` | Content type header |

**Examples:**
```bash
# Sign with embedded payload
cosesigntool sign-pfx document.txt --pfx cert.pfx --output document.cose

# Sign with detached payload
cosesigntool sign-pfx document.txt --pfx cert.pfx --signature-type detached --output document.sig

# Sign with password from file
cosesigntool sign-pfx document.txt --pfx cert.pfx --pfx-password-file password.txt --output document.cose
```

---

### sign-pem

Sign with PEM certificate and key files.

```bash
cosesigntool sign-pem [<payload>] [options]
```

**Required Options:**
| Option | Description |
|--------|-------------|
| `--cert-file <cert-file>` | Path to the certificate file (`.pem`, `.crt`) |
| `--key-file <key-file>` | Path to the private key file (`.key`, `.pem`) |

**Optional:**
| Option | Description |
|--------|-------------|
| `--output`, `-o` | Output file path |
| `--signature-type`, `-t` | Type: `embedded`, `detached`, `indirect` |
| `--content-type`, `-c` | Content type header |

**Examples:**
```bash
# Sign with PEM files
cosesigntool sign-pem document.txt --cert-file cert.pem --key-file key.pem --output document.cose
```

---

### sign-certstore

Sign with a certificate from Windows Certificate Store.

```bash
cosesigntool sign-certstore [<payload>] [options]
```

**Required Options:**
| Option | Description |
|--------|-------------|
| `--thumbprint <thumbprint>` | Certificate thumbprint (SHA1) |

**Optional:**
| Option | Description |
|--------|-------------|
| `--store-name <name>` | Store name (default: My) |
| `--store-location <location>` | CurrentUser or LocalMachine |
| `--output`, `-o` | Output file path |
| `--signature-type`, `-t` | Type: `embedded`, `detached`, `indirect` |
| `--content-type`, `-c` | Content type header |

**Examples:**
```bash
# Sign with certificate by thumbprint
cosesigntool sign-certstore document.txt --thumbprint ABC123... --output document.cose
```

---

### sign-ephemeral

Sign with a temporary self-signed certificate (development/testing only).

```bash
cosesigntool sign-ephemeral [<payload>] [options]
```

**Optional:**
| Option | Description |
|--------|-------------|
| `--config <config>` | Path to JSON certificate config file |
| `--subject <subject>` | Certificate subject name (overrides config) |
| `--algorithm <ECDSA|MLDSA|RSA>` | Key algorithm (default: RSA; overrides config) |
| `--key-size <key-size>` | Key size in bits (defaults: RSA=4096, ECDSA=384, MLDSA=65) |
| `--validity-days <validity-days>` | Certificate validity period in days (default: 365) |
| `--no-chain` | Generate self-signed cert instead of full Root → Intermediate → Leaf chain |
| `--minimal` | Minimal config (RSA-2048, self-signed, 1 day validity) |
| `--pqc` | Post-quantum signing (ML-DSA-65 with full chain) |
| `--output`, `-o` | Output file path |
| `--signature-type`, `-t` | Type: `embedded`, `detached`, `indirect` |
| `--content-type`, `-c` | Content type header |

**Examples:**
```bash
# Quick test signing
cosesigntool sign-ephemeral document.txt --output document.cose

# With custom subject
cosesigntool sign-ephemeral document.txt --subject "CN=Test Signer" --output document.cose
```

> **Warning**: Ephemeral certificates should only be used for testing. The private key is discarded after signing.

---

### sign-akv-cert

Sign with an Azure Key Vault certificate.

```bash
cosesigntool sign-akv-cert [<payload>] [options]
```

**Required Options:**
| Option | Description |
|--------|-------------|
| `--akv-vault <uri>` | Azure Key Vault URL (e.g., https://my-vault.vault.azure.net) |
| `--akv-cert-name <name>` | Name of the certificate in Azure Key Vault |

**Optional:**
| Option | Description |
|--------|-------------|
| `--akv-cert-version <version>` | Specific certificate version (uses latest if omitted) |
| `--akv-refresh-interval <minutes>` | Auto-refresh interval in minutes (default: 15, 0 to disable) |
| `--output`, `-o` | Output file path |
| `--signature-type`, `-t` | Type: `embedded`, `detached`, `indirect` |
| `--content-type`, `-c` | Content type header |

Authentication uses `DefaultAzureCredential`. Configure credentials via environment variables, Managed Identity, or developer tooling (Azure CLI / Visual Studio sign-in).

**Examples:**
```bash
# Sign with Azure Key Vault (uses DefaultAzureCredential)
cosesigntool sign-akv-cert document.txt \
    --akv-vault https://myvault.vault.azure.net \
    --akv-cert-name signing-cert \
    --output document.cose

# Pin to a specific certificate version
cosesigntool sign-akv-cert document.txt \
    --akv-vault https://myvault.vault.azure.net \
    --akv-cert-name signing-cert \
    --akv-cert-version 0123456789abcdef0123456789abcdef \
    --output document.cose
```

---

### sign-azure

Sign with Azure Trusted Signing.

```bash
cosesigntool sign-azure [<payload>] [options]
```

**Required Options:**
| Option | Description |
|--------|-------------|
| `--ats-endpoint <uri>` | Azure Trusted Signing endpoint |
| `--ats-account-name <name>` | Trusted Signing account name |
| `--ats-cert-profile-name <name>` | Certificate profile name |

**Optional:**
| Option | Description |
|--------|-------------|
| `--output`, `-o` | Output file path |
| `--signature-type`, `-t` | Type: `embedded`, `detached`, `indirect` |
| `--content-type`, `-c` | Content type header |

Authentication uses `DefaultAzureCredential`. Configure credentials via environment variables, Managed Identity, or developer tooling (Azure CLI / Visual Studio sign-in).

---

### sign-akv-key

Sign with an Azure Key Vault key.

```bash
cosesigntool sign-akv-key [<payload>] [options]
```

**Required Options:**
| Option | Description |
|--------|-------------|
| `--akv-vault <uri>` | Azure Key Vault URL (e.g., https://my-vault.vault.azure.net) |
| `--akv-key-name <name>` | Name of the key in Azure Key Vault |

**Optional:**
| Option | Description |
|--------|-------------|
| `--akv-key-version <version>` | Specific key version (uses latest if omitted) |
| `--akv-refresh-interval <minutes>` | Auto-refresh interval in minutes (default: 15, 0 to disable) |
| `--output`, `-o` | Output file path |
| `--signature-type`, `-t` | Type: `embedded`, `detached`, `indirect` |
| `--content-type`, `-c` | Content type header |

Authentication uses `DefaultAzureCredential`. Configure credentials via environment variables, Managed Identity, or developer tooling (Azure CLI / Visual Studio sign-in).

**Examples:**
```bash
# Sign with Azure Trusted Signing
cosesigntool sign-azure document.txt \
    --ats-endpoint https://wus.codesigning.azure.net \
    --ats-account-name myaccount \
    --ats-cert-profile-name production-profile \
    --output document.cose
```

---

## Signature Types

| Type | Description | Use Case |
|------|-------------|----------|
| `embedded` | Payload included in signature | Single-file distribution |
| `detached` | Payload separate from signature | Large files, existing files |
| `indirect` | Signs hash, not payload | Very large payloads |

---

## Exit Codes

| Code | Description |
|------|-------------|
| 0 | Success |
| 1 | Invalid arguments |
| 2 | Validation failed |
| 3 | Signing failed |
| 4 | File not found |
| 5 | Certificate error |
| 99 | General error |

---

## Logging

### Console Verbosity

```bash
# Quiet (errors only)
cosesigntool verify document.cose -q

# Debug output
cosesigntool verify document.cose -vv

# Trace output
cosesigntool verify document.cose -vvv
```

### Log Files

```bash
# Write all logs to file
cosesigntool verify document.cose --log-file verify.log

# Append to existing log
cosesigntool verify document.cose --log-file verify.log --log-file-append

# JSON formatted logs
cosesigntool verify document.cose --log-file verify.json --output-format json
```

See [Logging and Diagnostics](../guides/logging-diagnostics.md) for details.

---

## Plugins

CoseSignTool supports plugins for additional signing and verification capabilities.

### Loading Plugins

Plugins are automatically loaded from `plugins/` subdirectory. Additional directories can be specified:

```bash
cosesigntool --additional-plugin-dir /path/to/plugins verify document.cose
```

### Bundled Plugins

| Plugin | Commands |
|--------|----------|
| Local | `sign-pfx`, `sign-pem`, `sign-certstore`, `sign-ephemeral` |
| Azure Key Vault | `sign-akv-cert`, `sign-akv-key` |
| Azure Trusted Signing | `sign-azure` |
| MST | (verification only) |

See [Plugin Development](../plugins/README.md) for creating custom plugins.
