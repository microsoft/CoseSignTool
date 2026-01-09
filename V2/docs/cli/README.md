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
| `-q`, `--quiet` | Suppress output except errors (verbosity 0) |
| `-vv` | Debug verbosity (level 3) |
| `-vvv` | Trace verbosity (level 4) |
| `--verbosity <N>` | Set verbosity level (0-4) |
| `--log-file <path>` | Write logs to file |
| `--log-file-append` | Append to existing log file |
| `--output-format <format>` | Output format: text, json, xml, quiet |
| `--additional-plugin-dir <path>` | Load plugins from additional directory |
| `-h`, `--help` | Show help |
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
| `--payload <file>` | Detached payload file |
| `--signature-only` | Skip payload verification |
| `--trust-roots <files>` | Custom trust root certificates |
| `--allow-untrusted` | Allow self-signed certificates |
| `--subject-name <name>` | Required certificate subject name |

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
cosesigntool inspect <file> [options]
```

**Arguments:**
- `<file>` - Path to COSE signature file

**Options:**
| Option | Description |
|--------|-------------|
| `--extract-payload <path>` | Extract embedded payload to file |
| `--show-headers` | Show all COSE headers |
| `--show-certificate` | Show signing certificate details |

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
cosesigntool sign-pfx <payload> [options]
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
| `--pfx-password <password>` | PFX password (insecure, prefer --pfx-password-file) |
| `--pfx-password-file <file>` | File containing PFX password |
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
cosesigntool sign-pem <payload> [options]
```

**Required Options:**
| Option | Description |
|--------|-------------|
| `--cert <file>` | Path to PEM certificate file |
| `--key <file>` | Path to PEM private key file |

**Optional:**
| Option | Description |
|--------|-------------|
| `--key-password <password>` | Private key password |
| `--key-password-file <file>` | File containing key password |
| `--chain <file>` | Certificate chain PEM file |
| `--output`, `-o` | Output file path |
| `--signature-type`, `-t` | Type: `embedded`, `detached`, `indirect` |
| `--content-type`, `-c` | Content type header |

**Examples:**
```bash
# Sign with PEM files
cosesigntool sign-pem document.txt --cert cert.pem --key key.pem --output document.cose

# Sign with certificate chain
cosesigntool sign-pem document.txt --cert cert.pem --key key.pem --chain chain.pem --output document.cose
```

---

### sign-cert-store

Sign with a certificate from Windows Certificate Store.

```bash
cosesigntool sign-cert-store <payload> [options]
```

**Required Options (one of):**
| Option | Description |
|--------|-------------|
| `--thumbprint <hash>` | Certificate thumbprint (SHA1) |
| `--subject-name <name>` | Certificate subject name |

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
cosesigntool sign-cert-store document.txt --thumbprint ABC123... --output document.cose

# Sign with certificate by subject name
cosesigntool sign-cert-store document.txt --subject-name "CN=My Signer" --output document.cose
```

---

### sign-ephemeral

Sign with a temporary self-signed certificate (development/testing only).

```bash
cosesigntool sign-ephemeral <payload> [options]
```

**Optional:**
| Option | Description |
|--------|-------------|
| `--subject-name <name>` | Subject name (default: "CN=Ephemeral") |
| `--key-size <bits>` | RSA key size (default: 2048) |
| `--algorithm <algo>` | Signing algorithm |
| `--output`, `-o` | Output file path |
| `--signature-type`, `-t` | Type: `embedded`, `detached`, `indirect` |

**Examples:**
```bash
# Quick test signing
cosesigntool sign-ephemeral document.txt --output document.cose

# With custom subject
cosesigntool sign-ephemeral document.txt --subject-name "CN=Test Signer" --output document.cose
```

> **Warning**: Ephemeral certificates should only be used for testing. The private key is discarded after signing.

---

### sign-akv-cert

Sign with an Azure Key Vault certificate.

```bash
cosesigntool sign-akv-cert <payload> [options]
```

**Required Options:**
| Option | Description |
|--------|-------------|
| `--vault-uri <uri>` | Azure Key Vault URI |
| `--cert-name <name>` | Certificate name in vault |

**Optional:**
| Option | Description |
|--------|-------------|
| `--cert-version <version>` | Specific certificate version |
| `--tenant-id <id>` | Azure AD tenant ID |
| `--client-id <id>` | Azure AD client ID |
| `--client-secret <secret>` | Azure AD client secret |
| `--output`, `-o` | Output file path |
| `--signature-type`, `-t` | Type: `embedded`, `detached`, `indirect` |

**Examples:**
```bash
# Sign with Azure Key Vault (uses DefaultAzureCredential)
cosesigntool sign-akv-cert document.txt \
    --vault-uri https://myvault.vault.azure.net \
    --cert-name signing-cert \
    --output document.cose

# Sign with service principal
cosesigntool sign-akv-cert document.txt \
    --vault-uri https://myvault.vault.azure.net \
    --cert-name signing-cert \
    --tenant-id $TENANT_ID \
    --client-id $CLIENT_ID \
    --client-secret $CLIENT_SECRET \
    --output document.cose
```

---

### sign-ats

Sign with Azure Trusted Signing.

```bash
cosesigntool sign-ats <payload> [options]
```

**Required Options:**
| Option | Description |
|--------|-------------|
| `--endpoint <uri>` | Azure Trusted Signing endpoint |
| `--account-name <name>` | Trusted Signing account name |
| `--certificate-profile <name>` | Certificate profile name |

**Optional:**
| Option | Description |
|--------|-------------|
| `--tenant-id <id>` | Azure AD tenant ID |
| `--client-id <id>` | Azure AD client ID |
| `--client-secret <secret>` | Azure AD client secret |
| `--output`, `-o` | Output file path |
| `--signature-type`, `-t` | Type: `embedded`, `detached`, `indirect` |

**Examples:**
```bash
# Sign with Azure Trusted Signing
cosesigntool sign-ats document.txt \
    --endpoint https://wus.codesigning.azure.net \
    --account-name myaccount \
    --certificate-profile production-profile \
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
| Local | `sign-pfx`, `sign-pem`, `sign-cert-store`, `sign-ephemeral` |
| Azure Key Vault | `sign-akv-cert` |
| Azure Trusted Signing | `sign-ats` |
| MST | (verification only) |

See [Plugin Development](../plugins/README.md) for creating custom plugins.
