# Sign Commands

The CoseSignTool CLI provides multiple sign commands through plugins. Each command supports different certificate sources.

## Available Sign Commands

Sign commands are provided by CLI plugins:

### Local Plugin Commands

| Command | Description |
|---------|-------------|
| `sign-pfx` | Sign using a PFX/PKCS#12 certificate file |
| `sign-certstore` | Sign using Windows/Linux certificate store |
| `sign-pem` | Sign using PEM-encoded certificate and key |
| `sign-ephemeral` | Sign using temporary self-signed certificate |

### Azure Plugin Commands

| Command | Description |
|---------|-------------|
| `sign-akv-cert` | Sign using an Azure Key Vault certificate |
| `sign-akv-key` | Sign using an Azure Key Vault key (adds `kid` header) |
| `sign-azure` | Sign using Azure Trusted Signing |

## sign-pfx

Sign using a PFX/PKCS#12 certificate file.

### Synopsis

```bash
CoseSignTool sign-pfx <input-file> [options]
```

### Options

| Option | Description |
|--------|-------------|
| `--pfx <path>` | Path to PFX/PKCS#12 file containing the signing certificate (required) |
| `--pfx-password-file <path>` | Path to a file containing the PFX password (more secure than command-line) |
| `--pfx-password-env <name>` | Name of environment variable containing the PFX password (default: `COSESIGNTOOL_PFX_PASSWORD`) |
| `--pfx-password-prompt` | Prompt for password interactively (automatic if no password is provided) |
| `--output <path>` | Output signature file path |
| `--content-type <type>` | Content type header value |
| `--signature-type <type>` | Signature type: `embedded`, `detached`, `indirect` (default: `indirect`) |

> **Note:** Provide the PFX password using `--pfx-password-file`, `--pfx-password-env`, `--pfx-password-prompt`, or the `COSESIGNTOOL_PFX_PASSWORD` environment variable.

### Example

```bash
set COSESIGNTOOL_PFX_PASSWORD=my-password
CoseSignTool sign-pfx document.json --pfx cert.pfx --output signed.cose
```

## sign-certstore

Sign using a certificate from the system certificate store.

### Synopsis

```bash
CoseSignTool sign-certstore <input-file> [options]
```

### Options

| Option | Description |
|--------|-------------|
| `--thumbprint <hex>` | Certificate thumbprint (required) |
| `--store-name <name>` | Store name: `My`, `Root`, `CA`, etc. |
| `--store-location <loc>` | Store location: `CurrentUser` or `LocalMachine` |
| `--output <path>` | Output signature file path |
| `--content-type <type>` | Content type header value |
| `--signature-type <type>` | Signature type: `embedded`, `detached`, `indirect` (default: `indirect`) |

### Example

```bash
CoseSignTool sign-certstore document.json ^
    --thumbprint ABC123DEF456... ^
    --store-name My ^
    --store-location CurrentUser ^
    --output signed.cose
```

## sign-pem

Sign using PEM-encoded certificate and private key files.

### Synopsis

```bash
CoseSignTool sign-pem <input-file> [options]
```

### Options

| Option | Description |
|--------|-------------|
| `--cert-file <path>` | Path to PEM certificate file (required) |
| `--key-file <path>` | Path to PEM private key file (required) |
| `--output <path>` | Output signature file path |
| `--content-type <type>` | Content type header value |
| `--signature-type <type>` | Signature type: `embedded`, `detached`, `indirect` (default: `indirect`) |

> **Note:** Set the key password via the `COSESIGNTOOL_KEY_PASSWORD` environment variable if the key is encrypted.

### Example

```bash
CoseSignTool sign-pem document.json ^
    --cert-file certificate.pem ^
    --key-file private-key.pem ^
    --output signed.cose
```

## sign-ephemeral

Sign using a temporary self-signed certificate. **For testing only.**

### Synopsis

```bash
CoseSignTool sign-ephemeral <input-file> [options]
```

### Options

| Option | Description |
|--------|-------------|
| `--output <path>` | Output signature file path |
| `--content-type <type>` | Content type header value |
| `--config <path>` | Path to JSON configuration file for certificate settings |
| `--subject <subject>` | Certificate subject name (overrides config) |
| `--algorithm <ECDSA|MLDSA|RSA>` | Key algorithm (default: RSA). `MLDSA` is post-quantum and Windows-only |
| `--key-size <n>` | Key size. Defaults: RSA=4096, ECDSA=384, MLDSA=65 |
| `--validity-days <n>` | Certificate validity period in days (default: 365) |
| `--no-chain` | Generate a self-signed certificate instead of a full chain |
| `--minimal` | Minimal configuration (RSA-2048, self-signed, 1 day validity) |
| `--pqc` | Post-quantum quick mode (MLDSA-65 with full chain) |
| `--signature-type <type>` | Signature type: `embedded`, `detached`, `indirect` (default: `indirect`) |

### Example

```bash
CoseSignTool sign-ephemeral document.json --output test.cose
```

> **Warning:** Ephemeral certificates are self-signed and should not be used in production.

## sign-akv-cert

Sign using a certificate stored in Azure Key Vault.

### Synopsis

```bash
CoseSignTool sign-akv-cert <input-file> [options]
```

### Options

| Option | Description |
|--------|-------------|
| `--akv-vault <uri>` | Azure Key Vault URL (required) |
| `--akv-cert-name <name>` | Certificate name (required) |
| `--akv-cert-version <version>` | Certificate version (optional; uses latest if omitted) |
| `--akv-refresh-interval <minutes>` | Auto-refresh interval in minutes (default: 15, 0 to disable) |
| `--output <path>` | Output signature file path |
| `--content-type <type>` | Content type header value |
| `--signature-type <type>` | Signature type: `embedded`, `detached`, `indirect` (default: `indirect`) |

Authentication uses `DefaultAzureCredential` (non-interactive). Configure credentials via environment variables (e.g., `AZURE_TENANT_ID`, `AZURE_CLIENT_ID`, `AZURE_CLIENT_SECRET`) or Managed Identity.

### Example

```bash
CoseSignTool sign-akv-cert document.json ^
    --akv-vault https://my-vault.vault.azure.net ^
    --akv-cert-name signing-cert ^
    --output signed.cose
```

## sign-akv-key

Sign using a key stored in Azure Key Vault (no certificate). This adds a `kid` header per RFC 9052.

### Synopsis

```bash
CoseSignTool sign-akv-key <input-file> [options]
```

### Options

| Option | Description |
|--------|-------------|
| `--akv-vault <uri>` | Azure Key Vault URL (required) |
| `--akv-key-name <name>` | Key name (required) |
| `--akv-key-version <version>` | Key version (optional; uses latest if omitted) |
| `--akv-refresh-interval <minutes>` | Auto-refresh interval in minutes (default: 15, 0 to disable) |
| `--output <path>` | Output signature file path |
| `--content-type <type>` | Content type header value |
| `--signature-type <type>` | Signature type: `embedded`, `detached`, `indirect` (default: `indirect`) |

Authentication uses `DefaultAzureCredential` (non-interactive). Configure credentials via environment variables (e.g., `AZURE_TENANT_ID`, `AZURE_CLIENT_ID`, `AZURE_CLIENT_SECRET`) or Managed Identity.

### Example

```bash
CoseSignTool sign-akv-key document.json ^
    --akv-vault https://my-vault.vault.azure.net ^
    --akv-key-name signing-key ^
    --output signed.cose
```

## sign-azure

Sign using Azure Trusted Signing (requires Azure plugin).

### Synopsis

```bash
CoseSignTool sign-azure <input-file> [options]
```

### Options

| Option | Description |
|--------|-------------|
| `--ats-endpoint <uri>` | Azure Trusted Signing endpoint (required) |
| `--ats-account-name <name>` | Account name (required) |
| `--ats-cert-profile-name <name>` | Certificate profile name (required) |
| `--output <path>` | Output signature file path |
| `--content-type <type>` | Content type header value |
| `--signature-type <type>` | Signature type: `embedded`, `detached`, `indirect` (default: `indirect`) |

### Example

```bash
CoseSignTool sign-azure document.json ^
    --ats-endpoint https://myaccount.codesigning.azure.net ^
    --ats-account-name myaccount ^
    --ats-cert-profile-name myprofile ^
    --output signed.cose
```

## Common Options

All sign commands support these common options:

| Option | Description |
|--------|-------------|
| `--output <path>`, `-o` | Output file path (default: `<input>.cose`) |
| `--content-type <type>`, `-c` | MIME type for content type header |
| `--signature-type <type>`, `-t` | Signature type: `embedded`, `detached`, `indirect` (default: `indirect`) |
| `--hash-algorithm <alg>` | Hash algorithm for indirect signatures (default: `SHA256`) |

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success |
| 1 | Signing failed |
| 2 | Error (file not found, invalid certificate, etc.) |

## See Also

- [Verify Command](verify.md) - Verify signatures
- [Inspect Command](inspect.md) - Inspect signatures
- [Local Plugin](../plugins/local-plugin.md) - Local signing plugin details
- [Azure Plugin](../plugins/azure-plugin.md) - Azure signing plugin details
