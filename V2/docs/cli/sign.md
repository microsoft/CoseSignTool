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
| `--pfx-file <path>` | Path to PFX certificate file (required) |
| `--output <path>` | Output signature file path |
| `--content-type <type>` | Content type header value |
| `--signature-type <type>` | Signature type: `embedded`, `detached`, `indirect` (default: `indirect`) |

> **Note:** Set the PFX password via the `COSESIGNTOOL_PFX_PASSWORD` environment variable.

### Example

```bash
set COSESIGNTOOL_PFX_PASSWORD=my-password
CoseSignTool sign-pfx document.json --pfx-file cert.pfx --output signed.cose
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
| `--algorithm <alg>` | Signing algorithm: `ES256`, `ES384`, `PS256`, etc. |
| `--signature-type <type>` | Signature type: `embedded`, `detached`, `indirect` (default: `indirect`) |

### Example

```bash
CoseSignTool sign-ephemeral document.json --output test.cose
```

> **Warning:** Ephemeral certificates are self-signed and should not be used in production.

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
