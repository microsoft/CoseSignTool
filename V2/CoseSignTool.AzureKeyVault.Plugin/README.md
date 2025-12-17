# CoseSignTool.AzureKeyVault.Plugin

Azure Key Vault plugin for CoseSignTool providing two signing modes:
1. **Certificate-based signing** (`sign-akv-cert`) - Uses certificates with optional auto-refresh
2. **Key-only signing** (`sign-akv-key`) - Uses keys directly with RFC 9052 kid headers

## Installation

The plugin is loaded automatically when placed in the CoseSignTool plugins directory.

## Commands

### sign-akv-cert - Certificate-based Signing

Sign using a certificate stored in Azure Key Vault. The certificate's private key operations are performed remotely in Key Vault while the certificate chain is embedded in the COSE signature.

```bash
cosesigntool sign-akv-cert \
    --akv-vault https://my-vault.vault.azure.net \
    --akv-cert-name my-signing-cert \
    --payload payload.bin \
    --output signature.cose
```

#### Options

| Option | Required | Description |
|--------|----------|-------------|
| `--akv-vault` | Yes | Azure Key Vault URL |
| `--akv-cert-name` | Yes | Certificate name in Key Vault |
| `--akv-cert-version` | No | Specific version (uses latest if omitted) |
| `--akv-refresh-interval` | No | Auto-refresh interval in minutes (default: 15, 0 to disable) |

### sign-akv-key - Key-only Signing

Sign using a key stored in Azure Key Vault (no certificate). Adds RFC 9052 compliant `kid` header to identify the signing key.

```bash
cosesigntool sign-akv-key \
    --akv-vault https://my-vault.vault.azure.net \
    --akv-key-name my-signing-key \
    --payload payload.bin \
    --output signature.cose
```

#### Options

| Option | Required | Description |
|--------|----------|-------------|
| `--akv-vault` | Yes | Azure Key Vault URL |
| `--akv-key-name` | Yes | Key name in Key Vault |
| `--akv-key-version` | No | Specific version (uses latest if omitted) |
| `--akv-refresh-interval` | No | Auto-refresh interval in minutes (default: 15, 0 to disable) |

## Auto-Refresh Behavior

By default, both commands check for new versions every 15 minutes. This supports key/certificate rotation scenarios.

### Pinned Version Mode

To lock to a specific version (disable auto-refresh):

```bash
# Pin to specific certificate version
cosesigntool sign-akv-cert \
    --akv-vault https://my-vault.vault.azure.net \
    --akv-cert-name my-cert \
    --akv-cert-version abc123def456 \
    --payload payload.bin

# Pin to specific key version
cosesigntool sign-akv-key \
    --akv-vault https://my-vault.vault.azure.net \
    --akv-key-name my-key \
    --akv-key-version xyz789abc123 \
    --payload payload.bin
```

### Custom Refresh Interval

```bash
# Check for updates every 5 minutes
cosesigntool sign-akv-cert \
    --akv-vault https://my-vault.vault.azure.net \
    --akv-cert-name my-cert \
    --akv-refresh-interval 5 \
    --payload payload.bin

# Disable auto-refresh (but still use latest version at startup)
cosesigntool sign-akv-cert \
    --akv-vault https://my-vault.vault.azure.net \
    --akv-cert-name my-cert \
    --akv-refresh-interval 0 \
    --payload payload.bin
```

## When to Use Each Command

| Use Case | Command |
|----------|---------|
| Standard PKI trust model | `sign-akv-cert` |
| Cross-organization verification | `sign-akv-cert` |
| Internal systems with explicit key trust | `sign-akv-key` |
| HSM-protected keys without certificates | `sign-akv-key` |
| Minimal signature size | `sign-akv-key` |

## Authentication

The plugin uses `DefaultAzureCredential` which supports:
- Environment variables
- Managed Identity
- Azure CLI
- Azure PowerShell
- Visual Studio / VS Code

### Required Permissions

For **certificates** (`sign-akv-cert`):
- `certificates/get` - Read certificate metadata
- `keys/sign` - Sign with the certificate's key

For **keys** (`sign-akv-key`):
- `keys/get` - Read key metadata
- `keys/sign` - Sign with the key

Azure RBAC role `Key Vault Crypto User` provides these permissions.

## Signature Headers

### Certificate Signing (sign-akv-cert)

Includes full X.509 certificate chain in COSE headers for PKI-based verification.

### Key Signing (sign-akv-key)

Includes RFC 9052 `kid` header with the Key Vault key URI:

```json
{
  "protected": {
    "alg": -37,
    "kid": "https://my-vault.vault.azure.net/keys/my-key/version123"
  }
}
```

## License

MIT License - See LICENSE file for details.
