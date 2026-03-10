# CoseSign1.AzureKeyVault

A COSE signing service for Azure Key Vault keys (non-certificate signing).

This library provides an `ISigningService<SigningOptions>` implementation that uses Azure Key Vault keys for COSE signing operations. Unlike certificate-based signing, this uses standalone cryptographic keys and adds RFC 9052-compliant key identification headers (kid) to identify the signing key.

## Features

- **Key-only signing**: Sign with AKV keys that don't have associated certificates
- **HSM support**: Works with both software-protected and HSM-protected keys
- **RFC 9052 compliant**: Adds `kid` (Key ID) header to identify the signing key
- **Auto-refresh support**: Automatically check for key updates (rotation scenarios)
- **Pinned version mode**: Lock to a specific key version for consistency
- **Algorithm detection**: Automatically selects appropriate COSE algorithm based on key type

## Installation

```bash
dotnet add package CoseSign1.AzureKeyVault
```

## Usage

### Basic Usage with Latest Key Version

```csharp
using Azure.Identity;
using CoseSign1.AzureKeyVault;

// Create with auto-refresh (checks for new versions every 15 minutes)
var signingService = await AzureKeyVaultSigningService.CreateAsync(
    new Uri("https://my-vault.vault.azure.net/"),
    "my-signing-key",
    new DefaultAzureCredential());

// Get a signer with kid header
var signer = signingService.GetCoseSigner();

// Sign content
byte[] content = Encoding.UTF8.GetBytes("Hello, World!");
var signResult = CoseSign1Message.SignDetached(content, signer);
```

### Pinned Key Version (No Auto-refresh)

```csharp
// Pin to a specific key version
var signingService = await AzureKeyVaultSigningService.CreateAsync(
    new Uri("https://my-vault.vault.azure.net/"),
    "my-signing-key",
    version: "abc123def456...", // Specific version
    new DefaultAzureCredential());

// IsPinnedVersion will be true
Console.WriteLine($"Pinned: {signingService.IsPinnedVersion}");
```

### Custom Auto-refresh Interval

```csharp
// Check for new key versions every 5 minutes
var signingService = await AzureKeyVaultSigningService.CreateAsync(
    new Uri("https://my-vault.vault.azure.net/"),
    "my-signing-key",
    new DefaultAzureCredential(),
    autoRefreshInterval: TimeSpan.FromMinutes(5));
```

### Manual Refresh

```csharp
// Force check for a new key version
bool keyChanged = await signingService.RefreshKeyAsync();
if (keyChanged)
{
    Console.WriteLine("Key was rotated - using new version");
}
```

### Creating Signing Options

```csharp
// Create signing options for use with higher-level APIs
SigningOptions options = signingService.CreateSigningOptions();
```

## Key Identification (RFC 9052)

This service automatically adds a `kid` (Key ID) header per RFC 9052 Section 3.1. The header value is the full Azure Key Vault key URI:

```
https://my-vault.vault.azure.net/keys/my-key/version123
```

This allows verifiers to:
1. Identify which key was used for signing
2. Retrieve the public key from Key Vault for verification
3. Handle key rotation scenarios

### Header Structure

```json
{
  "protected": {
    "alg": -37,  // PS256, ES256, etc. based on key type
    "kid": "https://my-vault.vault.azure.net/keys/my-key/version123"
  }
}
```

## Supported Key Types

| Key Type | COSE Algorithms |
|----------|-----------------|
| RSA (2048) | PS256 |
| RSA (3072) | PS384 |
| RSA (4096) | PS512 |
| RSA-HSM | PS256/384/512 |
| EC P-256 | ES256 |
| EC P-384 | ES384 |
| EC P-521 | ES512 |
| EC-HSM | ES256/384/512 |

## Authentication

This library uses `Azure.Identity` for authentication. Common credential types:

```csharp
// For development (uses VS, VS Code, Azure CLI, etc.)
new DefaultAzureCredential()

// For managed identity
new ManagedIdentityCredential()
new ManagedIdentityCredential("client-id") // User-assigned

// For service principals
new ClientSecretCredential(tenantId, clientId, clientSecret)

// For interactive scenarios
new InteractiveBrowserCredential()
```

## Required Permissions

The identity needs these Key Vault permissions:

**Data Plane (Keys)**:
- `keys/get` - Read key metadata and public key
- `keys/sign` - Perform signing operations

For Azure RBAC, assign one of:
- `Key Vault Crypto User` - For sign operations only
- `Key Vault Crypto Officer` - For full key management

## Comparison with CoseSign1.Certificates.AzureKeyVault

| Feature | CoseSign1.AzureKeyVault | CoseSign1.Certificates.AzureKeyVault |
|---------|-------------------------|--------------------------------------|
| **Use case** | Key-only signing | Certificate-based signing |
| **Key identification** | `kid` header (Key URI) | Certificate chain in headers |
| **Verification** | Retrieve public key from AKV | Certificate chain validation |
| **Trust model** | Explicit key trust | PKI/certificate trust |
| **Best for** | Internal systems, HSM keys | External/cross-org trust |

## Thread Safety

The `AzureKeyVaultSigningService` is thread-safe for concurrent signing operations. The auto-refresh mechanism uses proper locking to ensure key updates are atomic.

## License

MIT License - See LICENSE file for details.
