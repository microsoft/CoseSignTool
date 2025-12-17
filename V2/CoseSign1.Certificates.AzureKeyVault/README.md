# CoseSign1.Certificates.AzureKeyVault

A `RemoteCertificateSource` implementation for Azure Key Vault certificates, enabling COSE Sign1 signing with certificates stored in Azure Key Vault.

## Features

- **Remote Signing**: Private keys never leave Azure Key Vault (HSM-backed or software-protected)
- **Auto-Refresh Mode**: Automatically detects and uses new certificate versions (default: every 15 minutes)
- **Pinned Version Mode**: Lock to a specific certificate version for reproducible signatures
- **Seamless Integration**: Works directly with `CertificateSigningService.Create()` factory method - no custom signing service needed

## Installation

```bash
dotnet add package CoseSign1.Certificates.AzureKeyVault
```

## Usage

### Auto-Refresh Mode (Recommended for Long-Running Services)

```csharp
using Azure.Identity;
using CoseSign1.Certificates.AzureKeyVault;
using CoseSign1.Certificates;

// Create certificate source with auto-refresh (checks every 15 minutes)
var source = await AzureKeyVaultCertificateSource.CreateAsync(
    new Uri("https://myvault.vault.azure.net"),
    "my-signing-cert",
    new DefaultAzureCredential());

// Use with the CertificateSigningService factory method
var signingService = CertificateSigningService.Create(source);

// Sign documents - certificate auto-rotates when renewed in Key Vault
var signer = signingService.GetCoseSigner(context);
```

### Custom Refresh Interval

```csharp
// Check for new certificate versions every 5 minutes
var source = await AzureKeyVaultCertificateSource.CreateAsync(
    new Uri("https://myvault.vault.azure.net"),
    "my-signing-cert",
    new DefaultAzureCredential(),
    refreshInterval: TimeSpan.FromMinutes(5));
```

### Pinned Version Mode (Reproducible Signatures)

```csharp
// Pin to a specific certificate version - no auto-refresh
var source = await AzureKeyVaultCertificateSource.CreateAsync(
    new Uri("https://myvault.vault.azure.net"),
    "my-signing-cert",
    new DefaultAzureCredential(),
    certificateVersion: "abc123def456...");

// Will always use this exact certificate version
```

### Manual Refresh

```csharp
// Manually check for and apply a new certificate version
bool wasUpdated = await source.RefreshCertificateAsync();
if (wasUpdated)
{
    Console.WriteLine($"Certificate updated to version: {source.Version}");
}
```

## Supported Key Types

| Key Type | Algorithms |
|----------|------------|
| RSA | PS256, PS384, PS512, RS256, RS384, RS512 |
| RSA-HSM | PS256, PS384, PS512, RS256, RS384, RS512 |
| EC | ES256, ES384, ES512 |
| EC-HSM | ES256, ES384, ES512 |

> **Note**: ML-DSA (post-quantum) is not yet supported by Azure Key Vault.

## Authentication

This library uses Azure SDK's `TokenCredential` for flexible authentication:

```csharp
// Development - uses VS, CLI, etc.
new DefaultAzureCredential()

// Production - managed identity
new ManagedIdentityCredential()

// Service principal
new ClientSecretCredential(tenantId, clientId, clientSecret)
```

## X.509 Chain Headers

When used with `CertificateSigningService.Create()`, the standard X.509 certificate chain headers are automatically added to COSE signatures:

- **x5t (34)**: Certificate thumbprint
- **x5chain (33)**: Full certificate chain (leaf-first)

## Thread Safety

`AzureKeyVaultCertificateSource` is thread-safe. The auto-refresh mechanism uses proper locking to ensure certificate updates are atomic.
