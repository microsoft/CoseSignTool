# CoseSign1.AzureKeyVault.Common

Common utilities and abstractions for Azure Key Vault COSE signing operations.

## Overview

This library provides shared code for Azure Key Vault signing operations, used by both:
- `CoseSign1.Certificates.AzureKeyVault` - Certificate-based signing
- `CoseSign1.AzureKeyVault` - Key-only signing

## Key Components

### KeyVaultCryptoClientWrapper

A wrapper around Azure Key Vault's `CryptographyClient` that provides a consistent signing interface:

```csharp
// Create wrapper for a specific key
var wrapper = await KeyVaultCryptoClientWrapper.CreateAsync(
    keyClient,
    credential,
    "my-key",
    version: null); // null for latest

// Sign with RSA
byte[] signature = await wrapper.SignHashWithRsaAsync(
    hash, 
    HashAlgorithmName.SHA256, 
    RSASignaturePadding.Pss);

// Sign with ECDSA
byte[] signature = await wrapper.SignHashWithEcdsaAsync(hash);
```

### KeyVaultAlgorithmMapper

Maps .NET cryptographic algorithms to Azure Key Vault SignatureAlgorithm:

```csharp
// RSA algorithm mapping
var akvAlg = KeyVaultAlgorithmMapper.MapRsaAlgorithm(
    HashAlgorithmName.SHA256, 
    RSASignaturePadding.Pss); // Returns SignatureAlgorithm.PS256

// ECDSA algorithm mapping
var akvAlg = KeyVaultAlgorithmMapper.MapEcdsaAlgorithm(32); // Returns ES256 for SHA-256 hash
```

## Azure Key Vault Architecture

Azure Key Vault certificates have three planes:

| Plane | Purpose | API |
|-------|---------|-----|
| `/certificates` | X.509 metadata management | CertificateClient |
| `/keys` | Private key operations (HSM/software) | CryptographyClient |
| `/secrets` | Exportable PFX/PEM material | SecretClient |

### HSM-Protected Keys

For HSM-backed certificates and keys:
- Private key never leaves Key Vault
- All signing happens via `CryptographyClient`
- This wrapper provides the signing abstraction

### Software-Protected (Exportable) Keys

For exportable certificates:
- Can download PFX/PEM via `/secrets`
- Can sign locally with downloaded key
- Use standard .NET crypto instead of this wrapper

## License

MIT License - See LICENSE file for details.
