<!-- Copyright (c) Microsoft Corporation. Licensed under the MIT License. -->

# cose_sign1_azure_key_vault

Azure Key Vault signing and validation extension pack for COSE_Sign1.

## Overview

This crate provides Azure Key Vault integration for both signing and validating
COSE_Sign1 messages. It enables remote signing with keys stored in Azure Key
Vault or Managed HSM, and validates that messages were signed with AKV-backed
keys via kid (key ID) header inspection.

Key capabilities:

- **Remote signing** with Azure Key Vault keys (EC and RSA)
- **Certificate source** for AKV-stored certificates with chain fetching
- **Key ID (kid) trust validation** with configurable allowlists
- **Public key embedding** in COSE protected or unprotected headers
- **Fluent trust policy DSL** for AKV-specific validation rules

## Architecture

```
┌────────────────────────────────────────────────────────┐
│            cose_sign1_azure_key_vault                   │
├─────────────┬──────────────────┬───────────────────────┤
│  common/    │  signing/        │  validation/           │
│  ├ AkvKey   │  ├ AzureKeyVault │  ├ AzureKeyVault       │
│  │  Client  │  │  SigningService│  │  TrustPack          │
│  ├ KeyVault │  ├ AzureKeyVault │  ├ Trust facts          │
│  │  Crypto  │  │  SigningKey   │  │  (kid-based)         │
│  │  Client  │  ├ AzureKeyVault │  └ Fluent DSL           │
│  │  (trait) │  │  Certificate  │    extensions            │
│  └ AkvError │  │  Source       │                          │
│             │  ├ KeyIdHeader   │                          │
│             │  │  Contributor  │                          │
│             │  └ CoseKeyHeader │                          │
│             │    Contributor   │                          │
├─────────────┴──────────────────┴───────────────────────┤
│  azure_identity / azure_security_keyvault_keys (SDK)    │
└────────────────────────────────────────────────────────┘
         │                        │
         ▼                        ▼
  cose_sign1_signing      cose_sign1_validation
  cose_sign1_certificates cose_sign1_validation_primitives
```

## Modules

| Module | Description |
|--------|-------------|
| `common` | `KeyVaultCryptoClient` trait, `AkvKeyClient` implementation, `AkvError` |
| `signing` | Signing key, signing service, certificate source, header contributors |
| `validation` | Trust pack, trust facts (kid detection/allowed), fluent DSL extensions |

## Key Types

### Common

- **`KeyVaultCryptoClient`** (trait) — Abstraction over Azure Key Vault crypto operations: sign, key metadata, public key retrieval.
- **`AkvKeyClient`** — Concrete implementation using the Azure SDK `KeyClient`. Supports EC (P-256, P-384, P-521) and RSA keys.
- **`AkvError`** — Error type with variants for crypto failures, key not found, authentication errors, and network issues.

### Signing

- **`AzureKeyVaultSigningService`** — Implements `SigningService`. Wraps an `AkvKeyClient` to perform remote signing. Automatically contributes kid and optionally embeds the COSE_Key in headers.
- **`AzureKeyVaultSigningKey`** — Implements `CryptoSigner` and `SigningServiceKey`. Signs data by sending digests to Azure Key Vault. Caches the COSE_Key CBOR representation.
- **`AzureKeyVaultCertificateSource`** — Implements `CertificateSource` and `RemoteCertificateSource`. Fetches certificate and chain from AKV, delegates signing to the AKV crypto client.
- **`KeyIdHeaderContributor`** — Implements `HeaderContributor`. Adds the AKV key ID (kid, label 4) to protected headers.
- **`CoseKeyHeaderContributor`** — Implements `HeaderContributor`. Embeds the public COSE_Key at a private-use label (-65537) in protected or unprotected headers.
- **`CoseKeyHeaderLocation`** — Enum: `Protected` (signed) or `Unprotected` (not signed).

### Validation

- **`AzureKeyVaultTrustPack`** — Implements `CoseSign1TrustPack` and `TrustFactProducer`. Inspects the kid header to detect AKV key IDs and validates them against an allowlist of URL patterns.
- **`AzureKeyVaultTrustOptions`** — Configuration for kid pattern allowlisting and AKV requirement enforcement.
- **`AzureKeyVaultKidDetectedFact`** — Whether the message kid looks like an AKV key identifier.
- **`AzureKeyVaultKidAllowedFact`** — Whether the kid matches an allowed pattern.

## Usage

### Basic Key Signing

```rust
use cose_sign1_azure_key_vault::signing::AzureKeyVaultSigningService;
use cose_sign1_azure_key_vault::common::AkvKeyClient;
use cose_sign1_signing::{SigningService, SigningContext};

// Create AKV client with developer credentials (local dev)
let client = AkvKeyClient::new_dev(
    "https://myvault.vault.azure.net",
    "my-signing-key",
    None, // latest version
)?;

// Create and initialize the signing service
let mut service = AzureKeyVaultSigningService::new(Box::new(client))?;
service.initialize()?;

// Get a signer — kid is automatically added to protected headers
let context = SigningContext::new(payload);
let signer = service.get_cose_signer(&context)?;
```

### Signing with Service Principal Credentials

```rust
use cose_sign1_azure_key_vault::common::AkvKeyClient;
use azure_identity::ClientSecretCredential;
use std::sync::Arc;

let credential = Arc::new(ClientSecretCredential::new(
    "tenant-id",
    "client-id",
    "client-secret",
    Default::default(),
));

let client = AkvKeyClient::new(
    "https://myvault.vault.azure.net",
    "my-signing-key",
    Some("key-version"),
    credential,
)?;
```

### Embedding the Public Key in Headers

```rust
use cose_sign1_azure_key_vault::signing::{
    AzureKeyVaultSigningService, CoseKeyHeaderLocation,
};

let mut service = AzureKeyVaultSigningService::new(Box::new(client))?;
service.initialize()?;

// Embed public key in unprotected headers (not signed)
service.enable_public_key_embedding(CoseKeyHeaderLocation::Unprotected)?;

// Or embed in protected headers (signed, tamper-proof)
service.enable_public_key_embedding(CoseKeyHeaderLocation::Protected)?;
```

### Certificate-Based Signing with AKV

```rust
use cose_sign1_azure_key_vault::signing::AzureKeyVaultCertificateSource;
use cose_sign1_certificates::CertificateSource;

let mut cert_source = AzureKeyVaultCertificateSource::new(Box::new(crypto_client));

// Fetch certificate and chain from Key Vault
let (cert_der, chain) = cert_source.fetch_certificate(
    "https://myvault.vault.azure.net",
    "my-certificate",
    credential,
)?;

// Initialize the source with fetched data
cert_source.initialize(cert_der, chain)?;

// Use with CertificateSigningService from cose_sign1_certificates
let signing_cert = cert_source.get_signing_certificate()?;
```

### Validating AKV-Signed Messages

```rust
use cose_sign1_azure_key_vault::validation::{
    AzureKeyVaultTrustPack, AzureKeyVaultTrustOptions,
};
use cose_sign1_validation::fluent::*;
use std::sync::Arc;

// Default options: require AKV kid, allow *.vault.azure.net and *.managedhsm.azure.net
let pack = AzureKeyVaultTrustPack::new(AzureKeyVaultTrustOptions::default());

let validator = ValidatorBuilder::new()
    .with_trust_pack(Arc::new(pack))
    .build()?;

let result = validator.validate(&cose_bytes, None)?;
```

### Custom KID Allowlist

```rust
use cose_sign1_azure_key_vault::validation::AzureKeyVaultTrustOptions;

let options = AzureKeyVaultTrustOptions {
    // Only allow keys from a specific vault
    allowed_kid_patterns: vec![
        "https://myvault.vault.azure.net/keys/*".into(),
    ],
    require_azure_key_vault_kid: true,
};
```

### Custom Trust Policies with the Fluent DSL

```rust
use cose_sign1_azure_key_vault::validation::fluent_ext::*;
use cose_sign1_azure_key_vault::validation::facts::*;
use cose_sign1_validation::fluent::*;

let plan = TrustPlanBuilder::new(vec![pack.clone()])
    .for_message(|msg| {
        msg.require_azure_key_vault_kid()
           .require_azure_key_vault_kid_allowed()
    })
    .compile()?;
```

## Supported Key Types and Algorithms

| Key Type | Curve / Size | COSE Algorithm | AKV Algorithm |
|----------|-------------|----------------|---------------|
| EC | P-256 | ES256 (-7) | ES256 |
| EC | P-384 | ES384 (-35) | ES384 |
| EC | P-521 | ES512 (-36) | ES512 |
| RSA | 2048+ | PS256 (-37) | PS256 |
| RSA | 2048+ | PS384 (-38) | PS384 |
| RSA | 2048+ | PS512 (-39) | PS512 |

Algorithm selection is automatic based on the key type and curve stored in
Azure Key Vault.

## Configuration

### AzureKeyVaultTrustOptions

```rust
pub struct AzureKeyVaultTrustOptions {
    /// URL patterns for allowed AKV key IDs.
    /// Supports wildcards (*) and regex (prefix with "regex:").
    /// Default: ["https://*.vault.azure.net/keys/*",
    ///           "https://*.managedhsm.azure.net/keys/*"]
    pub allowed_kid_patterns: Vec<String>,
    /// Require the kid header to be an AKV key identifier.
    /// Default: true
    pub require_azure_key_vault_kid: bool,
}
```

**Pattern matching:**
- `*` matches any characters within a segment
- `?` matches a single character
- Prefix with `regex:` for full regex support

### AkvKeyClient Constructors

| Constructor | Authentication | Use Case |
|-------------|---------------|----------|
| `AkvKeyClient::new(url, name, ver, credential)` | Any `TokenCredential` | Production |
| `AkvKeyClient::new_dev(url, name, ver)` | `DeveloperToolsCredential` | Local development |
| `AkvKeyClient::new_with_options(url, name, ver, cred, opts)` | Custom | Advanced configuration |

## Error Handling

All AKV operations return `AkvError`:

```rust
pub enum AkvError {
    CryptoOperationFailed(String),
    KeyNotFound(String),
    InvalidKeyType(String),
    AuthenticationFailed(String),
    NetworkError(String),
    InvalidConfiguration(String),
    CertificateSourceError(String),
    General(String),
}
```

Signing operations wrap `AkvError` into `SigningError` (from `cose_sign1_signing`).
Validation errors are reported through the trust fact system — failed kid
detection or allowlist checks produce facts with `false` values rather than
hard errors.

## Dependencies

- `cose_sign1_primitives` — Core COSE types
- `cose_sign1_signing` — Signing service traits
- `cose_sign1_certificates` — Certificate source trait
- `cose_sign1_validation` — Validation framework
- `cose_sign1_validation_primitives` — Trust fact types (with `regex` feature)
- `cose_sign1_crypto_openssl` — OpenSSL crypto provider
- `azure_core` — Azure SDK core (with reqwest + native TLS)
- `azure_identity` — Azure authentication (service principal, developer tools)
- `azure_security_keyvault_keys` — Azure Key Vault keys client
- `tokio` — Async runtime for Azure SDK calls
- `sha2` — Digest computation
- `regex` — KID pattern matching

## See Also

- [Azure Key Vault Pack documentation](../../docs/azure-key-vault-pack.md)
- [cose_sign1_signing](../../signing/core/) — Signing traits
- [cose_sign1_certificates](../certificates/) — Certificate trust pack (used for AKV certificate signing)
- [cose_sign1_validation](../../validation/core/) — Validation framework
