# cose_sign1_azure_trusted_signing

Azure Trusted Signing extension pack for the COSE Sign1 SDK.

Provides integration with [Microsoft Azure Trusted Signing](https://learn.microsoft.com/en-us/azure/trusted-signing/),
a cloud-based HSM-backed signing service with FIPS 140-2 Level 3 compliance.

## Features

- **Signing**: `AzureTrustedSigningService` implementing `SigningService` trait
- **Validation**: `AzureTrustedSigningTrustPack` with ATS-specific fact types  
- **DID:x509**: Auto-construction of DID:x509 identifiers from ATS certificate chains
- **REST Client**: Full implementation via `azure_trusted_signing_client` sub-crate

## Architecture

This crate is composed of two main components:

1. **`azure_trusted_signing_client`** (sub-crate) — Pure REST API client for Azure Trusted Signing
2. **Main crate** — COSE Sign1 integration layer implementing signing and validation traits

## Usage

### Creating a Trusted Signing Client

```rust
use azure_trusted_signing_client::{CertificateProfileClient, CertificateProfileClientOptions};

// Configure client
let options = CertificateProfileClientOptions::new(
    "https://eus.codesigning.azure.net", // endpoint
    "my-account",                        // account name
    "my-profile"                         // certificate profile name
);

// Create client with Azure Identity
let client = CertificateProfileClient::new_dev(options)?;
```

### Using AzureTrustedSigningCertificateSource

```rust
use cose_sign1_azure_trusted_signing::signing::certificate_source::AzureTrustedSigningCertificateSource;

// Create certificate source
let cert_source = AzureTrustedSigningCertificateSource::new(client);

// Retrieve certificate chain (cached)
let chain = cert_source.get_certificate_chain().await?;
let did_x509 = cert_source.get_did_x509().await?;
```

### Using AzureTrustedSigningService as a SigningService

```rust
use cose_sign1_azure_trusted_signing::AzureTrustedSigningService;
use cose_sign1_azure_trusted_signing::options::AzureTrustedSigningOptions;
use cose_sign1_signing::SigningService;

// Create options
let options = AzureTrustedSigningOptions::new(
    "https://eus.codesigning.azure.net",
    "my-account", 
    "my-profile"
);

// Create signing service
let signing_service = AzureTrustedSigningService::new(options);

// Get a COSE signer
let signer = signing_service.get_cose_signer().await?;

// Verify signature (post-sign validation)
let is_valid = signing_service.verify_signature(&payload, &signature).await?;
```

### Feature Flags

This crate does not expose any optional Cargo features — all functionality is enabled by default.

### Dependencies

Key dependencies include:
- **`azure_trusted_signing_client`** — REST API client (sub-crate)
- **`azure_core`** + **`azure_identity`** — Azure SDK authentication
- **`cose_sign1_signing`** — Signing service traits
- **`cose_sign1_validation`** — Trust pack traits
- **`did_x509`** — DID:x509 identifier construction
- **`tokio`** — Async runtime (required for Azure SDK)

## Client Sub-Crate

The `azure_trusted_signing_client` sub-crate provides a complete REST client implementation. 
See [`client/README.md`](client/README.md) for detailed client API documentation including:

- Sign operations with Long-Running Operation (LRO) polling
- Certificate chain and root certificate retrieval  
- Extended Key Usage (EKU) information
- Comprehensive error handling
- Authentication via Azure Identity

## Authentication

Authentication is handled via Azure Identity. The client supports:
- `DeveloperToolsCredential` (recommended for local development)
- `ManagedIdentityCredential` 
- `ClientSecretCredential`
- Any type implementing `azure_core::credentials::TokenCredential`

Auth scope is automatically constructed as `{endpoint}/.default`.