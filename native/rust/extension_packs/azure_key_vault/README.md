# cose_sign1_azure_key_vault

Azure Key Vault COSE signing and validation support pack.

This crate provides Azure Key Vault integration for both signing and validating COSE_Sign1 messages.

## Signing

The signing module provides Azure Key Vault backed signing services:

### Basic Key Signing

```rust
use cose_sign1_azure_key_vault::signing::{AzureKeyVaultSigningService};
use cose_sign1_azure_key_vault::common::AkvKeyClient;
use cose_sign1_signing::SigningContext;
use azure_identity::DeveloperToolsCredential;

// Create AKV client 
let client = AkvKeyClient::new_dev("https://myvault.vault.azure.net", "my-key", None)?;

// Create signing service
let mut service = AzureKeyVaultSigningService::new(Box::new(client))?;
service.initialize()?;

// Sign a message
let context = SigningContext::new(payload.as_bytes());
let signer = service.get_cose_signer(&context)?;
// Use signer with COSE_Sign1 message...
```

### Certificate-based Signing  

```rust
use cose_sign1_azure_key_vault::signing::AzureKeyVaultCertificateSource;
use cose_sign1_certificates::signing::remote::RemoteCertificateSource;

// Create certificate source
let cert_source = AzureKeyVaultCertificateSource::new(Box::new(client));
let (cert_der, chain_ders) = cert_source.fetch_certificate()?;

// Use with certificate signing service...
```

## Validation

- `cargo run -p cose_sign1_validation_azure_key_vault --example akv_kid_allowed`

Docs: [native/rust/docs/azure-key-vault-pack.md](../docs/azure-key-vault-pack.md).
