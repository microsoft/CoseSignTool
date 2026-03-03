// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Signing provider registry.
//!
//! Each provider is gated behind a feature flag. At compile time, only the
//! enabled providers are included.

use super::{SigningProvider, SigningProviderArgs};

/// DER key file provider — always available when crypto-openssl is enabled.
#[cfg(feature = "crypto-openssl")]
pub struct DerKeySigningProvider;

#[cfg(feature = "crypto-openssl")]
impl SigningProvider for DerKeySigningProvider {
    fn name(&self) -> &str {
        "der"
    }

    fn description(&self) -> &str {
        "Sign with a DER-encoded PKCS#8 private key file"
    }

    fn create_signer(
        &self,
        args: &SigningProviderArgs,
    ) -> Result<Box<dyn crypto_primitives::CryptoSigner>, anyhow::Error> {
        let key_path = args
            .key_path
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("--key is required for DER provider"))?;
        let key_der = std::fs::read(key_path)
            .map_err(|e| anyhow::anyhow!("Failed to read key file: {}", e))?;
        let provider = super::crypto::active_provider();
        provider
            .signer_from_der(&key_der)
            .map_err(|e| anyhow::anyhow!("Failed to create signer: {}", e))
    }
}

/// PFX/PKCS#12 signing provider.
///
/// Maps V2 `PfxSigningCommandProvider` (command: "x509-pfx").
/// CLI: `cosesigntool sign --provider pfx --pfx cert.pfx`
#[cfg(feature = "crypto-openssl")]
pub struct PfxSigningProvider;

#[cfg(feature = "crypto-openssl")]
impl SigningProvider for PfxSigningProvider {
    fn name(&self) -> &str {
        "pfx"
    }

    fn description(&self) -> &str {
        "Sign with a PFX/PKCS#12 certificate file"
    }

    fn create_signer(
        &self,
        args: &SigningProviderArgs,
    ) -> Result<Box<dyn crypto_primitives::CryptoSigner>, anyhow::Error> {
        let pfx_path = args
            .pfx_path
            .as_ref()
            .or(args.key_path.as_ref()) // fallback: --key can be a PFX too
            .ok_or_else(|| anyhow::anyhow!("--pfx or --key is required for PFX provider"))?;
        let pfx_bytes = std::fs::read(pfx_path)?;
        let password = args.pfx_password.as_deref().unwrap_or("");
        // Use OpenSSL to parse PFX and extract private key DER
        let pkcs12 = openssl::pkcs12::Pkcs12::from_der(&pfx_bytes)
            .map_err(|e| anyhow::anyhow!("Invalid PFX file: {}", e))?;
        let parsed = pkcs12
            .parse2(password)
            .map_err(|e| anyhow::anyhow!("Failed to parse PFX (wrong password?): {}", e))?;
        let pkey = parsed
            .pkey
            .ok_or_else(|| anyhow::anyhow!("PFX contains no private key"))?;
        let key_der = pkey
            .private_key_to_der()
            .map_err(|e| anyhow::anyhow!("Failed to extract DER key from PFX: {}", e))?;
        let provider = super::crypto::active_provider();
        provider
            .signer_from_der(&key_der)
            .map_err(|e| anyhow::anyhow!("Failed to create signer: {}", e))
    }
}

/// PEM signing provider.
///
/// Maps V2 `PemSigningCommandProvider` (command: "x509-pem").
/// CLI: `cosesigntool sign --provider pem --cert-file cert.pem --key-file key.pem`
#[cfg(feature = "crypto-openssl")]
pub struct PemSigningProvider;

#[cfg(feature = "crypto-openssl")]
impl SigningProvider for PemSigningProvider {
    fn name(&self) -> &str {
        "pem"
    }

    fn description(&self) -> &str {
        "Sign with PEM certificate and private key files"
    }

    fn create_signer(
        &self,
        args: &SigningProviderArgs,
    ) -> Result<Box<dyn crypto_primitives::CryptoSigner>, anyhow::Error> {
        let key_path = args
            .key_file
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("--key-file is required for PEM provider"))?;
        let pem_bytes = std::fs::read(key_path)?;
        let pkey = openssl::pkey::PKey::private_key_from_pem(&pem_bytes)
            .map_err(|e| anyhow::anyhow!("Invalid PEM private key: {}", e))?;
        let key_der = pkey
            .private_key_to_der()
            .map_err(|e| anyhow::anyhow!("Failed to convert PEM to DER: {}", e))?;
        let provider = super::crypto::active_provider();
        provider
            .signer_from_der(&key_der)
            .map_err(|e| anyhow::anyhow!("Failed to create signer: {}", e))
    }
}

/// Ephemeral signing provider — generates a throwaway certificate for testing.
///
/// Maps V2 `EphemeralSigningCommandProvider` (command: "x509-ephemeral").
/// CLI: `cosesigntool sign --provider ephemeral --subject "CN=Test"`
#[cfg(all(feature = "crypto-openssl", feature = "certificates"))]
pub struct EphemeralSigningProvider;

#[cfg(all(feature = "crypto-openssl", feature = "certificates"))]
impl SigningProvider for EphemeralSigningProvider {
    fn name(&self) -> &str {
        "ephemeral"
    }

    fn description(&self) -> &str {
        "Sign with an auto-generated ephemeral certificate (testing only)"
    }

    fn create_signer(
        &self,
        args: &SigningProviderArgs,
    ) -> Result<Box<dyn crypto_primitives::CryptoSigner>, anyhow::Error> {
        Ok(self.create_signer_with_chain(args)?.signer)
    }

    fn create_signer_with_chain(
        &self,
        args: &SigningProviderArgs,
    ) -> Result<super::SignerWithChain, anyhow::Error> {
        use cose_sign1_certificates_local::{
            EphemeralCertificateFactory, SoftwareKeyProvider,
            options::CertificateOptions, traits::CertificateFactory,
        };
        use cose_sign1_crypto_openssl::OpenSslCryptoProvider;
        use crypto_primitives::CryptoProvider;

        // Determine subject name from args or use default
        let subject = args.subject.as_deref().unwrap_or("CN=CoseSignTool Ephemeral");

        // Determine key algorithm from args
        let key_algorithm = match args.algorithm.as_deref() {
            #[cfg(feature = "pqc")]
            Some("mldsa") => cose_sign1_certificates_local::key_algorithm::KeyAlgorithm::MlDsa,
            #[cfg(not(feature = "pqc"))]
            Some("mldsa") => return Err(anyhow::anyhow!(
                "ML-DSA requires the 'pqc' feature. Rebuild with: cargo build --features pqc"
            )),
            _ => cose_sign1_certificates_local::key_algorithm::KeyAlgorithm::Ecdsa,
        };

        // Create the factory with a software key provider
        let key_provider = Box::new(SoftwareKeyProvider::new());
        let factory = EphemeralCertificateFactory::new(key_provider);

        // Build certificate options
        let mut options = CertificateOptions::default()
            .with_subject_name(subject)
            .with_key_algorithm(key_algorithm);
        if let Some(size) = args.key_size {
            options = options.with_key_size(size);
        }

        // Generate the certificate + key
        let cert = factory.create_certificate(options)
            .map_err(|e| anyhow::anyhow!("Failed to create ephemeral certificate: {}", e))?;

        // Compute thumbprint before moving key_der out
        let thumbprint = hex::encode(cert.thumbprint_sha256());
        let cert_der = cert.cert_der.clone();

        let key_der = cert.private_key_der
            .ok_or_else(|| anyhow::anyhow!("Ephemeral certificate has no private key"))?;

        // Create a CryptoSigner from the private key DER
        let provider = OpenSslCryptoProvider;
        let signer = provider.signer_from_der(&key_der)
            .map_err(|e| anyhow::anyhow!("Failed to create signer from ephemeral key: {}", e))?;

        tracing::info!(
            subject = subject,
            thumbprint = %thumbprint,
            "Generated ephemeral signing certificate"
        );

        Ok(super::SignerWithChain {
            signer,
            cert_chain: vec![cert_der],
        })
    }
}

/// AKV certificate signing provider.
///
/// Maps V2 `AzureKeyVaultCertificateCommandProvider` (command: "x509-akv-cert").
/// CLI: `cosesigntool sign --provider akv-cert --vault-url https://my.vault.azure.net --cert-name my-cert`
#[cfg(feature = "akv")]
pub struct AkvCertSigningProvider;

#[cfg(feature = "akv")]
impl SigningProvider for AkvCertSigningProvider {
    fn name(&self) -> &str {
        "akv-cert"
    }

    fn description(&self) -> &str {
        "Sign using a certificate from Azure Key Vault"
    }

    fn create_signer(
        &self,
        args: &SigningProviderArgs,
    ) -> Result<Box<dyn crypto_primitives::CryptoSigner>, anyhow::Error> {
        let vault_url = args.vault_url.as_ref()
            .ok_or_else(|| anyhow::anyhow!("--akv-vault is required for AKV cert provider"))?;
        let cert_name = args.cert_name.as_ref()
            .ok_or_else(|| anyhow::anyhow!("--akv-cert-name is required for AKV cert provider"))?;
        let cert_version = args.cert_version.as_deref();

        // Create AKV key client with DeveloperToolsCredential
        let client = cose_sign1_azure_key_vault::common::akv_key_client::AkvKeyClient::new_dev(
            vault_url, cert_name, cert_version,
        ).map_err(|e| anyhow::anyhow!("Failed to create AKV client: {}", e))?;

        // Create signing key from the AKV client
        let signing_key = cose_sign1_azure_key_vault::signing::akv_signing_key::AzureKeyVaultSigningKey::new(
            Box::new(client),
        ).map_err(|e| anyhow::anyhow!("Failed to create AKV signing key: {}", e))?;

        Ok(Box::new(signing_key))
    }
}

/// AKV key-only signing provider (no certificate, kid header only).
///
/// Maps V2 `AzureKeyVaultKeyCommandProvider` (command: "akv-key").
/// CLI: `cosesigntool sign --provider akv-key --akv-vault https://my.vault.azure.net --akv-key-name my-key`
#[cfg(feature = "akv")]
pub struct AkvKeySigningProvider;

#[cfg(feature = "akv")]
impl SigningProvider for AkvKeySigningProvider {
    fn name(&self) -> &str {
        "akv-key"
    }

    fn description(&self) -> &str {
        "Sign using a key from Azure Key Vault (kid header, no certificate)"
    }

    fn create_signer(
        &self,
        args: &SigningProviderArgs,
    ) -> Result<Box<dyn crypto_primitives::CryptoSigner>, anyhow::Error> {
        let vault_url = args.vault_url.as_ref()
            .ok_or_else(|| anyhow::anyhow!("--akv-vault is required for AKV key provider"))?;
        let key_name = args.key_name.as_ref()
            .ok_or_else(|| anyhow::anyhow!("--akv-key-name is required for AKV key provider"))?;
        let key_version = args.key_version.as_deref();

        // Create AKV key client with DeveloperToolsCredential
        let client = cose_sign1_azure_key_vault::common::akv_key_client::AkvKeyClient::new_dev(
            vault_url, key_name, key_version,
        ).map_err(|e| anyhow::anyhow!("Failed to create AKV client: {}", e))?;

        // Create signing key from the AKV client
        let signing_key = cose_sign1_azure_key_vault::signing::akv_signing_key::AzureKeyVaultSigningKey::new(
            Box::new(client),
        ).map_err(|e| anyhow::anyhow!("Failed to create AKV signing key: {}", e))?;

        Ok(Box::new(signing_key))
    }
}

/// Azure Trusted Signing provider.
///
/// Maps V2 `AzureTrustedSigningCommandProvider` (command: "x509-ats").
/// CLI: `cosesigntool sign --provider ats --ats-endpoint https://... --ats-account <name> --ats-profile <name>`
#[cfg(feature = "ats")]
pub struct AtsSigningProvider;

#[cfg(feature = "ats")]
impl SigningProvider for AtsSigningProvider {
    fn name(&self) -> &str {
        "ats"
    }

    fn description(&self) -> &str {
        "Sign using Azure Trusted Signing service"
    }

    fn create_signer(
        &self,
        args: &SigningProviderArgs,
    ) -> Result<Box<dyn crypto_primitives::CryptoSigner>, anyhow::Error> {
        let endpoint = args.ats_endpoint.as_ref()
            .ok_or_else(|| anyhow::anyhow!("--ats-endpoint is required for ATS provider"))?;
        let account = args.ats_account.as_ref()
            .ok_or_else(|| anyhow::anyhow!("--ats-account-name is required for ATS provider"))?;
        let profile = args.ats_profile.as_ref()
            .ok_or_else(|| anyhow::anyhow!("--ats-cert-profile-name is required for ATS provider"))?;

        // Create ATS signing service options
        let options = cose_sign1_azure_trusted_signing::options::AzureTrustedSigningOptions {
            endpoint: endpoint.clone(),
            account_name: account.clone(),
            certificate_profile_name: profile.clone(),
        };

        // Create the ATS certificate source with DefaultAzureCredential
        let source = cose_sign1_azure_trusted_signing::signing::certificate_source::AzureTrustedSigningCertificateSource::new(options)
            .map_err(|e| anyhow::anyhow!("Failed to create ATS client: {}", e))?;

        // Create AtsCryptoSigner (remote signing via ATS HSM)
        let signer = cose_sign1_azure_trusted_signing::signing::ats_crypto_signer::AtsCryptoSigner::new(
            std::sync::Arc::new(source),
            "PS256".to_string(),
            -37, // COSE PS256
            "RSA".to_string(),
        );

        Ok(Box::new(signer))
    }
}

/// Collect all available signing providers based on compile-time features.
pub fn available_providers() -> Vec<Box<dyn SigningProvider>> {
    let mut providers: Vec<Box<dyn SigningProvider>> = Vec::new();

    #[cfg(feature = "crypto-openssl")]
    {
        providers.push(Box::new(DerKeySigningProvider));
        providers.push(Box::new(PfxSigningProvider));
        providers.push(Box::new(PemSigningProvider));
    }

    #[cfg(all(feature = "crypto-openssl", feature = "certificates"))]
    providers.push(Box::new(EphemeralSigningProvider));

    #[cfg(feature = "akv")]
    {
        providers.push(Box::new(AkvCertSigningProvider));
        providers.push(Box::new(AkvKeySigningProvider));
    }
    
    #[cfg(feature = "ats")]
    providers.push(Box::new(AtsSigningProvider));

    providers
}

/// Look up a signing provider by name.
pub fn find_provider(name: &str) -> Option<Box<dyn SigningProvider>> {
    available_providers().into_iter().find(|p| p.name() == name)
}