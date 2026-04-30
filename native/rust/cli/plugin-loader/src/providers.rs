// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Built-in plugin provider implementations hosted by the plugin loader.

use anyhow::{anyhow, Context, Result};
use cose_sign1_certificates::chain_builder::ExplicitCertificateChainBuilder;
use cose_sign1_certificates::error::CertificateError;
use cose_sign1_certificates::signing::certificate_signing_options::CertificateSigningOptions;
use cose_sign1_certificates::signing::certificate_signing_service::CertificateSigningService;
use cose_sign1_certificates::signing::signing_key_provider::SigningKeyProvider;
use cose_sign1_certificates::signing::source::CertificateSource;
use cose_sign1_certificates_local::{
    loaders::{pem, pfx},
    Certificate, CertificateFactory, CertificateOptions, EphemeralCertificateFactory,
    SoftwareKeyProvider,
};
use cose_sign1_crypto_openssl::OpenSslCryptoProvider;
use cose_sign1_factories::{
    direct::{DirectSignatureFactory, DirectSignatureOptions},
    indirect::{IndirectSignatureFactory, IndirectSignatureOptions},
};
use cose_sign1_headers::{CwtClaims, CwtClaimsHeaderContributor};
use cose_sign1_primitives::CoseHeaderLabel;
use cose_sign1_signing::{SigningContext, SigningService};
use cosesigntool_plugin_api::traits::{
    PluginCapability, PluginCommandDef, PluginConfig, PluginInfo, PluginOptionDef, PluginProvider,
};
use crypto_primitives::{
    CryptoError, CryptoProvider, CryptoSigner, SigningContext as CryptoSigningContext,
};
use std::collections::HashMap;
use std::sync::Arc;

#[cfg(feature = "aas")]
use cose_sign1_azure_artifact_signing::options::AzureArtifactSigningOptions;
#[cfg(feature = "aas")]
use cose_sign1_azure_artifact_signing::signing::signing_service::AzureArtifactSigningService;
#[cfg(feature = "akv")]
use cose_sign1_azure_key_vault::common::AkvKeyClient;
#[cfg(feature = "akv")]
use cose_sign1_azure_key_vault::signing::AzureKeyVaultSigningService;

#[derive(Default)]
struct ServiceStore {
    services: HashMap<String, Arc<dyn SigningService>>,
    next_service_id: u64,
}

impl ServiceStore {
    fn insert(&mut self, prefix: &str, service: Arc<dyn SigningService>) -> String {
        self.next_service_id += 1;
        let service_id = format!("{prefix}-{}", self.next_service_id);
        self.services.insert(service_id.clone(), service);
        service_id
    }

    fn get(&self, service_id: &str) -> Result<Arc<dyn SigningService>, String> {
        self.services
            .get(service_id)
            .cloned()
            .ok_or_else(|| format!("Unknown service_id: {service_id}"))
    }
}

pub fn create_provider(name: &str) -> Result<Box<dyn PluginProvider>> {
    match name {
        "local-pfx" => Ok(Box::new(LocalPfxProvider::default())),
        "local-pem" => Ok(Box::new(LocalPemProvider::default())),
        "local-ephemeral" => Ok(Box::new(LocalEphemeralProvider::default())),
        #[cfg(feature = "aas")]
        "aas" => Ok(Box::new(AasProvider::default())),
        #[cfg(feature = "akv")]
        "akv" => Ok(Box::new(AkvProvider::key())),
        #[cfg(feature = "akv")]
        "akv-cert" => Ok(Box::new(AkvProvider::certificate())),
        _ => anyhow::bail!("Unknown plugin: {name}"),
    }
}

pub fn available_plugins() -> Vec<&'static str> {
    let mut plugins = vec!["local-ephemeral", "local-pem", "local-pfx"];
    #[cfg(feature = "aas")]
    plugins.push("aas");
    #[cfg(feature = "akv")]
    {
        plugins.push("akv");
        plugins.push("akv-cert");
    }
    plugins
}

#[derive(Default)]
pub struct LocalPfxProvider {
    store: ServiceStore,
}

impl PluginProvider for LocalPfxProvider {
    fn info(&self) -> PluginInfo {
        plugin_info(
            "local-pfx",
            "Local PFX Provider",
            "Loads a local PFX/PKCS#12 certificate for signing.",
            &[plugin_command(
                "pfx",
                "Sign with a local PFX/PKCS#12 certificate.",
                local_pfx_options(),
            )],
        )
    }

    fn create_service(&mut self, config: PluginConfig) -> Result<String, String> {
        let service = create_local_pfx_service(&config).map_err(|error| error.to_string())?;
        Ok(self.store.insert("local-pfx-service", Arc::new(service)))
    }

    fn get_cert_chain(&mut self, service_id: &str) -> Result<Vec<Vec<u8>>, String> {
        service_cert_chain(&self.store.get(service_id)?)
    }

    fn get_algorithm(&mut self, service_id: &str) -> Result<i64, String> {
        service_algorithm(&self.store.get(service_id)?)
    }

    fn sign(&mut self, service_id: &str, data: &[u8], algorithm: i64) -> Result<Vec<u8>, String> {
        service_sign(&self.store.get(service_id)?, data, algorithm)
    }

    fn sign_payload(
        &mut self,
        service_id: &str,
        payload: &[u8],
        content_type: &str,
        format: &str,
        options: &PluginConfig,
    ) -> Result<Vec<u8>, String> {
        sign_payload_with_service(&self.store.get(service_id)?, payload, content_type, format, options)
    }
}

#[derive(Default)]
pub struct LocalPemProvider {
    store: ServiceStore,
}

impl PluginProvider for LocalPemProvider {
    fn info(&self) -> PluginInfo {
        plugin_info(
            "local-pem",
            "Local PEM Provider",
            "Loads local PEM certificate and key files for signing.",
            &[plugin_command(
                "pem",
                "Sign with local PEM certificate and key files.",
                local_pem_options(),
            )],
        )
    }

    fn create_service(&mut self, config: PluginConfig) -> Result<String, String> {
        let service = create_local_pem_service(&config).map_err(|error| error.to_string())?;
        Ok(self.store.insert("local-pem-service", Arc::new(service)))
    }

    fn get_cert_chain(&mut self, service_id: &str) -> Result<Vec<Vec<u8>>, String> {
        service_cert_chain(&self.store.get(service_id)?)
    }

    fn get_algorithm(&mut self, service_id: &str) -> Result<i64, String> {
        service_algorithm(&self.store.get(service_id)?)
    }

    fn sign(&mut self, service_id: &str, data: &[u8], algorithm: i64) -> Result<Vec<u8>, String> {
        service_sign(&self.store.get(service_id)?, data, algorithm)
    }

    fn sign_payload(
        &mut self,
        service_id: &str,
        payload: &[u8],
        content_type: &str,
        format: &str,
        options: &PluginConfig,
    ) -> Result<Vec<u8>, String> {
        sign_payload_with_service(&self.store.get(service_id)?, payload, content_type, format, options)
    }
}

#[derive(Default)]
pub struct LocalEphemeralProvider {
    store: ServiceStore,
}

impl PluginProvider for LocalEphemeralProvider {
    fn info(&self) -> PluginInfo {
        plugin_info(
            "local-ephemeral",
            "Local Ephemeral Provider",
            "Creates an in-memory certificate for signing test payloads.",
            &[plugin_command(
                "ephemeral",
                "Sign with an ephemeral in-memory certificate.",
                vec![PluginOptionDef {
                    name: "subject".to_string(),
                    value_name: "subject".to_string(),
                    description: "Certificate subject (CN=...).".to_string(),
                    required: false,
                    default_value: Some("CN=CoseSignTool Ephemeral".to_string()),
                    short: None,
                    is_flag: false,
                }],
            )],
        )
    }

    fn create_service(&mut self, config: PluginConfig) -> Result<String, String> {
        let service = create_local_ephemeral_service(&config).map_err(|error| error.to_string())?;
        Ok(self.store.insert("local-ephemeral-service", Arc::new(service)))
    }

    fn get_cert_chain(&mut self, service_id: &str) -> Result<Vec<Vec<u8>>, String> {
        service_cert_chain(&self.store.get(service_id)?)
    }

    fn get_algorithm(&mut self, service_id: &str) -> Result<i64, String> {
        service_algorithm(&self.store.get(service_id)?)
    }

    fn sign(&mut self, service_id: &str, data: &[u8], algorithm: i64) -> Result<Vec<u8>, String> {
        service_sign(&self.store.get(service_id)?, data, algorithm)
    }

    fn sign_payload(
        &mut self,
        service_id: &str,
        payload: &[u8],
        content_type: &str,
        format: &str,
        options: &PluginConfig,
    ) -> Result<Vec<u8>, String> {
        sign_payload_with_service(&self.store.get(service_id)?, payload, content_type, format, options)
    }
}

#[cfg(feature = "aas")]
#[derive(Default)]
pub struct AasProvider {
    store: ServiceStore,
}

#[cfg(feature = "aas")]
impl PluginProvider for AasProvider {
    fn info(&self) -> PluginInfo {
        plugin_info(
            "aas",
            "Azure Artifact Signing Provider",
            "Uses Azure Artifact Signing for remote certificate-backed signing.",
            &[plugin_command(
                "aas",
                "Sign with Azure Artifact Signing cloud service.",
                aas_options(),
            )],
        )
    }

    fn create_service(&mut self, config: PluginConfig) -> Result<String, String> {
        let service = create_aas_service(&config).map_err(|error| error.to_string())?;
        Ok(self.store.insert("aas-service", Arc::new(service)))
    }

    fn get_cert_chain(&mut self, service_id: &str) -> Result<Vec<Vec<u8>>, String> {
        service_cert_chain(&self.store.get(service_id)?)
    }

    fn get_algorithm(&mut self, service_id: &str) -> Result<i64, String> {
        service_algorithm(&self.store.get(service_id)?)
    }

    fn sign(&mut self, service_id: &str, data: &[u8], algorithm: i64) -> Result<Vec<u8>, String> {
        service_sign(&self.store.get(service_id)?, data, algorithm)
    }

    fn sign_payload(
        &mut self,
        service_id: &str,
        payload: &[u8],
        content_type: &str,
        format: &str,
        options: &PluginConfig,
    ) -> Result<Vec<u8>, String> {
        sign_payload_with_service(&self.store.get(service_id)?, payload, content_type, format, options)
    }
}

#[cfg(feature = "akv")]
enum AkvMode {
    Key,
    Certificate,
}

#[cfg(feature = "akv")]
pub struct AkvProvider {
    store: ServiceStore,
    mode: AkvMode,
}

#[cfg(feature = "akv")]
impl AkvProvider {
    fn key() -> Self {
        Self {
            store: ServiceStore::default(),
            mode: AkvMode::Key,
        }
    }

    fn certificate() -> Self {
        Self {
            store: ServiceStore::default(),
            mode: AkvMode::Certificate,
        }
    }
}

#[cfg(feature = "akv")]
impl PluginProvider for AkvProvider {
    fn info(&self) -> PluginInfo {
        match self.mode {
            AkvMode::Key => plugin_info(
                "akv",
                "Azure Key Vault Key Provider",
                "Uses Azure Key Vault keys for remote signing.",
                &[plugin_command(
                    "akv",
                    "Sign using Azure Key Vault key.",
                    akv_key_options(),
                )],
            ),
            AkvMode::Certificate => plugin_info(
                "akv",
                "Azure Key Vault Certificate Provider",
                "Uses Azure Key Vault certificates for remote signing.",
                &[plugin_command(
                    "akv-cert",
                    "Sign using Azure Key Vault certificate.",
                    akv_cert_options(),
                )],
            ),
        }
    }

    fn create_service(&mut self, config: PluginConfig) -> Result<String, String> {
        let service = match self.mode {
            AkvMode::Key => create_akv_key_service(&config),
            AkvMode::Certificate => create_akv_certificate_service(&config),
        }
        .map_err(|error| error.to_string())?;
        Ok(self.store.insert("akv-service", Arc::new(service)))
    }

    fn get_cert_chain(&mut self, service_id: &str) -> Result<Vec<Vec<u8>>, String> {
        service_cert_chain(&self.store.get(service_id)?)
    }

    fn get_algorithm(&mut self, service_id: &str) -> Result<i64, String> {
        service_algorithm(&self.store.get(service_id)?)
    }

    fn sign(&mut self, service_id: &str, data: &[u8], algorithm: i64) -> Result<Vec<u8>, String> {
        service_sign(&self.store.get(service_id)?, data, algorithm)
    }

    fn sign_payload(
        &mut self,
        service_id: &str,
        payload: &[u8],
        content_type: &str,
        format: &str,
        options: &PluginConfig,
    ) -> Result<Vec<u8>, String> {
        sign_payload_with_service(&self.store.get(service_id)?, payload, content_type, format, options)
    }
}

fn plugin_info(id: &str, name: &str, description: &str, commands: &[PluginCommandDef]) -> PluginInfo {
    PluginInfo {
        id: id.to_string(),
        name: name.to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        description: description.to_string(),
        capabilities: vec![PluginCapability::Signing],
        commands: commands.to_vec(),
        transparency_options: Vec::new(),
    }
}

fn plugin_command(name: &str, description: &str, options: Vec<PluginOptionDef>) -> PluginCommandDef {
    PluginCommandDef {
        name: name.to_string(),
        description: description.to_string(),
        options,
        capability: PluginCapability::Signing,
    }
}

fn option_definition(
    name: &str,
    value_name: &str,
    description: &str,
    required: bool,
) -> PluginOptionDef {
    PluginOptionDef {
        name: name.to_string(),
        value_name: value_name.to_string(),
        description: description.to_string(),
        required,
        default_value: None,
        short: None,
        is_flag: false,
    }
}

fn local_pfx_options() -> Vec<PluginOptionDef> {
    vec![
        option_definition(
            "pfx",
            "pfx",
            "Path to PFX/PKCS#12 file containing the signing certificate and private key",
            true,
        ),
        option_definition(
            "pfx-password-file",
            "pfx-password-file",
            "Path to a file containing the PFX password (more secure than command line)",
            false,
        ),
        option_definition(
            "pfx-password-env",
            "pfx-password-env",
            "Name of environment variable containing the PFX password",
            false,
        ),
    ]
}

fn local_pem_options() -> Vec<PluginOptionDef> {
    vec![
        option_definition(
            "cert-file",
            "cert-file",
            "Path to the certificate file (.pem, .crt)",
            true,
        ),
        option_definition(
            "key-file",
            "key-file",
            "Path to the private key file (.key, .pem)",
            true,
        ),
    ]
}

#[cfg(feature = "aas")]
fn aas_options() -> Vec<PluginOptionDef> {
    vec![
        option_definition(
            "aas-endpoint",
            "aas-endpoint",
            "Azure Artifact Signing endpoint URL (e.g., https://xxx.codesigning.azure.net)",
            true,
        ),
        option_definition(
            "aas-account-name",
            "aas-account-name",
            "Azure Artifact Signing account name",
            true,
        ),
        option_definition(
            "aas-cert-profile-name",
            "aas-cert-profile-name",
            "Certificate profile name in Azure Artifact Signing",
            true,
        ),
    ]
}

#[cfg(feature = "akv")]
fn akv_key_options() -> Vec<PluginOptionDef> {
    vec![
        option_definition(
            "akv-vault",
            "akv-vault",
            "Azure Key Vault URL (e.g., https://my-vault.vault.azure.net).",
            true,
        ),
        option_definition("akv-key-name", "akv-key-name", "Key name in Azure Key Vault.", true),
        option_definition(
            "akv-key-version",
            "akv-key-version",
            "Key version (optional — uses latest if not specified).",
            false,
        ),
    ]
}

#[cfg(feature = "akv")]
fn akv_cert_options() -> Vec<PluginOptionDef> {
    vec![
        option_definition(
            "akv-vault",
            "akv-vault",
            "Azure Key Vault URL (e.g., https://my-vault.vault.azure.net)",
            true,
        ),
        option_definition(
            "akv-cert-name",
            "akv-cert-name",
            "Name of the certificate in Azure Key Vault",
            true,
        ),
        option_definition(
            "akv-cert-version",
            "akv-cert-version",
            "Specific version of the certificate (optional - uses latest)",
            false,
        ),
    ]
}

fn create_local_pfx_service(config: &PluginConfig) -> Result<CertificateSigningService> {
    let pfx_path = required_option(config, "pfx")?;
    let password_file = optional_option(config, "pfx-password-file");
    let password_env = optional_option(config, "pfx-password-env");
    let password = resolve_pfx_password(password_file, password_env)?;
    let certificate = match password.as_deref() {
        Some("") => pfx::load_from_pfx_no_password(pfx_path),
        Some(password) => {
            let env_var_name = "COSESIGNTOOL_PLUGIN_LOADER_PFX_PASSWORD";
            std::env::set_var(env_var_name, password);
            let result = pfx::load_from_pfx_with_env_var(pfx_path, env_var_name);
            std::env::remove_var(env_var_name);
            result
        }
        None => pfx::load_from_pfx(pfx_path),
    }
    .with_context(|| format!("Failed to load PFX certificate: {pfx_path}"))?;
    build_service_from_cert(certificate)
}

fn create_local_pem_service(config: &PluginConfig) -> Result<CertificateSigningService> {
    let cert_path = required_option(config, "cert-file")?;
    let key_path = required_option(config, "key-file")?;
    let mut certificate = pem::load_cert_from_pem(cert_path)
        .with_context(|| format!("Failed to load PEM certificate: {cert_path}"))?;

    if certificate.private_key_der.is_none() {
        let key_pem = std::fs::read(key_path)
            .with_context(|| format!("Failed to read PEM key file: {key_path}"))?;
        let key_certificate = pem::load_cert_from_pem_bytes(&key_pem)
            .context("Failed to parse PEM private key")?;
        certificate.private_key_der = key_certificate.private_key_der;
    }

    build_service_from_cert(certificate)
}

fn create_local_ephemeral_service(config: &PluginConfig) -> Result<CertificateSigningService> {
    let subject = optional_option(config, "subject").unwrap_or("CN=CoseSignTool Ephemeral");
    let key_provider = Box::new(SoftwareKeyProvider::new());
    let factory = EphemeralCertificateFactory::new(key_provider);
    let options = CertificateOptions::default().with_subject_name(subject);
    let certificate = factory
        .create_certificate(options)
        .map_err(|error| anyhow!("Failed to create ephemeral certificate: {error}"))?;
    build_service_from_cert(certificate)
}

#[cfg(feature = "aas")]
fn create_aas_service(config: &PluginConfig) -> Result<AzureArtifactSigningService> {
    let options = AzureArtifactSigningOptions {
        endpoint: required_option(config, "aas-endpoint")?.to_string(),
        account_name: required_option(config, "aas-account-name")?.to_string(),
        certificate_profile_name: required_option(config, "aas-cert-profile-name")?.to_string(),
    };

    AzureArtifactSigningService::new(options)
        .map_err(|error| anyhow!("Failed to create Azure Artifact Signing service: {error}"))
        .context(
            "Ensure Azure credentials are configured (az login, managed identity, or environment variables)",
        )
}

#[cfg(feature = "akv")]
fn create_akv_key_service(config: &PluginConfig) -> Result<AzureKeyVaultSigningService> {
    let vault_url = required_option(config, "akv-vault")?;
    let key_name = required_option(config, "akv-key-name")?;
    let key_version = optional_option(config, "akv-key-version");
    create_akv_service(vault_url, key_name, key_version)
}

#[cfg(feature = "akv")]
fn create_akv_certificate_service(config: &PluginConfig) -> Result<AzureKeyVaultSigningService> {
    let vault_url = required_option(config, "akv-vault")?;
    let cert_name = required_option(config, "akv-cert-name")?;
    let cert_version = optional_option(config, "akv-cert-version");
    create_akv_service(vault_url, cert_name, cert_version)
}

#[cfg(feature = "akv")]
fn create_akv_service(
    vault_url: &str,
    key_name: &str,
    key_version: Option<&str>,
) -> Result<AzureKeyVaultSigningService> {
    let crypto_client = AkvKeyClient::new_dev(vault_url, key_name, key_version)
        .map_err(|error| anyhow!("Failed to create AKV crypto client: {error}"))?;

    let mut service = AzureKeyVaultSigningService::new(Box::new(crypto_client))
        .map_err(|error| anyhow!("Failed to create AKV signing service: {error}"))?;

    service
        .initialize()
        .map_err(|error| anyhow!("Failed to initialize AKV signing service: {error}"))
        .context(
            "Ensure Azure credentials are configured (az login) and the key vault resource is accessible",
        )?;

    Ok(service)
}

fn required_option<'a>(config: &'a PluginConfig, name: &str) -> Result<&'a str> {
    config
        .options
        .get(name)
        .map(String::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| anyhow!("Missing required option: {name}"))
}

fn optional_option<'a>(config: &'a PluginConfig, name: &str) -> Option<&'a str> {
    config.options.get(name).map(String::as_str)
}

fn resolve_pfx_password(
    password_file: Option<&str>,
    password_env: Option<&str>,
) -> Result<Option<String>> {
    if password_file.is_some() && password_env.is_some() {
        return Err(anyhow!(
            "Specify either pfx-password-file or pfx-password-env, not both"
        ));
    }

    if let Some(password_file) = password_file {
        let password = std::fs::read_to_string(password_file)
            .with_context(|| format!("Failed to read PFX password file: {password_file}"))?;
        return Ok(Some(password.trim_end_matches(['\r', '\n']).to_string()));
    }

    if let Some(password_env) = password_env {
        let password = std::env::var(password_env)
            .with_context(|| format!("Environment variable '{password_env}' does not contain a PFX password"))?;
        return Ok(Some(password));
    }

    Ok(None)
}

fn build_service_from_cert(certificate: Certificate) -> Result<CertificateSigningService> {
    let key_der = certificate
        .private_key_der
        .as_ref()
        .ok_or_else(|| anyhow!("Certificate does not contain a private key"))?;

    let crypto_provider = OpenSslCryptoProvider;
    let signer = crypto_provider
        .signer_from_der(key_der)
        .map_err(|error| anyhow!("Failed to create signer from private key: {error}"))?;

    let signing_key: Arc<dyn SigningKeyProvider> = Arc::new(LocalSigningKeyProvider { signer });
    let certificate_source: Box<dyn CertificateSource> = Box::new(LocalCertificateSource::new(certificate));
    let options = CertificateSigningOptions {
        enable_scitt_compliance: true,
        ..Default::default()
    };

    Ok(CertificateSigningService::new(
        certificate_source,
        signing_key,
        options,
    ))
}

fn sign_payload_with_service(
    service: &Arc<dyn SigningService>,
    payload: &[u8],
    content_type: &str,
    format: &str,
    options: &PluginConfig,
) -> Result<Vec<u8>, String> {
    let format = format.to_ascii_lowercase();
    match format.as_str() {
        "direct" => {
            let factory = DirectSignatureFactory::new(Arc::clone(service));
            let direct_options = build_direct_signature_options(options).map_err(|error| error.to_string())?;
            factory
                .create_bytes(payload, content_type, Some(direct_options))
                .map_err(|error| error.to_string())
        }
        "indirect" => {
            let direct_factory = DirectSignatureFactory::new(Arc::clone(service));
            let factory = IndirectSignatureFactory::new(direct_factory);
            let indirect_options = build_indirect_signature_options(options).map_err(|error| error.to_string())?;
            factory
                .create_bytes(payload, content_type, Some(indirect_options))
                .map_err(|error| error.to_string())
        }
        _ => Err(format!("Unsupported signature format: {format}")),
    }
}

fn build_direct_signature_options(options: &PluginConfig) -> Result<DirectSignatureOptions> {
    ensure_supported_scitt_type(optional_option(options, "scitt-type"))?;

    let embed_payload = if flag_is_set(options, "embed") {
        true
    } else if flag_is_set(options, "detached") {
        false
    } else {
        true
    };
    let mut direct_options = DirectSignatureOptions::default().with_embed_payload(embed_payload);
    let scitt_subject = selected_scitt_subject(options);

    if optional_option(options, "issuer").is_some() || scitt_subject.is_some() {
        let mut claims = CwtClaims::new();

        if let Some(issuer) = optional_option(options, "issuer") {
            claims = claims.with_issuer(issuer.to_string());
        }

        if let Some(subject) = scitt_subject {
            claims = claims.with_subject(subject.to_string());
        }

        let contributor = CwtClaimsHeaderContributor::new(&claims)
            .map_err(|error| anyhow!("Failed to build CWT claims contributor: {error}"))?;
        direct_options = direct_options.add_header_contributor(Box::new(contributor));
    }

    Ok(direct_options)
}

fn build_indirect_signature_options(options: &PluginConfig) -> Result<IndirectSignatureOptions> {
    Ok(IndirectSignatureOptions::default().with_base_options(build_direct_signature_options(options)?))
}

fn ensure_supported_scitt_type(scitt_type: Option<&str>) -> Result<()> {
    if let Some(scitt_type) = scitt_type {
        if !scitt_type.eq_ignore_ascii_case("mst") {
            return Err(anyhow!(
                "Unsupported scitt-type '{scitt_type}'. Only 'mst' is currently supported"
            ));
        }
    }

    Ok(())
}

fn selected_scitt_subject<'a>(options: &'a PluginConfig) -> Option<&'a str> {
    optional_option(options, "cwt-subject").or(optional_option(options, "scitt-subject"))
}

fn flag_is_set(options: &PluginConfig, name: &str) -> bool {
    matches!(
        optional_option(options, name),
        Some("true") | Some("1") | Some("yes") | Some("on")
    )
}

fn service_sign(
    service: &Arc<dyn SigningService>,
    data: &[u8],
    algorithm: i64,
) -> Result<Vec<u8>, String> {
    let context = SigningContext::from_slice(&[]);
    let signer = service
        .get_cose_signer(&context)
        .map_err(|error| error.to_string())?;
    if algorithm != 0 && signer.signer().algorithm() != algorithm {
        tracing::debug!(
            requested_algorithm = algorithm,
            provider_algorithm = signer.signer().algorithm(),
            "Ignoring mismatched sign algorithm override for plugin service"
        );
    }
    signer.signer().sign(data).map_err(|error| error.to_string())
}

fn service_algorithm(service: &Arc<dyn SigningService>) -> Result<i64, String> {
    let context = SigningContext::from_slice(&[]);
    let signer = service
        .get_cose_signer(&context)
        .map_err(|error| error.to_string())?;
    Ok(signer.signer().algorithm())
}

fn service_cert_chain(service: &Arc<dyn SigningService>) -> Result<Vec<Vec<u8>>, String> {
    let context = SigningContext::from_slice(&[]);
    let signer = service
        .get_cose_signer(&context)
        .map_err(|error| error.to_string())?;
    let x5chain_label = CoseHeaderLabel::Int(33);
    Ok(signer
        .protected_headers()
        .get_bytes_one_or_many(&x5chain_label)
        .or_else(|| signer.unprotected_headers().get_bytes_one_or_many(&x5chain_label))
        .unwrap_or_default())
}

struct LocalCertificateSource {
    certificate: Certificate,
    chain_builder: ExplicitCertificateChainBuilder,
}

impl LocalCertificateSource {
    fn new(certificate: Certificate) -> Self {
        let mut chain_der = vec![certificate.cert_der.clone()];
        chain_der.extend(certificate.chain.iter().cloned());
        Self {
            certificate,
            chain_builder: ExplicitCertificateChainBuilder::new(chain_der),
        }
    }
}

impl CertificateSource for LocalCertificateSource {
    fn get_signing_certificate(&self) -> std::result::Result<&[u8], CertificateError> {
        Ok(&self.certificate.cert_der)
    }

    fn has_private_key(&self) -> bool {
        self.certificate.has_private_key()
    }

    fn get_chain_builder(
        &self,
    ) -> &dyn cose_sign1_certificates::chain_builder::CertificateChainBuilder {
        &self.chain_builder
    }
}

struct LocalSigningKeyProvider {
    signer: Box<dyn CryptoSigner>,
}

impl CryptoSigner for LocalSigningKeyProvider {
    fn sign(&self, data: &[u8]) -> std::result::Result<Vec<u8>, CryptoError> {
        self.signer.sign(data)
    }

    fn algorithm(&self) -> i64 {
        self.signer.algorithm()
    }

    fn key_id(&self) -> Option<&[u8]> {
        self.signer.key_id()
    }

    fn key_type(&self) -> &str {
        self.signer.key_type()
    }

    fn supports_streaming(&self) -> bool {
        self.signer.supports_streaming()
    }

    fn sign_init(&self) -> std::result::Result<Box<dyn CryptoSigningContext>, CryptoError> {
        self.signer.sign_init()
    }
}

impl SigningKeyProvider for LocalSigningKeyProvider {
    fn is_remote(&self) -> bool {
        false
    }
}
