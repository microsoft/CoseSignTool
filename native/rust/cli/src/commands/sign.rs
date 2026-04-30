// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! `CoseSignTool sign x509 {pfx|pem|ats|ephemeral} <payload> [options]`
//!
//! Mirrors V2 .NET sign command structure exactly.

use crate::output::{self, OutputFormat};
use crate::providers;
use anyhow::{Context, Result};
use clap::{Args, Subcommand};
use cose_sign1_factories::{
    direct::{DirectSignatureFactory, DirectSignatureOptions},
    indirect::{IndirectSignatureFactory, IndirectSignatureOptions},
};
use cose_sign1_headers::{CwtClaims, CwtClaimsHeaderContributor};
use cose_sign1_primitives::CoseSign1Message;
use cose_sign1_signing::SigningService;
use std::fs;
use std::io::{IsTerminal, Read, Write};
use std::sync::Arc;

/// Signing method (currently x509 only, extensible).
#[derive(Subcommand, Debug)]
pub enum SignMethod {
    /// Sign using X.509 certificates.
    X509 {
        #[command(subcommand)]
        provider: X509Provider,
    },
}

/// X.509 certificate provider subcommands, matching V2 syntax.
#[derive(Subcommand, Debug)]
pub enum X509Provider {
    /// Sign with a local PFX/PKCS#12 certificate.
    Pfx(PfxArgs),
    /// Sign with local PEM certificate and key files.
    Pem(PemArgs),
    /// Sign with an ephemeral in-memory certificate (testing).
    Ephemeral(EphemeralArgs),
    /// Sign with Azure Artifact Signing cloud service.
    #[cfg(feature = "ats")]
    Ats(AtsArgs),
    /// Sign using Azure Key Vault key (no certificate chain).
    #[cfg(feature = "akv")]
    Akv(AkvArgs),
    /// Sign using Azure Key Vault certificate (with certificate chain).
    #[cfg(feature = "akv")]
    #[command(name = "akv-cert")]
    AkvCert(AkvCertArgs),
}

#[derive(Debug)]
struct ProviderDisplayInfo {
    certificate_source: String,
    account_name: Option<String>,
    certificate_profile: Option<String>,
}

impl ProviderDisplayInfo {
    fn new(certificate_source: &str) -> Self {
        Self {
            certificate_source: certificate_source.to_string(),
            account_name: None,
            certificate_profile: None,
        }
    }
}

// ============================================================================
// Shared signing options (common to all providers)
// ============================================================================

#[derive(Args, Debug)]
pub struct CommonSignArgs {
    /// Path to the payload file to sign.
    pub payload: String,

    /// Path to write the COSE_Sign1 output.
    #[arg(short, long)]
    pub output: String,

    /// Content type (e.g., "application/spdx+json").
    #[arg(
        short = 'c',
        long = "content-type",
        default_value = "application/octet-stream"
    )]
    pub content_type: String,

    /// Signature format: direct or indirect.
    #[arg(long, default_value = "indirect")]
    pub format: SignatureFormat,

    /// Create a detached signature (payload not embedded).
    #[arg(long)]
    pub detached: bool,

    /// CWT issuer claim.
    #[arg(long)]
    pub issuer: Option<String>,

    /// CWT subject claim.
    #[arg(long = "cwt-subject")]
    pub cwt_subject: Option<String>,

    /// Add MST transparency receipt after signing.
    #[cfg(feature = "mst")]
    #[arg(long = "add-mst-receipt")]
    pub add_mst_receipt: bool,

    /// MST service endpoint URL.
    #[cfg(feature = "mst")]
    #[arg(long = "mst-endpoint")]
    pub mst_endpoint: Option<String>,
}

#[derive(Debug, Clone, clap::ValueEnum)]
pub enum SignatureFormat {
    Direct,
    Indirect,
}

// ============================================================================
// Provider-specific argument structs
// ============================================================================

#[derive(Args, Debug)]
pub struct PfxArgs {
    #[command(flatten)]
    pub common: CommonSignArgs,

    /// Path to the PFX/PKCS#12 file.
    #[arg(long)]
    pub pfx: String,

    /// PFX password (prefer COSESIGNTOOL_PFX_PASSWORD env var).
    #[arg(long = "pfx-password")]
    pub pfx_password: Option<String>,
}

#[derive(Args, Debug)]
pub struct PemArgs {
    #[command(flatten)]
    pub common: CommonSignArgs,

    /// Path to the PEM certificate file.
    #[arg(long = "cert-file")]
    pub cert_file: String,

    /// Path to the PEM private key file.
    #[arg(long = "key-file")]
    pub key_file: String,
}

#[derive(Args, Debug)]
pub struct EphemeralArgs {
    #[command(flatten)]
    pub common: CommonSignArgs,

    /// Certificate subject (CN=...).
    #[arg(long, default_value = "CN=CoseSignTool Ephemeral")]
    pub subject: String,
}

#[cfg(feature = "ats")]
#[derive(Args, Debug)]
pub struct AtsArgs {
    #[command(flatten)]
    pub common: CommonSignArgs,

    /// Azure Artifact Signing endpoint URL.
    #[arg(long = "ats-endpoint")]
    pub ats_endpoint: String,

    /// Azure Artifact Signing account name.
    #[arg(long = "ats-account-name")]
    pub ats_account_name: String,

    /// Certificate profile name in Azure Artifact Signing.
    #[arg(long = "ats-cert-profile-name")]
    pub ats_cert_profile_name: String,
}

#[cfg(feature = "akv")]
#[derive(clap::Args, Debug)]
pub struct AkvArgs {
    #[command(flatten)]
    pub common: CommonSignArgs,

    /// Azure Key Vault URL (e.g., https://my-vault.vault.azure.net).
    #[arg(long = "akv-vault")]
    pub akv_vault: String,

    /// Key name in Azure Key Vault.
    #[arg(long = "akv-key-name")]
    pub akv_key_name: String,

    /// Key version (optional — uses latest if not specified).
    #[arg(long = "akv-key-version")]
    pub akv_key_version: Option<String>,
}

#[cfg(feature = "akv")]
#[derive(clap::Args, Debug)]
pub struct AkvCertArgs {
    #[command(flatten)]
    pub common: CommonSignArgs,

    /// Azure Key Vault URL (e.g., https://my-vault.vault.azure.net).
    #[arg(long = "akv-vault")]
    pub akv_vault: String,

    /// Certificate name in Azure Key Vault.
    #[arg(long = "akv-cert-name")]
    pub akv_cert_name: String,

    /// Certificate version (optional — uses latest if not specified).
    #[arg(long = "akv-cert-version")]
    pub akv_cert_version: Option<String>,
}

// ============================================================================
// Execution
// ============================================================================

/// Execute the sign command.
pub fn execute(method: SignMethod, format: OutputFormat) -> Result<i32> {
    match method {
        SignMethod::X509 { provider } => execute_x509(provider, format),
    }
}

fn execute_x509(provider: X509Provider, format: OutputFormat) -> Result<i32> {
    let (service, common, provider_info): (
        Arc<dyn SigningService>,
        CommonSignArgs,
        ProviderDisplayInfo,
    ) = match provider {
        X509Provider::Pfx(args) => {
            let service =
                providers::local::create_pfx_service(&args.pfx, args.pfx_password.as_deref())?;
            (
                Arc::new(service),
                args.common,
                ProviderDisplayInfo::new("PFX"),
            )
        }
        X509Provider::Pem(args) => {
            let service = providers::local::create_pem_service(&args.cert_file, &args.key_file)?;
            (
                Arc::new(service),
                args.common,
                ProviderDisplayInfo::new("PEM"),
            )
        }
        X509Provider::Ephemeral(args) => {
            let service = providers::local::create_ephemeral_service(&args.subject)?;
            (
                Arc::new(service),
                args.common,
                ProviderDisplayInfo::new("Ephemeral"),
            )
        }
        #[cfg(feature = "ats")]
        X509Provider::Ats(args) => {
            let service = providers::ats::create_ats_service(
                &args.ats_endpoint,
                &args.ats_account_name,
                &args.ats_cert_profile_name,
            )?;
            (
                Arc::new(service),
                args.common,
                ProviderDisplayInfo {
                    certificate_source: "Azure Artifact Signing".to_string(),
                    account_name: Some(args.ats_account_name),
                    certificate_profile: Some(args.ats_cert_profile_name),
                },
            )
        }
        #[cfg(feature = "akv")]
        X509Provider::Akv(args) => {
            let service = providers::akv::create_akv_key_service(
                &args.akv_vault,
                &args.akv_key_name,
                args.akv_key_version.as_deref(),
            )?;
            (
                Arc::new(service),
                args.common,
                ProviderDisplayInfo {
                    certificate_source: "Azure Key Vault (Key)".to_string(),
                    account_name: Some(args.akv_key_name),
                    certificate_profile: None,
                },
            )
        }
        #[cfg(feature = "akv")]
        X509Provider::AkvCert(args) => {
            let service = providers::akv::create_akv_cert_service(
                &args.akv_vault,
                &args.akv_cert_name,
                args.akv_cert_version.as_deref(),
            )?;
            (
                Arc::new(service),
                args.common,
                ProviderDisplayInfo {
                    certificate_source: "Azure Key Vault (Certificate)".to_string(),
                    account_name: Some(args.akv_cert_name),
                    certificate_profile: None,
                },
            )
        }
    };

    let (payload, payload_display) = read_payload_bytes(&common)?;
    let direct_factory = build_direct_factory(service, &common)?;

    let signed_bytes = match common.format {
        SignatureFormat::Direct => {
            let options = build_direct_signature_options(&common)?;
            direct_factory
                .create_bytes(&payload, &common.content_type, Some(options))
                .map_err(|e| anyhow::anyhow!("Signing failed: {e}"))?
        }
        SignatureFormat::Indirect => {
            let factory = IndirectSignatureFactory::new(direct_factory);
            let options = build_indirect_signature_options(&common)?;
            factory
                .create_bytes(&payload, &common.content_type, Some(options))
                .map_err(|e| anyhow::anyhow!("Signing failed: {e}"))?
        }
    };

    let writes_to_stdout = write_output_bytes(&common.output, &signed_bytes)?;
    let certificate_subject =
        extract_certificate_subject(&signed_bytes)?.unwrap_or_else(|| "Unavailable".to_string());

    if !matches!(format, OutputFormat::Quiet) {
        let mut writer: Box<dyn Write> = if writes_to_stdout {
            Box::new(std::io::stderr())
        } else {
            Box::new(std::io::stdout())
        };

        output::write_section(writer.as_mut(), "Signing Operation")?;
        output::write_field(writer.as_mut(), "Payload", &payload_display)?;
        output::write_field(
            writer.as_mut(),
            "Output",
            if writes_to_stdout {
                "stdout"
            } else {
                &common.output
            },
        )?;
        output::write_field(
            writer.as_mut(),
            "Signature Type",
            match common.format {
                SignatureFormat::Direct => "direct",
                SignatureFormat::Indirect => "indirect",
            },
        )?;
        output::write_field(writer.as_mut(), "Content Type", &common.content_type)?;
        output::write_field(
            writer.as_mut(),
            "Certificate Source",
            &provider_info.certificate_source,
        )?;
        output::write_field(
            writer.as_mut(),
            "Account Name",
            provider_info.account_name.as_deref().unwrap_or("N/A"),
        )?;
        output::write_field(
            writer.as_mut(),
            "Certificate Profile",
            provider_info
                .certificate_profile
                .as_deref()
                .unwrap_or("N/A"),
        )?;
        output::write_field(writer.as_mut(), "Certificate Subject", &certificate_subject)?;
        #[cfg(feature = "mst")]
        output::write_field(
            writer.as_mut(),
            "MST Receipt",
            if common.add_mst_receipt {
                "Enabled"
            } else {
                "Disabled"
            },
        )?;
        output::write_field(
            writer.as_mut(),
            "Signature Size",
            &format!("{} bytes", signed_bytes.len()),
        )?;
        writeln!(writer, "\n[OK] Successfully signed payload")?;
    }

    Ok(0)
}

fn build_direct_signature_options(common: &CommonSignArgs) -> Result<DirectSignatureOptions> {
    let mut options = DirectSignatureOptions::default().with_embed_payload(!common.detached);

    if common.issuer.is_some() || common.cwt_subject.is_some() {
        let mut claims = CwtClaims::new();

        if let Some(issuer) = &common.issuer {
            claims = claims.with_issuer(issuer.clone());
        }

        if let Some(subject) = &common.cwt_subject {
            claims = claims.with_subject(subject.clone());
        }

        let contributor = CwtClaimsHeaderContributor::new(&claims)
            .map_err(|e| anyhow::anyhow!("Failed to build CWT claims contributor: {e}"))?;
        options = options.add_header_contributor(Box::new(contributor));
    }

    Ok(options)
}

fn build_indirect_signature_options(common: &CommonSignArgs) -> Result<IndirectSignatureOptions> {
    Ok(IndirectSignatureOptions::default()
        .with_base_options(build_direct_signature_options(common)?))
}

fn read_payload_bytes(common: &CommonSignArgs) -> Result<(Vec<u8>, String)> {
    if common.payload == "-" || !std::io::stdin().is_terminal() {
        let mut payload = Vec::new();
        std::io::stdin()
            .read_to_end(&mut payload)
            .context("Failed to read payload from stdin")?;
        Ok((payload, "stdin".to_string()))
    } else {
        let payload = fs::read(&common.payload)
            .with_context(|| format!("Failed to read payload file: {}", common.payload))?;
        Ok((payload, common.payload.clone()))
    }
}

fn write_output_bytes(output_path: &str, signed_bytes: &[u8]) -> Result<bool> {
    if output_path == "-" {
        let mut stdout = std::io::stdout();
        stdout
            .write_all(signed_bytes)
            .context("Failed to write signature to stdout")?;
        stdout.flush().context("Failed to flush stdout")?;
        Ok(true)
    } else {
        fs::write(output_path, signed_bytes)
            .with_context(|| format!("Failed to write output: {output_path}"))?;
        Ok(false)
    }
}

fn extract_certificate_subject(signed_bytes: &[u8]) -> Result<Option<String>> {
    let message = CoseSign1Message::parse(signed_bytes)
        .map_err(|e| anyhow::anyhow!("Failed to parse COSE_Sign1 output: {e}"))?;
    Ok(output::extract_signing_certificate_details(&message)?.map(|details| details.subject))
}

#[cfg(feature = "mst")]
fn build_direct_factory(
    service: Arc<dyn SigningService>,
    common: &CommonSignArgs,
) -> Result<DirectSignatureFactory> {
    if common.add_mst_receipt {
        let endpoint = common.mst_endpoint.as_deref().ok_or_else(|| {
            anyhow::anyhow!("--mst-endpoint is required when --add-mst-receipt is set")
        })?;
        let provider = providers::mst::create_mst_transparency_provider(endpoint)?;
        Ok(DirectSignatureFactory::with_transparency_providers(
            service,
            vec![provider],
        ))
    } else {
        Ok(DirectSignatureFactory::new(service))
    }
}

#[cfg(not(feature = "mst"))]
fn build_direct_factory(
    service: Arc<dyn SigningService>,
    _common: &CommonSignArgs,
) -> Result<DirectSignatureFactory> {
    Ok(DirectSignatureFactory::new(service))
}
