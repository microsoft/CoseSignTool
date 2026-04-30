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
use cose_sign1_signing::SigningService;
use std::fs;
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
    // AKV provider would go here behind #[cfg(feature = "akv")]
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
    let (service, common, provider_name): (Arc<dyn SigningService>, &CommonSignArgs, &str) =
        match &provider {
            X509Provider::Pfx(args) => {
                let svc =
                    providers::local::create_pfx_service(&args.pfx, args.pfx_password.as_deref())?;
                (Arc::new(svc), &args.common, "PFX")
            }
            X509Provider::Pem(args) => {
                let svc = providers::local::create_pem_service(&args.cert_file, &args.key_file)?;
                (Arc::new(svc), &args.common, "PEM")
            }
            X509Provider::Ephemeral(args) => {
                let svc = providers::local::create_ephemeral_service(&args.subject)?;
                (Arc::new(svc), &args.common, "Ephemeral")
            }
            #[cfg(feature = "ats")]
            X509Provider::Ats(args) => {
                let svc = providers::ats::create_ats_service(
                    &args.ats_endpoint,
                    &args.ats_account_name,
                    &args.ats_cert_profile_name,
                )?;
                (Arc::new(svc), &args.common, "Azure Artifact Signing")
            }
        };

    // Read payload
    let payload = fs::read(&common.payload)
        .with_context(|| format!("Failed to read payload file: {}", common.payload))?;

    // Sign using the appropriate factory
    let direct_factory = build_direct_factory(service, common)?;
    let signed_bytes = match common.format {
        SignatureFormat::Direct => {
            let options = build_direct_signature_options(common)?;
            direct_factory
                .create_bytes(&payload, &common.content_type, Some(options))
                .map_err(|e| anyhow::anyhow!("Signing failed: {e}"))?
        }
        SignatureFormat::Indirect => {
            let factory = IndirectSignatureFactory::new(direct_factory);
            let options = build_indirect_signature_options(common)?;
            factory
                .create_bytes(&payload, &common.content_type, Some(options))
                .map_err(|e| anyhow::anyhow!("Signing failed: {e}"))?
        }
    };

    // Write output
    fs::write(&common.output, &signed_bytes)
        .with_context(|| format!("Failed to write output: {}", common.output))?;

    if !matches!(format, OutputFormat::Quiet) {
        let stdout = &mut std::io::stdout();
        output::write_section(stdout, "Signing Operation")?;
        output::write_field(stdout, "Payload", &common.payload)?;
        output::write_field(stdout, "Output", &common.output)?;
        output::write_field(
            stdout,
            "Signature Type",
            match common.format {
                SignatureFormat::Direct => "direct",
                SignatureFormat::Indirect => "indirect",
            },
        )?;
        output::write_field(stdout, "Content Type", &common.content_type)?;
        output::write_field(stdout, "Provider", provider_name)?;
        output::write_field(
            stdout,
            "Signature Size",
            &format!("{} bytes", signed_bytes.len()),
        )?;
        println!("\n[OK] Successfully signed payload");
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
