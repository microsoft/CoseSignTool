// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! `CoseSignTool sign x509 {pfx|pem|aas|ephemeral} <payload> [options]`
//!
//! Mirrors V2 .NET sign command structure exactly.

use crate::output::{self, OutputFormat};
use crate::plugin_host::PluginRegistry;
use crate::providers;
use anyhow::{Context, Result};
use clap::{Arg, ArgAction, ArgMatches, Args, Command as ClapCommand, Subcommand};
use cose_sign1_factories::{
    direct::{DirectSignatureFactory, DirectSignatureOptions},
    indirect::{IndirectSignatureFactory, IndirectSignatureOptions},
};
use cose_sign1_headers::{CwtClaims, CwtClaimsHeaderContributor};
use cose_sign1_primitives::CoseSign1Message;
use cose_sign1_signing::{SigningService, TransparencyEndpointInfo};
use cosesigntool_plugin_api::traits::{
    PluginCapability, PluginCommandDef, PluginInfo, PluginOptionDef,
};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::io::{Read, Write};
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
    #[cfg(feature = "aas")]
    Aas(AasArgs),
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
    fn new(certificate_source: impl Into<String>) -> Self {
        Self {
            certificate_source: certificate_source.into(),
            account_name: None,
            certificate_profile: None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct PluginSignInvocation {
    pub command_name: String,
    pub common: CommonSignArgs,
    pub provider_options: HashMap<String, String>,
}

#[derive(Debug, Clone)]
struct TransparencyCommandPlan {
    discovered_endpoints: Vec<TransparencyEndpointInfo>,
    submission_targets: Vec<TransparencySubmissionTarget>,
    suggestions: Vec<String>,
}

#[derive(Debug, Clone)]
struct TransparencySubmissionTarget {
    service_type: String,
    endpoint: String,
    display_name: String,
}

// ============================================================================
// Shared signing options (common to all providers)
// ============================================================================

#[derive(Args, Debug, Clone)]
pub struct CommonSignArgs {
    /// Path to the payload file to sign.
    #[arg(value_name = "payload")]
    pub payload: String,

    /// Output file path, or '-' for stdout.
    #[arg(short = 'o', long = "output", value_name = "output")]
    pub output: String,

    /// Content type.
    #[arg(
        long = "content-type",
        value_name = "content-type",
        default_value = "application/octet-stream"
    )]
    pub content_type: String,

    /// Signature format.
    #[arg(long = "format", value_name = "format", default_value = "indirect")]
    pub format: SignatureFormat,

    /// Create detached signature.
    #[arg(long = "detached", conflicts_with = "embed")]
    pub detached: bool,

    /// Embed payload in signature.
    #[arg(long = "embed", conflicts_with = "detached")]
    pub embed: bool,

    /// CWT Claims issuer (iss) — identifies who created the signature.
    #[arg(long = "issuer", value_name = "issuer")]
    pub issuer: Option<String>,

    /// CWT Claims subject (sub) field.
    #[arg(
        long = "cwt-subject",
        value_name = "cwt-subject",
        conflicts_with = "scitt_subject"
    )]
    pub cwt_subject: Option<String>,

    /// SCITT transparency ledger entry.
    #[arg(
        long = "scitt-subject",
        value_name = "SCITT_SUBJECT",
        conflicts_with = "cwt_subject"
    )]
    pub scitt_subject: Option<String>,

    /// Enable SCITT transparency ledger.
    #[arg(long = "enable-scitt", conflicts_with = "no_scitt")]
    pub enable_scitt: bool,

    /// Disable SCITT compliance (omit default CWT claims from signature).
    #[arg(long = "no-scitt", conflicts_with = "enable_scitt")]
    pub no_scitt: bool,

    /// SCITT implementation type.
    #[arg(long = "scitt-type", value_name = "SCITT_TYPE")]
    pub scitt_type: Option<String>,

    /// MST service endpoint URL.
    /// Can be specified multiple times for multi-ledger submission.
    /// When specified, the signed output is submitted to each MST endpoint and the receipt-enhanced
    /// COSE_Sign1 is written as output.
    #[cfg(feature = "mst")]
    #[arg(long = "mst-endpoint", value_name = "mst-endpoint", action = clap::ArgAction::Append, alias = "scitt-mst-endpoint")]
    pub mst_endpoints: Vec<String>,

    /// Plugin-contributed transparency options resolved from CLI arguments.
    #[arg(skip = HashMap::new())]
    pub transparency_options: HashMap<String, String>,
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

    /// Path to PFX/PKCS#12 file containing the signing certificate and private key
    #[arg(long = "pfx", value_name = "pfx")]
    pub pfx: String,

    /// Path to a file containing the PFX password (more secure than command line)
    #[arg(long = "pfx-password-file", value_name = "pfx-password-file")]
    pub pfx_password_file: Option<String>,

    /// Name of environment variable containing the PFX password
    #[arg(long = "pfx-password-env", value_name = "pfx-password-env")]
    pub pfx_password_env: Option<String>,
}

#[derive(Args, Debug)]
pub struct PemArgs {
    #[command(flatten)]
    pub common: CommonSignArgs,

    /// Path to the certificate file (.pem, .crt)
    #[arg(long = "cert-file", value_name = "cert-file")]
    pub cert_file: String,

    /// Path to the private key file (.key, .pem)
    #[arg(long = "key-file", value_name = "key-file")]
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

#[cfg(feature = "aas")]
#[derive(Args, Debug)]
pub struct AasArgs {
    #[command(flatten)]
    pub common: CommonSignArgs,

    /// Azure Artifact Signing endpoint URL (e.g., https://xxx.codesigning.azure.net)
    #[arg(long = "aas-endpoint", value_name = "aas-endpoint")]
    pub aas_endpoint: String,

    /// Azure Artifact Signing account name
    #[arg(long = "aas-account-name", value_name = "aas-account-name")]
    pub aas_account_name: String,

    /// Certificate profile name in Azure Artifact Signing
    #[arg(long = "aas-cert-profile-name", value_name = "aas-cert-profile-name")]
    pub aas_cert_profile_name: String,
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

    /// Azure Key Vault URL (e.g., https://my-vault.vault.azure.net)
    #[arg(long = "akv-vault", value_name = "akv-vault")]
    pub akv_vault: String,

    /// Name of the certificate in Azure Key Vault
    #[arg(long = "akv-cert-name", value_name = "akv-cert-name")]
    pub akv_cert_name: String,

    /// Specific version of the certificate (optional - uses latest)
    #[arg(long = "akv-cert-version", value_name = "akv-cert-version")]
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

pub fn execute_plugin(
    invocation: PluginSignInvocation,
    format: OutputFormat,
    registry: &PluginRegistry,
) -> Result<i32> {
    let service = providers::plugin::create_plugin_service(
        registry,
        invocation.command_name.as_str(),
        &invocation.provider_options,
    )?;
    let provider_info = ProviderDisplayInfo::new(format!("Plugin ({})", invocation.command_name));
    execute_signing_service(Arc::new(service), invocation.common, provider_info, format)
}

fn execute_x509(provider: X509Provider, format: OutputFormat) -> Result<i32> {
    let (service, common, provider_info): (
        Arc<dyn SigningService>,
        CommonSignArgs,
        ProviderDisplayInfo,
    ) = match provider {
        X509Provider::Pfx(args) => {
            let password = resolve_pfx_password(
                args.pfx_password_file.as_deref(),
                args.pfx_password_env.as_deref(),
            )?;
            let service = providers::local::create_pfx_service(&args.pfx, password.as_deref())?;
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
        #[cfg(feature = "aas")]
        X509Provider::Aas(args) => {
            let service = providers::aas::create_aas_service(
                &args.aas_endpoint,
                &args.aas_account_name,
                &args.aas_cert_profile_name,
            )?;
            (
                Arc::new(service),
                args.common,
                ProviderDisplayInfo {
                    certificate_source: "Azure Artifact Signing".to_string(),
                    account_name: Some(args.aas_account_name),
                    certificate_profile: Some(args.aas_cert_profile_name),
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

    execute_signing_service(service, common, provider_info, format)
}

fn execute_signing_service(
    service: Arc<dyn SigningService>,
    common: CommonSignArgs,
    provider_info: ProviderDisplayInfo,
    format: OutputFormat,
) -> Result<i32> {
    let transparency_plan = build_transparency_plan(service.as_ref(), &common);
    let (payload, payload_display) = read_payload_bytes(&common)?;
    let direct_factory = DirectSignatureFactory::new(service);

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

    let output_bytes = apply_scitt_transparency(
        signed_bytes,
        transparency_plan.submission_targets.as_slice(),
    )?;
    let writes_to_stdout = write_output_bytes(&common.output, &output_bytes)?;
    let certificate_subject =
        extract_certificate_subject(&output_bytes)?.unwrap_or_else(|| "Unavailable".to_string());
    #[cfg(feature = "mst")]
    let scitt_mst_endpoints_display: String = if common.mst_endpoints.is_empty() {
        "N/A".to_string()
    } else {
        common.mst_endpoints.join(", ")
    };
    let discovered_transparency_display =
        format_discovered_transparency_endpoints(transparency_plan.discovered_endpoints.as_slice());
    let transparency_submission_display =
        format_transparency_submission_targets(transparency_plan.submission_targets.as_slice());
    let transparency_suggestions_display =
        format_transparency_suggestions(transparency_plan.suggestions.as_slice());
    let scitt_subject_display: &str = selected_scitt_subject(&common).unwrap_or("N/A");

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
        output::write_field(
            writer.as_mut(),
            "SCITT Compliance",
            if common.no_scitt {
                "Disabled"
            } else {
                "Enabled"
            },
        )?;
        #[cfg(feature = "mst")]
        output::write_field(
            writer.as_mut(),
            "SCITT MST Endpoints",
            &scitt_mst_endpoints_display,
        )?;
        output::write_field(
            writer.as_mut(),
            "Discovered Transparency Services",
            &discovered_transparency_display,
        )?;
        output::write_field(
            writer.as_mut(),
            "SCITT Submission Targets",
            &transparency_submission_display,
        )?;
        output::write_field(
            writer.as_mut(),
            "SCITT Suggestions",
            &transparency_suggestions_display,
        )?;
        output::write_field(writer.as_mut(), "SCITT Subject", scitt_subject_display)?;
        output::write_field(
            writer.as_mut(),
            "Signature Size",
            &format!("{} bytes", output_bytes.len()),
        )?;
        writeln!(writer, "\n[OK] Successfully signed payload")?;
    }

    Ok(0)
}

fn build_direct_signature_options(common: &CommonSignArgs) -> Result<DirectSignatureOptions> {
    ensure_supported_scitt_type(common.scitt_type.as_deref())?;

    let embed_payload = common.embed || !common.detached;
    let mut options = DirectSignatureOptions::default().with_embed_payload(embed_payload);
    let scitt_subject = selected_scitt_subject(common);

    if common.issuer.is_some() || scitt_subject.is_some() {
        let mut claims = CwtClaims::new();

        if let Some(issuer) = &common.issuer {
            claims = claims.with_issuer(issuer.clone());
        }

        if let Some(subject) = scitt_subject {
            claims = claims.with_subject(subject.to_string());
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
    if common.payload == "-" {
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

fn build_transparency_plan(
    service: &dyn SigningService,
    common: &CommonSignArgs,
) -> TransparencyCommandPlan {
    let discovered_endpoints = service.transparency_endpoints();
    let mut submission_targets = Vec::new();
    let mut seen_targets = HashSet::new();

    #[cfg(feature = "mst")]
    for endpoint in &common.mst_endpoints {
        push_transparency_submission_target(
            &mut submission_targets,
            &mut seen_targets,
            "mst",
            endpoint,
            "Microsoft Signing Transparency",
        );
    }

    for (option_name, value) in &common.transparency_options {
        if value == "true" {
            continue;
        }

        if let Some(service_type) = transparency_service_type_from_option(option_name.as_str()) {
            push_transparency_submission_target(
                &mut submission_targets,
                &mut seen_targets,
                service_type,
                value,
                option_name,
            );
        }
    }

    if submission_targets.is_empty() {
        for endpoint in &discovered_endpoints {
            if endpoint.auto_submit {
                push_transparency_submission_target(
                    &mut submission_targets,
                    &mut seen_targets,
                    endpoint.service_type.as_str(),
                    endpoint.endpoint.as_str(),
                    endpoint.display_name.as_str(),
                );
            }
        }
    }

    let suggestions = if submission_targets.is_empty() {
        discovered_endpoints
            .iter()
            .map(format_transparency_suggestion)
            .collect()
    } else {
        Vec::new()
    };

    TransparencyCommandPlan {
        discovered_endpoints,
        submission_targets,
        suggestions,
    }
}

fn push_transparency_submission_target(
    targets: &mut Vec<TransparencySubmissionTarget>,
    seen_targets: &mut HashSet<String>,
    service_type: &str,
    endpoint: &str,
    display_name: &str,
) {
    if endpoint.is_empty() {
        return;
    }

    let dedupe_key = format!("{}\u{0}{}", service_type, endpoint);
    if seen_targets.insert(dedupe_key) {
        targets.push(TransparencySubmissionTarget {
            service_type: service_type.to_string(),
            endpoint: endpoint.to_string(),
            display_name: display_name.to_string(),
        });
    }
}

fn format_discovered_transparency_endpoints(endpoints: &[TransparencyEndpointInfo]) -> String {
    if endpoints.is_empty() {
        return "N/A".to_string();
    }

    endpoints
        .iter()
        .map(|endpoint| {
            format!(
                "{} [{}] {} ({})",
                endpoint.display_name,
                endpoint.service_type,
                endpoint.endpoint,
                if endpoint.auto_submit {
                    "auto-submit"
                } else {
                    "manual"
                }
            )
        })
        .collect::<Vec<String>>()
        .join(", ")
}

fn format_transparency_submission_targets(targets: &[TransparencySubmissionTarget]) -> String {
    if targets.is_empty() {
        return "N/A".to_string();
    }

    targets
        .iter()
        .map(|target| {
            format!(
                "{} [{}] {}",
                target.display_name, target.service_type, target.endpoint
            )
        })
        .collect::<Vec<String>>()
        .join(", ")
}

fn format_transparency_suggestions(suggestions: &[String]) -> String {
    if suggestions.is_empty() {
        return "N/A".to_string();
    }

    suggestions.join(", ")
}

fn format_transparency_suggestion(endpoint: &TransparencyEndpointInfo) -> String {
    match endpoint.service_type.as_str() {
        "mst" => format!("--scitt-mst-endpoint {}", endpoint.endpoint),
        service_type => format!("--scitt-{}-endpoint {}", service_type, endpoint.endpoint),
    }
}

fn transparency_service_type_from_option(option_name: &str) -> Option<&str> {
    option_name
        .strip_prefix("scitt-")
        .and_then(|value| value.strip_suffix("-endpoint"))
        .filter(|value| !value.is_empty())
}

fn apply_scitt_transparency(
    signed_bytes: Vec<u8>,
    submission_targets: &[TransparencySubmissionTarget],
) -> Result<Vec<u8>> {
    let mut receipt_bytes = signed_bytes;

    for target in submission_targets {
        receipt_bytes = apply_transparency_submission_target(receipt_bytes, target)?;
    }

    Ok(receipt_bytes)
}

fn apply_transparency_submission_target(
    signed_bytes: Vec<u8>,
    target: &TransparencySubmissionTarget,
) -> Result<Vec<u8>> {
    #[cfg(feature = "mst")]
    if target.service_type.eq_ignore_ascii_case("mst") {
        let provider = providers::mst::create_mst_transparency_provider(target.endpoint.as_str())?;
        return provider
            .add_transparency_proof(&signed_bytes)
            .map_err(|e| anyhow::anyhow!(
                "SCITT submission failed for {} ({}): {e}",
                target.endpoint,
                target.display_name
            ));
    }

    if target.service_type.eq_ignore_ascii_case("mst") {
        return Err(anyhow::anyhow!(
            "MST transparency support is not enabled in this build"
        ));
    }

    Err(anyhow::anyhow!(
        "Transparency service '{}' is not supported by this build",
        target.service_type
    ))
}

pub fn build_sign_command(plugin_infos: &[PluginInfo]) -> ClapCommand {
    let mut x509_command = X509Provider::augment_subcommands(
        ClapCommand::new("x509")
            .about("Sign using X.509 certificates.")
            .subcommand_required(true)
            .arg_required_else_help(true),
    );
    let mut added_command_names = HashSet::new();
    let mut added_transparency_option_names = HashSet::new();

    for plugin_command in collect_plugin_signing_commands(plugin_infos) {
        if added_command_names.insert(plugin_command.name.clone()) {
            x509_command = x509_command.subcommand(build_plugin_subcommand(plugin_command));
        }
    }

    for option in collect_transparency_plugin_options(plugin_infos) {
        if added_transparency_option_names.insert(option.name.clone()) {
            x509_command = x509_command.arg(build_plugin_option_arg(option, true));
        }
    }

    ClapCommand::new("sign")
        .about("Sign a payload and produce a COSE_Sign1 message.")
        .subcommand_required(true)
        .arg_required_else_help(true)
        .subcommand(x509_command)
}

pub fn try_parse_plugin_invocation(
    plugin_infos: &[PluginInfo],
    matches: &ArgMatches,
) -> Result<Option<PluginSignInvocation>, String> {
    let Some(("sign", sign_matches)) = matches.subcommand() else {
        return Ok(None);
    };
    let Some(("x509", x509_matches)) = sign_matches.subcommand() else {
        return Ok(None);
    };
    let Some((provider_name, provider_matches)) = x509_matches.subcommand() else {
        return Ok(None);
    };

    if is_builtin_provider_name(provider_name) {
        return Ok(None);
    }

    let Some(command_def) = find_plugin_command(plugin_infos, provider_name) else {
        return Ok(None);
    };

    Ok(Some(PluginSignInvocation {
        command_name: provider_name.to_string(),
        common: common_sign_args_from_matches(provider_matches, plugin_infos)?,
        provider_options: plugin_option_values_from_matches(provider_matches, command_def),
    }))
}

pub fn is_builtin_provider_name(name: &str) -> bool {
    match name {
        "pfx" | "pem" | "ephemeral" => true,
        #[cfg(feature = "aas")]
        "aas" => true,
        #[cfg(feature = "akv")]
        "akv" | "akv-cert" => true,
        _ => false,
    }
}

pub fn set_builtin_transparency_options(
    method: &mut SignMethod,
    transparency_options: HashMap<String, String>,
) {
    common_sign_args_mut(method).transparency_options = transparency_options;
}

fn common_sign_args_mut(method: &mut SignMethod) -> &mut CommonSignArgs {
    match method {
        SignMethod::X509 { provider } => match provider {
            X509Provider::Pfx(args) => &mut args.common,
            X509Provider::Pem(args) => &mut args.common,
            X509Provider::Ephemeral(args) => &mut args.common,
            #[cfg(feature = "aas")]
            X509Provider::Aas(args) => &mut args.common,
            #[cfg(feature = "akv")]
            X509Provider::Akv(args) => &mut args.common,
            #[cfg(feature = "akv")]
            X509Provider::AkvCert(args) => &mut args.common,
        },
    }
}

fn build_plugin_subcommand(command: &PluginCommandDef) -> ClapCommand {
    let command_name = leak_str(command.name.as_str());
    let mut subcommand = CommonSignArgs::augment_args(
        ClapCommand::new(command_name)
            .about(leak_str(command.description.as_str()))
            .arg_required_else_help(true),
    );

    for option in &command.options {
        subcommand = subcommand.arg(build_plugin_option_arg(option, false));
    }

    subcommand
}

fn build_plugin_option_arg(option: &PluginOptionDef, global: bool) -> Arg {
    let option_name = leak_str(option.name.as_str());
    let mut arg = Arg::new(option_name)
        .long(option_name)
        .help(leak_str(option.description.as_str()));

    if global {
        arg = arg.global(true);
    }

    if let Some(short) = option.short {
        arg = arg.short(short);
    }

    if option.is_flag {
        return arg.action(ArgAction::SetTrue);
    }

    arg = arg
        .value_name(leak_str(option.value_name.as_str()))
        .required(option.required);
    if let Some(default_value) = &option.default_value {
        arg = arg.default_value(leak_str(default_value.as_str()));
    }

    arg
}

fn collect_plugin_signing_commands(plugin_infos: &[PluginInfo]) -> Vec<&PluginCommandDef> {
    let mut commands: Vec<&PluginCommandDef> = plugin_infos
        .iter()
        .flat_map(|plugin| plugin.commands.iter())
        .filter(|command| command.capability == PluginCapability::Signing)
        .filter(|command| !is_builtin_provider_name(command.name.as_str()))
        .collect();
    commands.sort_by(|left, right| left.name.cmp(&right.name));
    commands
}

fn collect_transparency_plugin_options(plugin_infos: &[PluginInfo]) -> Vec<&PluginOptionDef> {
    let mut options: Vec<&PluginOptionDef> = plugin_infos
        .iter()
        .filter(|plugin| plugin.capabilities.contains(&PluginCapability::Transparency))
        .flat_map(|plugin| plugin.transparency_options.iter())
        .collect();
    options.sort_by(|left, right| left.name.cmp(&right.name));
    options
}

fn find_plugin_command<'a>(
    plugin_infos: &'a [PluginInfo],
    command_name: &str,
) -> Option<&'a PluginCommandDef> {
    plugin_infos
        .iter()
        .flat_map(|plugin| plugin.commands.iter())
        .find(|command| {
            command.capability == PluginCapability::Signing && command.name == command_name
        })
}

fn option_values_from_matches<'a, I>(matches: &ArgMatches, options: I) -> HashMap<String, String>
where
    I: IntoIterator<Item = &'a PluginOptionDef>,
{
    let mut values = HashMap::new();

    for option in options {
        if option.is_flag {
            if matches.get_flag(option.name.as_str()) {
                values.insert(option.name.clone(), "true".to_string());
            }
            continue;
        }

        if let Some(value) = matches.get_one::<String>(option.name.as_str()) {
            values.insert(option.name.clone(), value.clone());
        }
    }

    values
}

fn plugin_option_values_from_matches(
    matches: &ArgMatches,
    command: &PluginCommandDef,
) -> HashMap<String, String> {
    option_values_from_matches(matches, command.options.iter())
}

pub fn transparency_option_values_from_matches(
    matches: &ArgMatches,
    plugin_infos: &[PluginInfo],
) -> HashMap<String, String> {
    option_values_from_matches(matches, collect_transparency_plugin_options(plugin_infos))
}

fn common_sign_args_from_matches(
    matches: &ArgMatches,
    plugin_infos: &[PluginInfo],
) -> Result<CommonSignArgs, String> {
    Ok(CommonSignArgs {
        payload: required_string_arg(matches, "payload")?,
        output: required_string_arg(matches, "output")?,
        content_type: required_string_arg(matches, "content_type")?,
        format: matches
            .get_one::<SignatureFormat>("format")
            .cloned()
            .unwrap_or(SignatureFormat::Indirect),
        detached: matches.get_flag("detached"),
        embed: matches.get_flag("embed"),
        issuer: optional_string_arg(matches, "issuer"),
        cwt_subject: optional_string_arg(matches, "cwt_subject"),
        scitt_subject: optional_string_arg(matches, "scitt_subject"),
        enable_scitt: matches.get_flag("enable_scitt"),
        no_scitt: matches.get_flag("no_scitt"),
        scitt_type: optional_string_arg(matches, "scitt_type"),
        #[cfg(feature = "mst")]
        mst_endpoints: matches
            .get_many::<String>("mst_endpoints")
            .map(|values| values.cloned().collect())
            .unwrap_or_default(),
        transparency_options: transparency_option_values_from_matches(matches, plugin_infos),
    })
}

fn required_string_arg(matches: &ArgMatches, id: &str) -> Result<String, String> {
    matches
        .get_one::<String>(id)
        .cloned()
        .ok_or_else(|| format!("missing required argument '{}'", id))
}

fn optional_string_arg(matches: &ArgMatches, id: &str) -> Option<String> {
    matches.get_one::<String>(id).cloned()
}

fn selected_scitt_subject(common: &CommonSignArgs) -> Option<&str> {
    common
        .cwt_subject
        .as_deref()
        .or(common.scitt_subject.as_deref())
}

fn ensure_supported_scitt_type(scitt_type: Option<&str>) -> Result<()> {
    if let Some(scitt_type) = scitt_type {
        if !scitt_type.eq_ignore_ascii_case("mst") {
            return Err(anyhow::anyhow!(
                "Unsupported --scitt-type '{}'. Only 'mst' is currently supported",
                scitt_type
            ));
        }
    }

    Ok(())
}

fn leak_str(value: &str) -> &'static str {
    Box::leak(value.to_string().into_boxed_str())
}

fn resolve_pfx_password(
    password_file: Option<&str>,
    password_env: Option<&str>,
) -> Result<Option<String>> {
    if password_file.is_some() && password_env.is_some() {
        return Err(anyhow::anyhow!(
            "Specify either --pfx-password-file or --pfx-password-env, not both"
        ));
    }

    if let Some(password_file) = password_file {
        let password = fs::read_to_string(password_file)
            .with_context(|| format!("Failed to read PFX password file: {password_file}"))?;
        return Ok(Some(password.trim_end_matches(['\r', '\n']).to_string()));
    }

    if let Some(password_env) = password_env {
        let password = std::env::var(password_env).with_context(|| {
            format!("Environment variable '{password_env}' does not contain a PFX password")
        })?;
        return Ok(Some(password));
    }

    Ok(None)
}
