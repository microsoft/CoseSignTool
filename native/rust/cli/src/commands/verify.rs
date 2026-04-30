// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! `CoseSignTool verify {x509|scitt} <signature> [--payload <file>]`

use super::ScittType;
use crate::output::{self, OutputFormat};
use anyhow::{Context, Result};
use clap::{ArgAction, Args, Command as ClapCommand, Subcommand};
use cose_sign1_certificates::validation::facts::{
    X509ChainTrustedFact, X509SigningCertificateIdentityFact,
};
use cose_sign1_certificates::validation::fluent_ext::{
    X509ChainTrustedWhereExt, X509SigningCertificateIdentityWhereExt,
};
use cose_sign1_certificates::validation::pack::{
    CertificateTrustOptions, X509CertificateTrustPack,
};
use cose_sign1_validation::fluent::{
    CoseSign1TrustPack, CoseSign1Validator, Payload, TrustPlanBuilder,
};
#[cfg(feature = "mst")]
use cose_sign1_transparent_mst::code_transparency_client::{
    CodeTransparencyClient, CodeTransparencyClientConfig,
};
#[cfg(feature = "mst")]
use cose_sign1_transparent_mst::validation::MstTrustPack;
use std::fs;
use std::io::Read;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
#[cfg(feature = "mst")]
use url::Url;

/// Verification method.
#[derive(Subcommand, Debug)]
pub enum VerifyMethod {
    /// Verify using X.509 certificate trust.
    X509(VerifyX509Args),
    /// Verify using SCITT transparency receipt trust.
    Scitt(VerifyScittArgs),
}

/// Arguments for X.509 verification.
#[derive(Args, Debug)]
pub struct VerifyX509Args {
    /// Path to the COSE_Sign1 signature file.
    #[arg(value_name = "signature")]
    pub signature: String,

    /// Payload file for detached/indirect verification
    #[arg(short = 'p', long = "payload", value_name = "payload")]
    pub payload: Option<String>,

    /// Verify only cryptographic signature, skip payload validation
    #[arg(long = "signature-only")]
    pub signature_only: bool,

    /// Use system trust roots (default: true)
    #[arg(long = "trust-system-roots", default_value_t = true, action = ArgAction::SetTrue)]
    pub trust_system_roots: bool,

    /// Allow untrusted roots (skip chain trust requirement)
    #[arg(long = "allow-untrusted")]
    pub allow_untrusted: bool,

    /// Allow specific signing certificate thumbprint (SHA-256 hex)
    #[arg(long = "allow-thumbprint", value_name = "thumbprint")]
    pub allow_thumbprint: Option<String>,
}

/// Arguments for SCITT verification.
#[derive(Args, Debug)]
pub struct VerifyScittArgs {
    /// Path to the COSE_Sign1 signature file.
    #[arg(value_name = "signature")]
    pub signature: String,

    /// Payload file for detached/indirect verification.
    #[arg(short = 'p', long = "payload", value_name = "payload")]
    pub payload: Option<String>,

    /// SCITT implementation type.
    #[arg(long = "scitt-type", value_enum, default_value = "mst")]
    pub scitt_type: ScittType,

    /// MST service endpoint URL (for online JWKS key fetch).
    #[cfg(feature = "mst")]
    #[arg(long = "mst-endpoint", value_name = "mst-endpoint")]
    pub mst_endpoint: Option<String>,
}

/// Execute the verify command.
pub fn build_verify_command() -> ClapCommand {
    VerifyMethod::augment_subcommands(
        ClapCommand::new("verify")
            .about("Verify a COSE_Sign1 message.")
            .subcommand_required(true)
            .arg_required_else_help(true),
    )
}

/// Execute the verify command.
pub fn execute(method: VerifyMethod, format: OutputFormat) -> Result<i32> {
    match method {
        VerifyMethod::X509(args) => execute_x509(args, format),
        VerifyMethod::Scitt(args) => execute_scitt(args, format),
    }
}

fn execute_x509(args: VerifyX509Args, format: OutputFormat) -> Result<i32> {
    let (sig_bytes, signature_display) = read_signature_bytes(&args.signature)?;

    let message = Arc::new(
        cose_sign1_primitives::CoseSign1Message::parse(&sig_bytes)
            .map_err(|e| anyhow::anyhow!("Failed to parse COSE_Sign1: {e}"))?,
    );
    let raw_arc: Arc<[u8]> = Arc::from(sig_bytes);

    let detached_payload = read_detached_payload(args.payload.as_deref())?;

    let trust_options = CertificateTrustOptions {
        allowed_thumbprints: args
            .allow_thumbprint
            .iter()
            .cloned()
            .collect::<Vec<String>>(),
        identity_pinning_enabled: args.allow_thumbprint.is_some(),
        trust_embedded_chain_as_trusted: args.trust_system_roots || args.allow_untrusted,
        ..Default::default()
    };
    let cert_pack: Arc<dyn CoseSign1TrustPack> =
        Arc::new(X509CertificateTrustPack::new(trust_options));
    let validator =
        build_validator(cert_pack, args.allow_thumbprint.as_deref())?.with_options(|options| {
            options.detached_payload = detached_payload;
            options.skip_post_signature_validation = args.signature_only;
        });

    let result = validator
        .validate_arc(message, raw_arc)
        .map_err(|e| anyhow::anyhow!("Validation error: {e}"))?;

    let is_valid = result.overall.is_valid();

    if !matches!(format, OutputFormat::Quiet) {
        let stdout = &mut std::io::stdout();
        output::write_section(stdout, "Verification Operation")?;
        output::write_field(stdout, "Signature", &signature_display)?;

        if let Some(ref payload_path) = args.payload {
            output::write_field(stdout, "Payload", payload_path)?;
        }

        output::write_field(stdout, "Trust Mode", &describe_trust_mode(&args))?;
        output::write_field(stdout, "Revocation Check Mode", "none")?;

        output::write_section(stdout, "Verification Stages")?;
        output::write_validation_stage(stdout, "Resolution", &result.resolution)?;
        output::write_validation_stage(stdout, "Trust", &result.trust)?;
        output::write_validation_stage(stdout, "Signature", &result.signature)?;
        output::write_validation_stage(stdout, "Post-Signature", &result.post_signature_policy)?;

        if is_valid {
            println!("\n[OK] Signature verified successfully");
        } else {
            println!("\n[ERROR] Signature verification failed");
        }
    }

    Ok(if is_valid { 0 } else { 1 })
}

fn execute_scitt(args: VerifyScittArgs, format: OutputFormat) -> Result<i32> {
    match args.scitt_type {
        ScittType::Mst => execute_mst_scitt(args, format),
    }
}

#[cfg(feature = "mst")]
fn execute_mst_scitt(args: VerifyScittArgs, format: OutputFormat) -> Result<i32> {
    let (sig_bytes, signature_display) = read_signature_bytes(&args.signature)?;

    let message = Arc::new(
        cose_sign1_primitives::CoseSign1Message::parse(&sig_bytes)
            .map_err(|e| anyhow::anyhow!("Failed to parse COSE_Sign1: {e}"))?,
    );
    let raw_arc: Arc<[u8]> = Arc::from(sig_bytes);
    let detached_payload = read_detached_payload(args.payload.as_deref())?;

    let mst_pack: Arc<dyn CoseSign1TrustPack> = match args.mst_endpoint.as_deref() {
        Some(endpoint) => Arc::new(MstTrustPack::new(false, Some(fetch_mst_jwks(endpoint)?), None)),
        None => Arc::new(MstTrustPack::online()),
    };
    let validator = CoseSign1Validator::new(vec![mst_pack]).with_options(|options| {
        options.detached_payload = detached_payload;
    });

    let result = validator
        .validate_arc(message, raw_arc)
        .map_err(|e| anyhow::anyhow!("Validation error: {e}"))?;

    let is_valid = result.overall.is_valid();

    if !matches!(format, OutputFormat::Quiet) {
        let stdout = &mut std::io::stdout();
        output::write_section(stdout, "Verification Operation")?;
        output::write_field(stdout, "Signature", &signature_display)?;

        if let Some(ref payload_path) = args.payload {
            output::write_field(stdout, "Payload", payload_path)?;
        }

        output::write_field(stdout, "SCITT Type", describe_scitt_type(args.scitt_type))?;
        output::write_field(stdout, "Trust Mode", &describe_scitt_trust_mode(&args))?;
        output::write_field(stdout, "Revocation Check Mode", "none")?;

        output::write_section(stdout, "Verification Stages")?;
        output::write_validation_stage(stdout, "Resolution", &result.resolution)?;
        output::write_validation_stage(stdout, "Trust", &result.trust)?;
        output::write_validation_stage(stdout, "Signature", &result.signature)?;
        output::write_validation_stage(stdout, "Post-Signature", &result.post_signature_policy)?;

        if is_valid {
            println!("\n[OK] Signature verified successfully");
        } else {
            println!("\n[ERROR] Signature verification failed");
        }
    }

    Ok(if is_valid { 0 } else { 1 })
}

#[cfg(not(feature = "mst"))]
fn execute_mst_scitt(_args: VerifyScittArgs, _format: OutputFormat) -> Result<i32> {
    Err(anyhow::anyhow!(
        "MST SCITT verification support is not enabled in this build"
    ))
}

fn build_validator(
    cert_pack: Arc<dyn CoseSign1TrustPack>,
    allowed_thumbprint: Option<&str>,
) -> Result<CoseSign1Validator> {
    let trust_packs = vec![cert_pack];

    if let Some(thumbprint) = allowed_thumbprint {
        let now_unix_seconds = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_secs() as i64)
            .unwrap_or(0);

        let trust_plan = TrustPlanBuilder::new(trust_packs.clone())
            .for_primary_signing_key(|key| {
                key.require::<X509ChainTrustedFact>(|fact| fact.require_trusted())
                    .and()
                    .require::<X509SigningCertificateIdentityFact>(|fact| {
                        fact.cert_valid_at(now_unix_seconds)
                            .thumbprint_eq(thumbprint)
                    })
            })
            .compile()
            .map_err(|e| anyhow::anyhow!("Failed to compile trust plan: {e}"))?;

        Ok(CoseSign1Validator::new(trust_plan))
    } else {
        Ok(CoseSign1Validator::new(trust_packs))
    }
}

fn read_detached_payload(payload_path: Option<&str>) -> Result<Option<Payload>> {
    match payload_path {
        Some(path) => Ok(Some(Payload::from(
            fs::read(path).with_context(|| format!("Failed to read payload file: {path}"))?,
        ))),
        None => Ok(None),
    }
}

#[cfg(feature = "mst")]
fn fetch_mst_jwks(mst_endpoint: &str) -> Result<String> {
    let endpoint =
        Url::parse(mst_endpoint).with_context(|| format!("Invalid MST endpoint URL: {mst_endpoint}"))?;
    let client = CodeTransparencyClient::new(endpoint, CodeTransparencyClientConfig::default());
    client
        .get_public_keys()
        .map_err(|e| anyhow::anyhow!("Failed to fetch MST JWKS from {mst_endpoint}: {e}"))
}

fn read_signature_bytes(signature_path: &str) -> Result<(Vec<u8>, String)> {
    if signature_path == "-" {
        let mut signature = Vec::new();
        std::io::stdin()
            .read_to_end(&mut signature)
            .context("Failed to read signature from stdin")?;
        Ok((signature, "stdin".to_string()))
    } else {
        let signature = fs::read(signature_path)
            .with_context(|| format!("Failed to read signature file: {signature_path}"))?;
        Ok((signature, signature_path.to_string()))
    }
}

fn describe_trust_mode(args: &VerifyX509Args) -> String {
    let mut mode = if args.allow_untrusted {
        "Allow untrusted roots".to_string()
    } else if args.trust_system_roots {
        "System trust roots".to_string()
    } else {
        "No trust roots".to_string()
    };

    if args.allow_thumbprint.is_some() {
        mode.push_str(" + thumbprint pin");
    }

    mode
}

fn describe_scitt_type(scitt_type: ScittType) -> &'static str {
    match scitt_type {
        ScittType::Mst => "mst",
    }
}

fn describe_scitt_trust_mode(args: &VerifyScittArgs) -> String {
    match args.scitt_type {
        ScittType::Mst => {
            #[cfg(feature = "mst")]
            {
                if args.mst_endpoint.is_some() {
                    return "SCITT receipt trust (mst, explicit JWKS endpoint)".to_string();
                }
            }

            "SCITT receipt trust (mst)".to_string()
        }
    }
}
