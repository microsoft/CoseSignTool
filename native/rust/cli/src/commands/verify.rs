// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! `CoseSignTool verify {x509|scitt} <signature> [--payload <file>]`

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
#[cfg(feature = "mst")]
use cose_sign1_transparent_mst::validation::facts::MstReceiptTrustedFact;
#[cfg(feature = "mst")]
use cose_sign1_transparent_mst::validation::fluent_ext::{
    MstCounterSignatureScopeRulesExt, MstReceiptTrustedWhereExt,
};
#[cfg(feature = "mst")]
use cose_sign1_transparent_mst::validation::MstTrustPack;
use cose_sign1_validation::fluent::{
    CoseSign1TrustPack, CoseSign1Validator, Payload, TrustPlanBuilder,
};
use std::collections::HashMap;
use std::fs;
use std::io::Read;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

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

    /// Trust the embedded x5chain as a trust anchor.
    #[arg(long = "trust-embedded")]
    pub trust_embedded: bool,

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

    /// Issuer(s) to trust. The receipt's issuer field is matched against this list.
    /// Can be specified multiple times. If omitted, all issuers are accepted.
    #[arg(long = "issuer", value_name = "url", action = clap::ArgAction::Append)]
    pub issuer: Vec<String>,

    /// SCITT implementation type.
    #[arg(long = "scitt-type", value_name = "SCITT_TYPE")]
    pub scitt_type: Option<String>,

    /// MST service endpoint URL.
    #[cfg(feature = "mst")]
    #[arg(long = "mst-endpoint", value_name = "mst-endpoint", action = clap::ArgAction::Append)]
    pub mst_endpoints: Vec<String>,

    /// Offline JWKS keys for a specific issuer, in the format issuer=path.
    /// Skips online key discovery for that issuer. Can be specified multiple times.
    /// Specifying offline keys for an issuer implicitly trusts that issuer.
    /// Example: --issuer-offline-keys https://eus.mst.azure.net=keys.jwks
    #[arg(long = "issuer-offline-keys", value_name = "issuer=path", action = clap::ArgAction::Append)]
    pub issuer_offline_keys: Vec<String>,
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
        trust_embedded_chain_as_trusted: args.trust_embedded
            || args.trust_system_roots
            || args.allow_untrusted,
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
    ensure_supported_scitt_type(args.scitt_type.as_deref())?;

    // Parse offline keys: each is "issuer=path"
    let mut offline_keys: HashMap<String, String> = HashMap::new();
    let mut trusted_issuers: Vec<String> = args.issuer.clone();

    #[cfg(feature = "mst")]
    for endpoint in &args.mst_endpoints {
        push_unique(&mut trusted_issuers, endpoint.clone());
    }

    for entry in &args.issuer_offline_keys {
        let (issuer, path) = entry.split_once('=').ok_or_else(|| {
            anyhow::anyhow!(
                "Invalid --issuer-offline-keys format: '{}'. Expected issuer=path (e.g., https://eus.mst.azure.net=keys.jwks)",
                entry
            )
        })?;
        offline_keys.insert(issuer.to_string(), path.to_string());
        // Specifying offline keys implicitly trusts that issuer.
        push_unique(&mut trusted_issuers, issuer.to_string());
    }

    execute_scitt_inner(args, trusted_issuers, offline_keys, format)
}

#[cfg(feature = "mst")]
fn execute_scitt_inner(
    args: VerifyScittArgs,
    trusted_issuers: Vec<String>,
    offline_keys: HashMap<String, String>,
    format: OutputFormat,
) -> Result<i32> {
    let (sig_bytes, signature_display) = read_signature_bytes(&args.signature)?;

    let message = Arc::new(
        cose_sign1_primitives::CoseSign1Message::parse(&sig_bytes)
            .map_err(|e| anyhow::anyhow!("Failed to parse COSE_Sign1: {e}"))?,
    );
    let raw_arc: Arc<[u8]> = Arc::from(sig_bytes);
    let detached_payload = read_detached_payload(args.payload.as_deref())?;

    let mst_pack = build_scitt_trust_pack(&offline_keys)?;
    let validator = build_scitt_validator(mst_pack, &trusted_issuers, detached_payload)?;

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

        output::write_field(stdout, "Trust Model", "SCITT Transparency Receipt")?;
        if trusted_issuers.is_empty() {
            output::write_field(stdout, "Trusted Issuers", "all (no restriction)")?;
        } else {
            for issuer in &trusted_issuers {
                let mode = if offline_keys.contains_key(issuer) {
                    "offline keys"
                } else {
                    "online"
                };
                output::write_field(stdout, "Trusted Issuer", &format!("{issuer} ({mode})"))?;
            }
        }

        output::write_section(stdout, "Verification Stages")?;
        output::write_validation_stage(stdout, "Resolution", &result.resolution)?;
        output::write_validation_stage(stdout, "Trust", &result.trust)?;
        output::write_validation_stage(stdout, "Signature", &result.signature)?;
        output::write_validation_stage(stdout, "Post-Signature", &result.post_signature_policy)?;

        if is_valid {
            println!("\n[OK] Signature verified successfully via SCITT receipt");
        } else {
            println!("\n[ERROR] SCITT receipt verification failed");
        }
    }

    Ok(if is_valid { 0 } else { 1 })
}

#[cfg(not(feature = "mst"))]
fn execute_scitt_inner(
    _args: VerifyScittArgs,
    _trusted_issuers: Vec<String>,
    _offline_keys: HashMap<String, String>,
    _format: OutputFormat,
) -> Result<i32> {
    Err(anyhow::anyhow!(
        "SCITT verification requires the 'mst' feature. Rebuild with --features mst"
    ))
}

#[cfg(feature = "mst")]
fn build_scitt_trust_pack(
    offline_keys: &HashMap<String, String>,
) -> Result<Arc<dyn CoseSign1TrustPack>> {
    if offline_keys.is_empty() {
        return Ok(Arc::new(MstTrustPack::online()));
    }

    // MstTrustPack currently accepts a single shared JWKS document. Issuer allowlisting happens in
    // the trust plan below; per-issuer offline JWKS selection is not yet modeled by the pack API.
    let mut shared_jwks_json: Option<String> = None;
    for jwks_path in offline_keys.values() {
        let jwks_json = fs::read_to_string(jwks_path)
            .with_context(|| format!("Failed to read offline JWKS: {jwks_path}"))?;
        match &shared_jwks_json {
            None => {
                shared_jwks_json = Some(jwks_json);
            }
            Some(existing) if existing == &jwks_json => {}
            Some(_) => {
                return Err(anyhow::anyhow!(
                    "The current MstTrustPack API accepts only one offline JWKS document. Multiple --issuer-offline-keys entries with different files are not yet supported."
                ));
            }
        }
    }

    Ok(Arc::new(MstTrustPack::new(false, shared_jwks_json, None)))
}

#[cfg(feature = "mst")]
fn build_scitt_validator(
    mst_pack: Arc<dyn CoseSign1TrustPack>,
    trusted_issuers: &[String],
    detached_payload: Option<Payload>,
) -> Result<CoseSign1Validator> {
    let validator = if trusted_issuers.is_empty() {
        CoseSign1Validator::new(vec![mst_pack])
    } else {
        let mut trust_plan_builder = TrustPlanBuilder::new(vec![mst_pack.clone()]);

        for (index, issuer) in trusted_issuers.iter().enumerate() {
            if index > 0 {
                trust_plan_builder = trust_plan_builder.or();
            }

            let issuer = issuer.clone();
            trust_plan_builder = trust_plan_builder.for_counter_signature(|counter_signature| {
                counter_signature
                    .require::<MstReceiptTrustedFact>(|fact| fact.require_receipt_trusted())
                    .and()
                    .require_mst_receipt_issuer_eq(issuer)
            });
        }

        let trust_plan = trust_plan_builder
            .compile()
            .map_err(|e| anyhow::anyhow!("Failed to compile SCITT trust plan: {e}"))?;
        CoseSign1Validator::new(trust_plan)
    };

    Ok(validator.with_options(|options| {
        options.detached_payload = detached_payload;
    }))
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
        Some(path) => {
            Ok(Some(Payload::from(fs::read(path).with_context(|| {
                format!("Failed to read payload file: {path}")
            })?)))
        }
        None => Ok(None),
    }
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

fn push_unique(items: &mut Vec<String>, value: String) {
    if !items.iter().any(|item| item == &value) {
        items.push(value);
    }
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
