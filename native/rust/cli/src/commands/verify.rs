// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! `CoseSignTool verify x509 <signature> [--payload <file>]`

use crate::output::{self, OutputFormat};
use anyhow::{Context, Result};
use clap::{Args, Subcommand};
use cose_sign1_certificates::validation::facts::{X509ChainTrustedFact, X509SigningCertificateIdentityFact};
use cose_sign1_certificates::validation::fluent_ext::{
    X509ChainTrustedWhereExt, X509SigningCertificateIdentityWhereExt,
};
use cose_sign1_certificates::validation::pack::{CertificateTrustOptions, X509CertificateTrustPack};
use cose_sign1_validation::fluent::{
    CoseSign1TrustPack, CoseSign1Validator, Payload, TrustPlanBuilder,
};
use std::fs;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

/// Verification method.
#[derive(Subcommand, Debug)]
pub enum VerifyMethod {
    /// Verify using X.509 certificate trust.
    X509(VerifyX509Args),
}

/// Arguments for X.509 verification.
#[derive(Args, Debug)]
pub struct VerifyX509Args {
    /// Path to the COSE_Sign1 signature file.
    pub signature: String,

    /// Path to the payload file (required for detached/indirect signatures).
    #[arg(long)]
    pub payload: Option<String>,

    /// Allow a specific signing certificate thumbprint (SHA-256 hex).
    #[arg(long = "allow-thumbprint")]
    pub allow_thumbprint: Option<String>,

    /// Trust embedded certificate chain (no OS trust store validation).
    #[arg(long = "trust-embedded")]
    pub trust_embedded: bool,
}

/// Execute the verify command.
pub fn execute(method: VerifyMethod, format: OutputFormat) -> Result<i32> {
    match method {
        VerifyMethod::X509(args) => execute_x509(args, format),
    }
}

fn execute_x509(args: VerifyX509Args, format: OutputFormat) -> Result<i32> {
    let sig_bytes = fs::read(&args.signature)
        .with_context(|| format!("Failed to read signature file: {}", args.signature))?;

    let message = Arc::new(
        cose_sign1_primitives::CoseSign1Message::parse(&sig_bytes)
            .map_err(|e| anyhow::anyhow!("Failed to parse COSE_Sign1: {e}"))?,
    );
    let raw_arc: Arc<[u8]> = Arc::from(sig_bytes);

    let detached_payload = match &args.payload {
        Some(path) => Some(Payload::from(
            fs::read(path).with_context(|| format!("Failed to read payload file: {path}"))?,
        )),
        None => None,
    };

    let trust_options = CertificateTrustOptions {
        trust_embedded_chain_as_trusted: args.trust_embedded,
        ..Default::default()
    };
    let cert_pack: Arc<dyn CoseSign1TrustPack> = Arc::new(X509CertificateTrustPack::new(trust_options));
    let validator = build_validator(cert_pack, args.allow_thumbprint.as_deref())?.with_options(|options| {
        options.detached_payload = detached_payload;
    });

    let result = validator
        .validate_arc(message, raw_arc)
        .map_err(|e| anyhow::anyhow!("Validation error: {e}"))?;

    let is_valid = result.overall.is_valid();

    if !matches!(format, OutputFormat::Quiet) {
        let stdout = &mut std::io::stdout();
        output::write_section(stdout, "Verification Operation")?;
        output::write_field(stdout, "Signature", &args.signature)?;

        if let Some(ref payload_path) = args.payload {
            output::write_field(stdout, "Payload", payload_path)?;
        }

        if is_valid {
            println!("\n[OK] Signature verified successfully");
        } else {
            println!("\n[ERROR] Signature verification failed");
            for failure in &result.overall.failures {
                eprintln!("[ERROR]   {:?}", failure);
            }
        }
    }

    Ok(if is_valid { 0 } else { 1 })
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
