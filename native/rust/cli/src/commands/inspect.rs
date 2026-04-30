// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! `CoseSignTool inspect <signature>` — parse and display COSE_Sign1 structure.

use crate::output::{self, OutputFormat};
use anyhow::{Context, Result};
use clap::{Args, Command as ClapCommand};
use serde_json::{Map, Value};
use std::fs;

/// Arguments for the inspect command.
#[derive(Args, Debug)]
pub struct InspectArgs {
    /// Path to the COSE_Sign1 signature file.
    #[arg(value_name = "signature")]
    pub signature: String,

    /// Extract embedded payload to file
    #[arg(long = "extract-payload", value_name = "path")]
    pub extract_payload: Option<String>,
}

pub fn build_inspect_command() -> ClapCommand {
    InspectArgs::augment_args(
        ClapCommand::new("inspect")
            .about("Inspect a COSE_Sign1 message (parse and display structure).")
            .arg_required_else_help(true),
    )
}

/// Execute the inspect command.
pub fn execute(args: InspectArgs, format: OutputFormat) -> Result<i32> {
    let raw_bytes = fs::read(&args.signature)
        .with_context(|| format!("Failed to read signature file: {}", args.signature))?;

    let message = cose_sign1_primitives::CoseSign1Message::parse(&raw_bytes)
        .map_err(|e| anyhow::anyhow!("Failed to parse COSE_Sign1: {e}"))?;

    if let Some(extract_path) = &args.extract_payload {
        let payload = message
            .payload()
            .ok_or_else(|| anyhow::anyhow!("COSE_Sign1 message does not contain an embedded payload"))?;
        fs::write(extract_path, payload)
            .with_context(|| format!("Failed to write extracted payload: {extract_path}"))?;
    }

    let content_type = message
        .protected_headers()
        .content_type()
        .or_else(|| message.unprotected_headers().content_type());
    let x5chain = output::extract_x5chain(&message);
    let x5t = output::extract_x5t(&message)?;
    let cwt_claims = output::extract_cwt_claims(&message)?;

    match format {
        OutputFormat::Quiet => {}
        OutputFormat::Text => {
            let stdout = &mut std::io::stdout();
            output::write_section(stdout, "COSE_Sign1 Message")?;
            output::write_field(stdout, "File", &args.signature)?;
            output::write_field(stdout, "Size", &format!("{} bytes", raw_bytes.len()))?;

            if let Some(alg) = message.alg() {
                output::write_field(stdout, "Algorithm", &output::format_algorithm(alg))?;
            }

            output::write_field(
                stdout,
                "Content-Type",
                &content_type
                    .as_ref()
                    .map(ToString::to_string)
                    .unwrap_or_else(|| "Not set".to_string()),
            )?;

            if message.is_detached() {
                output::write_field(stdout, "Payload", "Detached (not embedded)")?;
            } else if let Some(payload) = message.payload() {
                output::write_field(
                    stdout,
                    "Payload",
                    &format!("{} bytes (embedded)", payload.len()),
                )?;
            }

            if let Some(extract_path) = &args.extract_payload {
                output::write_field(stdout, "Extracted Payload", extract_path)?;
            }

            output::write_field(
                stdout,
                "Signature",
                &format!("{} bytes", message.signature().len()),
            )?;

            if let Some(x5t) = &x5t {
                output::write_field(
                    stdout,
                    "x5t",
                    &format!(
                        "{} ({})",
                        x5t.thumbprint,
                        output::format_algorithm(x5t.algorithm_id)
                    ),
                )?;
            }

            if let Some(certificates) = &x5chain {
                output::write_field(
                    stdout,
                    "x5chain",
                    &format!("{} certificate(s)", certificates.len()),
                )?;
            }

            if let Some(claims) = &cwt_claims {
                output::write_section(stdout, "CWT Claims")?;
                for (key, value) in output::cwt_claim_entries(claims) {
                    output::write_field(stdout, &key, &value)?;
                }
            }

            if let Some(certificates) = &x5chain {
                output::write_section(stdout, "Certificates")?;
                for (index, cert_der) in certificates.iter().enumerate() {
                    let details = output::parse_certificate_details(cert_der)?;
                    output::write_field(
                        stdout,
                        &format!("Certificate {} Subject", index + 1),
                        &details.subject,
                    )?;
                    output::write_field(
                        stdout,
                        &format!("Certificate {} Issuer", index + 1),
                        &details.issuer,
                    )?;
                    output::write_field(
                        stdout,
                        &format!("Certificate {} Thumbprint", index + 1),
                        &details.thumbprint,
                    )?;
                    output::write_field(
                        stdout,
                        &format!("Certificate {} Valid From", index + 1),
                        &details.not_before,
                    )?;
                    output::write_field(
                        stdout,
                        &format!("Certificate {} Valid To", index + 1),
                        &details.not_after,
                    )?;
                }
            }

            println!();
        }
        OutputFormat::Json => {
            let certificates_json = if let Some(certificates) = &x5chain {
                certificates
                    .iter()
                    .map(|cert_der| {
                        let details = output::parse_certificate_details(cert_der)?;
                        Ok(serde_json::json!({
                            "subject": details.subject,
                            "issuer": details.issuer,
                            "thumbprint": details.thumbprint,
                            "valid_from": details.not_before,
                            "valid_to": details.not_after,
                        }))
                    })
                    .collect::<Result<Vec<Value>>>()?
            } else {
                Vec::new()
            };

            let cwt_claims_json = if let Some(claims) = &cwt_claims {
                let mut map = Map::new();
                for (key, value) in output::cwt_claim_entries(claims) {
                    map.insert(key, Value::String(value));
                }
                Value::Object(map)
            } else {
                Value::Null
            };

            let info = serde_json::json!({
                "file": args.signature,
                "size": raw_bytes.len(),
                "algorithm": message.alg().map(|alg| serde_json::json!({
                    "id": alg,
                    "name": output::algorithm_name(alg),
                })),
                "content_type": content_type.map(|value| value.to_string()),
                "detached": message.is_detached(),
                "payload_size": message.payload().map(|payload| payload.len()),
                "signature_size": message.signature().len(),
                "x5t": x5t.as_ref().map(|value| serde_json::json!({
                    "algorithm_id": value.algorithm_id,
                    "algorithm_name": value.algorithm_name,
                    "thumbprint": value.thumbprint,
                })),
                "x5chain_count": x5chain.as_ref().map(|value| value.len()).unwrap_or(0),
                "certificates": certificates_json,
                "cwt_claims": cwt_claims_json,
            });
            println!("{}", serde_json::to_string_pretty(&info)?);
        }
    }

    Ok(0)
}
