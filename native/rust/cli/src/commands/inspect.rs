// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! `CoseSignTool inspect <signature>` — parse and display COSE_Sign1 structure.

use crate::output::{self, OutputFormat};
use anyhow::{Context, Result};
use clap::Args;
use cose_sign1_primitives::CoseHeaderLabel;
use std::fs;

/// Arguments for the inspect command.
#[derive(Args, Debug)]
pub struct InspectArgs {
    /// Path to the COSE_Sign1 signature file.
    pub signature: String,
}

/// Execute the inspect command.
pub fn execute(args: InspectArgs, format: OutputFormat) -> Result<i32> {
    let raw_bytes = fs::read(&args.signature)
        .with_context(|| format!("Failed to read signature file: {}", args.signature))?;

    let message = cose_sign1_primitives::CoseSign1Message::parse(&raw_bytes)
        .map_err(|e| anyhow::anyhow!("Failed to parse COSE_Sign1: {e}"))?;

    let stdout = &mut std::io::stdout();

    match format {
        OutputFormat::Quiet => {}
        OutputFormat::Text => {
            output::write_section(stdout, "COSE_Sign1 Message")?;
            output::write_field(stdout, "File", &args.signature)?;
            output::write_field(stdout, "Size", &format!("{} bytes", raw_bytes.len()))?;

            if let Some(alg) = message.alg() {
                output::write_field(stdout, "Algorithm", &format!("{alg}"))?;
            }

            // Payload
            if message.is_detached() {
                output::write_field(stdout, "Payload", "Detached (not embedded)")?;
            } else if let Some(payload) = message.payload() {
                output::write_field(stdout, "Payload", &format!("{} bytes (embedded)", payload.len()))?;
            }

            // Signature
            output::write_field(
                stdout,
                "Signature",
                &format!("{} bytes", message.signature().len()),
            )?;

            // x5chain (certificate chain) if present
            let x5chain_label = CoseHeaderLabel::Int(33);
            let protected_chain = message.protected_headers().get_arc_slices_one_or_many(&x5chain_label);
            let unprotected_chain = message.unprotected_headers().get_arc_slices_one_or_many(&x5chain_label);
            let chain = protected_chain.or(unprotected_chain);
            if let Some(chain_items) = chain {
                let certificate_count = chain_items.len();
                let total_chain_bytes: usize = chain_items.iter().map(|item| item.len()).sum();
                output::write_field(
                    stdout,
                    "x5chain",
                    &format!("{certificate_count} cert(s), {total_chain_bytes} bytes"),
                )?;
            }

            println!();
        }
        OutputFormat::Json => {
            let info = serde_json::json!({
                "file": args.signature,
                "size": raw_bytes.len(),
                "detached": message.is_detached(),
                "signature_size": message.signature().len(),
            });
            println!("{}", serde_json::to_string_pretty(&info)?);
        }
    }

    Ok(0)
}
