// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Inspect command: parse and display COSE_Sign1 message structure.

use clap::Args;
use std::fs;
use std::path::PathBuf;
use crate::providers::output::{OutputFormat, OutputSection, render};

#[derive(Args)]
pub struct InspectArgs {
    /// Path to the COSE_Sign1 message file
    #[arg(short, long)]
    pub input: PathBuf,

    /// Output format
    #[arg(long, default_value = "text", value_parser = ["text", "json", "quiet"])]
    pub output_format: String,

    /// Show all header entries (not just standard ones)
    #[arg(long)]
    pub all_headers: bool,

    /// Show certificate chain details (if x5chain present)
    #[arg(long)]
    pub show_certs: bool,

    /// Show raw hex of signature
    #[arg(long)]
    pub show_signature: bool,

    /// Show CWT claims (if present in header label 15)
    #[arg(long)]
    pub show_cwt: bool,
}

#[cfg_attr(coverage_nightly, coverage(off))]
pub fn run(args: InspectArgs) -> i32 {
    tracing::info!(input = %args.input.display(), output_format = %args.output_format, "Inspecting COSE_Sign1 message");

    // 1. Read COSE bytes
    let cose_bytes = match fs::read(&args.input) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("Error reading input: {}", e);
            return 2;
        }
    };

    // 2. Parse
    let msg = match cose_sign1_primitives::CoseSign1Message::parse(&cose_bytes) {
        Ok(m) => m,
        Err(e) => {
            eprintln!("Parse error: {}", e);
            return 2;
        }
    };

    // 3. Build structured output
    let mut sections: Vec<(String, OutputSection)> = Vec::new();

    // Section 1: Message Overview
    let mut overview = OutputSection::new();
    overview.insert("Total size".into(), format!("{} bytes", cose_bytes.len()));
    let headers = msg.protected_headers();
    if let Some(alg) = headers.alg() {
        overview.insert("Algorithm".into(), format!("{} ({})", alg_name(alg), alg));
    }
    if let Some(ct) = headers.content_type() {
        overview.insert("Content-Type".into(), format!("{:?}", ct));
    }
    overview.insert("Payload".into(), if msg.is_detached() {
        "detached".into()
    } else {
        format!("{} bytes (embedded)", msg.payload.as_ref().map_or(0, |p| p.len()))
    });
    overview.insert("Signature".into(), format!("{} bytes", msg.signature.len()));
    sections.push(("Message Overview".into(), overview));

    // Section 2: Protected Headers (all entries)
    if args.all_headers {
        let mut hdr_section = OutputSection::new();
        hdr_section.insert("Count".into(), format!("{}", headers.len()));
        
        // Iterate over all header entries
        for (label, value) in headers.iter() {
            let label_str = match label {
                cose_primitives::headers::CoseHeaderLabel::Int(i) => format!("Label {}", i),
                cose_primitives::headers::CoseHeaderLabel::Text(s) => format!("Label \"{}\"", s),
            };
            let value_str = format_header_value(value);
            hdr_section.insert(label_str, value_str);
        }
        sections.push(("Protected Headers".into(), hdr_section));
    }

    // Section 3: Unprotected Headers
    if args.all_headers {
        let mut uhdr = OutputSection::new();
        uhdr.insert("Count".into(), format!("{}", msg.unprotected.len()));
        
        // Iterate over all unprotected header entries
        for (label, value) in msg.unprotected.iter() {
            let label_str = match label {
                cose_primitives::headers::CoseHeaderLabel::Int(i) => format!("Label {}", i),
                cose_primitives::headers::CoseHeaderLabel::Text(s) => format!("Label \"{}\"", s),
            };
            let value_str = format_header_value(value);
            uhdr.insert(label_str, value_str);
        }
        sections.push(("Unprotected Headers".into(), uhdr));
    }

    // Section 4: CWT Claims (header label 15)
    if args.show_cwt {
        let mut cwt_section = OutputSection::new();
        if let Some(cwt_header_value) = headers.get(&cose_primitives::headers::CoseHeaderLabel::Int(15)) {
            if let Some(cwt_bytes) = cwt_header_value.as_bytes() {
                match cose_sign1_headers::CwtClaims::from_cbor_bytes(cwt_bytes) {
                    Ok(claims) => {
                        if let Some(ref iss) = claims.issuer {
                            cwt_section.insert("Issuer (iss)".into(), iss.clone());
                        }
                        if let Some(ref sub) = claims.subject {
                            cwt_section.insert("Subject (sub)".into(), sub.clone());
                        }
                        if let Some(ref aud) = claims.audience {
                            cwt_section.insert("Audience (aud)".into(), aud.clone());
                        }
                        if let Some(iat) = claims.issued_at {
                            cwt_section.insert("Issued At (iat)".into(), format_timestamp(iat));
                        }
                        if let Some(nbf) = claims.not_before {
                            cwt_section.insert("Not Before (nbf)".into(), format_timestamp(nbf));
                        }
                        if let Some(exp) = claims.expiration_time {
                            cwt_section.insert("Expires (exp)".into(), format_timestamp(exp));
                        }
                        if let Some(ref cti) = claims.cwt_id {
                            cwt_section.insert("CWT ID (cti)".into(), hex::encode(cti));
                        }
                        if !claims.custom_claims.is_empty() {
                            cwt_section.insert("Custom Claims".into(), format!("{} additional claims", claims.custom_claims.len()));
                        }
                    }
                    Err(e) => {
                        cwt_section.insert("Error".into(), format!("Failed to decode CWT: {}", e));
                    }
                }
            } else {
                cwt_section.insert("Error".into(), "CWT header is not a byte string".into());
            }
        } else {
            cwt_section.insert("Status".into(), "Not present".into());
        }
        sections.push(("CWT Claims".into(), cwt_section));
    }

    // Section 5: Certificate chain (x5chain header label 33)
    #[cfg(feature = "certificates")]
    if args.show_certs {
        let mut cert_section = OutputSection::new();
        
        // Check both protected and unprotected headers for x5chain (label 33)
        let x5chain_label = cose_primitives::headers::CoseHeaderLabel::Int(33);
        let x5chain_value = headers.get(&x5chain_label)
            .or_else(|| msg.unprotected.get(&x5chain_label));
            
        if let Some(x5chain_value) = x5chain_value {
            if let Some(cert_bytes_vec) = x5chain_value.as_bytes_one_or_many() {
                cert_section.insert("Certificate Count".into(), format!("{}", cert_bytes_vec.len()));
                for (i, cert_der) in cert_bytes_vec.iter().enumerate() {
                    // For now, just show the size and a preview of the certificate DER
                    cert_section.insert(
                        format!("Certificate {}", i + 1),
                        format!("{} bytes DER", cert_der.len())
                    );
                }
            } else {
                cert_section.insert("Error".into(), "x5chain is not a byte string or array of byte strings".into());
            }
        } else {
            cert_section.insert("Status".into(), "x5chain not present".into());
        }
        sections.push(("Certificate Chain (x5chain)".into(), cert_section));
    }
    
    #[cfg(not(feature = "certificates"))]
    if args.show_certs {
        let mut cert_section = OutputSection::new();
        cert_section.insert("Status".into(), "Certificate parsing not available (certificates feature not enabled)".into());
        sections.push(("Certificate Chain (x5chain)".into(), cert_section));
    }

    // Section 6: Raw signature (hex)
    if args.show_signature {
        let mut sig_section = OutputSection::new();
        sig_section.insert("Hex".into(), hex::encode(&msg.signature));
        sections.push(("Signature".into(), sig_section));
    }

    // Render
    let output_format: OutputFormat = args.output_format.parse().unwrap_or(OutputFormat::Text);
    let rendered = render(output_format, &sections);
    if !rendered.is_empty() {
        print!("{}", rendered);
    }

    0
}

fn format_header_value(value: &cose_primitives::headers::CoseHeaderValue) -> String {
    match value {
        cose_primitives::headers::CoseHeaderValue::Int(i) => i.to_string(),
        cose_primitives::headers::CoseHeaderValue::Uint(u) => u.to_string(),
        cose_primitives::headers::CoseHeaderValue::Text(s) => format!("\"{}\"", s),
        cose_primitives::headers::CoseHeaderValue::Bytes(b) => {
            if b.len() <= 32 {
                hex::encode(b)
            } else {
                format!("<{} bytes>", b.len())
            }
        }
        cose_primitives::headers::CoseHeaderValue::Bool(b) => b.to_string(),
        cose_primitives::headers::CoseHeaderValue::Array(_) => "<array>".to_string(),
        cose_primitives::headers::CoseHeaderValue::Map(_) => "<map>".to_string(),
        cose_primitives::headers::CoseHeaderValue::Tagged(tag, _) => format!("<tagged {}>", tag),
        cose_primitives::headers::CoseHeaderValue::Float(f) => f.to_string(),
        cose_primitives::headers::CoseHeaderValue::Null => "null".to_string(),
        cose_primitives::headers::CoseHeaderValue::Undefined => "undefined".to_string(),
        cose_primitives::headers::CoseHeaderValue::Raw(b) => format!("<raw {} bytes>", b.len()),
    }
}

fn format_timestamp(timestamp: i64) -> String {
    // Format Unix timestamp as both epoch and human-readable time
    use std::time::{UNIX_EPOCH, Duration};
    
    if let Some(system_time) = UNIX_EPOCH.checked_add(Duration::from_secs(timestamp as u64)) {
        if let Ok(datetime) = system_time.duration_since(UNIX_EPOCH) {
            format!("{} ({})", timestamp, format_duration_since_epoch(datetime))
        } else {
            timestamp.to_string()
        }
    } else {
        timestamp.to_string()
    }
}

fn format_duration_since_epoch(duration: std::time::Duration) -> String {
    // Simple formatter - just show the epoch time for now
    // In a full implementation, you might want to use chrono or similar
    format!("epoch+{}s", duration.as_secs())
}

fn alg_name(alg: i64) -> &'static str {
    match alg {
        -7 => "ES256",
        -35 => "ES384",
        -36 => "ES512",
        -8 => "EdDSA",
        -37 => "PS256",
        -257 => "RS256",
        _ => "Unknown",
    }
}
