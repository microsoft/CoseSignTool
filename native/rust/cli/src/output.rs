// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Output formatting for CLI results.

use anyhow::{Context, Result};
use cose_sign1_headers::{CWTClaimsHeaderLabels, CwtClaimValue, CwtClaims};
use cose_sign1_primitives::{CoseHeaderLabel, CoseHeaderMap, CoseHeaderValue, CoseSign1Message};
use cose_sign1_validation::fluent::{ValidationResult, ValidationResultKind};
use sha2::{Digest, Sha256};
use std::io::Write;
use x509_parser::prelude::{FromDer, X509Certificate};

/// Print the CoseSignTool banner to stderr.
pub fn print_banner() {
    let version = env!("CARGO_PKG_VERSION");
    let separator = "=".repeat(80);
    eprintln!("{separator}");
    eprintln!("CoseSignTool (Rust)");
    eprintln!("  Version: {version}");
    eprintln!("{separator}");
    eprintln!();
}

/// Output format for command results.
#[derive(Debug, Clone, Copy, clap::ValueEnum)]
pub enum OutputFormat {
    Text,
    Json,
    Quiet,
}

impl Default for OutputFormat {
    fn default() -> Self {
        Self::Text
    }
}

/// Parsed certificate details for text and JSON output.
#[derive(Debug, Clone)]
pub struct CertificateDetails {
    pub subject: String,
    pub issuer: String,
    pub thumbprint: String,
    pub not_before: String,
    pub not_after: String,
}

/// Parsed x5t details for text and JSON output.
#[derive(Debug, Clone)]
pub struct X5tDetails {
    pub algorithm_id: i64,
    pub algorithm_name: &'static str,
    pub thumbprint: String,
}

/// Write a key-value pair in the appropriate format.
pub fn write_field(w: &mut dyn Write, key: &str, value: &str) -> std::io::Result<()> {
    writeln!(w, "  {key}: {value}")
}

/// Write a section header.
pub fn write_section(w: &mut dyn Write, title: &str) -> std::io::Result<()> {
    writeln!(w, "\n{title}")?;
    writeln!(w, "{}", "-".repeat(title.len()))
}

/// Format a COSE algorithm identifier with a friendly algorithm name.
pub fn format_algorithm(algorithm_id: i64) -> String {
    format!("{algorithm_id} ({})", algorithm_name(algorithm_id))
}

/// Return the friendly name for a COSE algorithm identifier.
pub fn algorithm_name(algorithm_id: i64) -> &'static str {
    match algorithm_id {
        -7 => "ES256",
        -35 => "ES384",
        -36 => "ES512",
        -37 => "PS256",
        -38 => "PS384",
        -39 => "PS512",
        -257 => "RS256",
        -258 => "RS384",
        -259 => "RS512",
        -8 => "EdDSA",
        _ => "Unknown",
    }
}

/// Convert bytes to uppercase hexadecimal.
pub fn format_hex(bytes: &[u8]) -> String {
    hex::encode_upper(bytes)
}

/// Parse certificate details from DER bytes.
pub fn parse_certificate_details(cert_der: &[u8]) -> Result<CertificateDetails> {
    let (_, certificate) = X509Certificate::from_der(cert_der)
        .map_err(|e| anyhow::anyhow!("Failed to parse certificate: {e}"))?;
    let thumbprint = sha256_thumbprint(cert_der);

    Ok(CertificateDetails {
        subject: format!("{}", certificate.subject()),
        issuer: format!("{}", certificate.issuer()),
        thumbprint,
        not_before: format!("{}", certificate.validity().not_before),
        not_after: format!("{}", certificate.validity().not_after),
    })
}

/// Extract the signing certificate details from x5chain.
pub fn extract_signing_certificate_details(
    message: &CoseSign1Message,
) -> Result<Option<CertificateDetails>> {
    let Some(chain) = extract_x5chain(message) else {
        return Ok(None);
    };

    let Some(leaf) = chain.first() else {
        return Ok(None);
    };

    Ok(Some(parse_certificate_details(leaf)?))
}

/// Extract x5chain certificate DER bytes from a COSE message.
pub fn extract_x5chain(message: &CoseSign1Message) -> Option<Vec<Vec<u8>>> {
    let label = CoseHeaderLabel::Int(33);
    message
        .protected_headers()
        .get_bytes_one_or_many(&label)
        .or_else(|| message.unprotected_headers().get_bytes_one_or_many(&label))
}

/// Extract x5t details from a COSE message.
pub fn extract_x5t(message: &CoseSign1Message) -> Result<Option<X5tDetails>> {
    let Some(value) = find_header_value(
        message.protected_headers(),
        message.unprotected_headers(),
        34,
    ) else {
        return Ok(None);
    };

    let CoseHeaderValue::Array(values) = value else {
        return Err(anyhow::anyhow!("x5t header is not a CBOR array"));
    };

    if values.len() != 2 {
        return Err(anyhow::anyhow!(
            "x5t header must contain [algorithm, thumbprint]"
        ));
    }

    let algorithm_id =
        header_value_to_i64(&values[0]).context("x5t hash algorithm is not an integer")?;
    let thumbprint = values[1]
        .as_bytes()
        .map(format_hex)
        .ok_or_else(|| anyhow::anyhow!("x5t thumbprint is not a byte string"))?;

    Ok(Some(X5tDetails {
        algorithm_id,
        algorithm_name: algorithm_name(algorithm_id),
        thumbprint,
    }))
}

/// Extract and parse CWT claims from a COSE message.
pub fn extract_cwt_claims(message: &CoseSign1Message) -> Result<Option<CwtClaims>> {
    let Some(value) = find_header_value(
        message.protected_headers(),
        message.unprotected_headers(),
        15,
    ) else {
        return Ok(None);
    };

    parse_cwt_claims(value).map(Some)
}

/// Convert parsed CWT claims into printable key-value pairs.
pub fn cwt_claim_entries(claims: &CwtClaims) -> Vec<(String, String)> {
    let mut entries = Vec::new();

    if let Some(value) = &claims.issuer {
        entries.push(("iss".to_string(), value.clone()));
    }
    if let Some(value) = &claims.subject {
        entries.push(("sub".to_string(), value.clone()));
    }
    if let Some(value) = &claims.audience {
        entries.push(("aud".to_string(), value.clone()));
    }
    if let Some(value) = claims.expiration_time {
        entries.push(("exp".to_string(), value.to_string()));
    }
    if let Some(value) = claims.not_before {
        entries.push(("nbf".to_string(), value.to_string()));
    }
    if let Some(value) = claims.issued_at {
        entries.push(("iat".to_string(), value.to_string()));
    }
    if let Some(value) = &claims.cwt_id {
        entries.push(("cti".to_string(), format_hex(value)));
    }

    let mut custom_labels: Vec<i64> = claims.custom_claims.keys().copied().collect();
    custom_labels.sort_unstable();

    for label in custom_labels {
        if let Some(value) = claims.custom_claims.get(&label) {
            entries.push((format!("claim[{label}]"), format_cwt_claim_value(value)));
        }
    }

    entries
}

/// Write a formatted validation stage result.
pub fn write_validation_stage(
    w: &mut dyn Write,
    stage_name: &str,
    result: &ValidationResult,
) -> std::io::Result<()> {
    let status = match result.kind {
        ValidationResultKind::Success => "Succeeded".to_string(),
        ValidationResultKind::Failure => "Failed".to_string(),
        ValidationResultKind::NotApplicable => {
            if let Some(reason) = result.metadata.get(ValidationResult::METADATA_REASON_KEY) {
                format!("Not applicable ({reason})")
            } else {
                "Not applicable".to_string()
            }
        }
    };

    write_field(w, stage_name, &status)?;

    for failure in &result.failures {
        write_field(w, &format!("{stage_name} Detail"), failure.message.as_ref())?;
    }

    Ok(())
}

fn sha256_thumbprint(cert_der: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(cert_der);
    format_hex(&hasher.finalize())
}

fn find_header_value<'a>(
    protected: &'a CoseHeaderMap,
    unprotected: &'a CoseHeaderMap,
    label: i64,
) -> Option<&'a CoseHeaderValue> {
    let header_label = CoseHeaderLabel::Int(label);
    protected
        .get(&header_label)
        .or_else(|| unprotected.get(&header_label))
}

fn parse_cwt_claims(value: &CoseHeaderValue) -> Result<CwtClaims> {
    let CoseHeaderValue::Map(entries) = value else {
        return Err(anyhow::anyhow!("CWT claims header is not a CBOR map"));
    };

    let mut claims = CwtClaims::new();

    for (label, value) in entries {
        let CoseHeaderLabel::Int(label) = label else {
            continue;
        };

        match *label {
            CWTClaimsHeaderLabels::ISSUER => {
                claims.issuer = Some(header_value_to_string(value, "iss")?);
            }
            CWTClaimsHeaderLabels::SUBJECT => {
                claims.subject = Some(header_value_to_string(value, "sub")?);
            }
            CWTClaimsHeaderLabels::AUDIENCE => {
                claims.audience = Some(header_value_to_string(value, "aud")?);
            }
            CWTClaimsHeaderLabels::EXPIRATION_TIME => {
                claims.expiration_time =
                    Some(header_value_to_i64(value).context("Invalid exp claim")?);
            }
            CWTClaimsHeaderLabels::NOT_BEFORE => {
                claims.not_before = Some(header_value_to_i64(value).context("Invalid nbf claim")?);
            }
            CWTClaimsHeaderLabels::ISSUED_AT => {
                claims.issued_at = Some(header_value_to_i64(value).context("Invalid iat claim")?);
            }
            CWTClaimsHeaderLabels::CWT_ID => {
                let bytes = value
                    .as_bytes()
                    .ok_or_else(|| anyhow::anyhow!("Invalid cti claim: expected byte string"))?;
                claims.cwt_id = Some(bytes.to_vec());
            }
            custom_label => {
                claims
                    .custom_claims
                    .insert(custom_label, header_value_to_claim_value(value)?);
            }
        }
    }

    Ok(claims)
}

fn header_value_to_claim_value(value: &CoseHeaderValue) -> Result<CwtClaimValue> {
    match value {
        CoseHeaderValue::Text(value) => Ok(CwtClaimValue::Text(value.to_string())),
        CoseHeaderValue::Int(value) => Ok(CwtClaimValue::Integer(*value)),
        CoseHeaderValue::Uint(value) => {
            let value = i64::try_from(*value)
                .map_err(|_| anyhow::anyhow!("Unsigned CWT claim exceeds i64 range"))?;
            Ok(CwtClaimValue::Integer(value))
        }
        CoseHeaderValue::Bytes(value) => Ok(CwtClaimValue::Bytes(value.as_bytes().to_vec())),
        CoseHeaderValue::Bool(value) => Ok(CwtClaimValue::Bool(*value)),
        CoseHeaderValue::Float(value) => Ok(CwtClaimValue::Float(*value)),
        _ => Err(anyhow::anyhow!("Unsupported CWT claim value type")),
    }
}

fn header_value_to_i64(value: &CoseHeaderValue) -> Result<i64> {
    match value {
        CoseHeaderValue::Int(value) => Ok(*value),
        CoseHeaderValue::Uint(value) => {
            i64::try_from(*value).map_err(|_| anyhow::anyhow!("Unsigned integer exceeds i64 range"))
        }
        _ => Err(anyhow::anyhow!("Expected integer value")),
    }
}

fn header_value_to_string(value: &CoseHeaderValue, claim_name: &str) -> Result<String> {
    match value {
        CoseHeaderValue::Text(value) => Ok(value.to_string()),
        _ => Err(anyhow::anyhow!(
            "Invalid {claim_name} claim: expected text string"
        )),
    }
}

fn format_cwt_claim_value(value: &CwtClaimValue) -> String {
    match value {
        CwtClaimValue::Text(value) => value.clone(),
        CwtClaimValue::Integer(value) => value.to_string(),
        CwtClaimValue::Bytes(value) => format_hex(value),
        CwtClaimValue::Bool(value) => value.to_string(),
        CwtClaimValue::Float(value) => value.to_string(),
    }
}
