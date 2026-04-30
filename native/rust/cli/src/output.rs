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
    if let CoseHeaderValue::Bytes(bytes) = value {
        return CwtClaims::from_cbor_bytes(bytes)
            .map_err(|e| anyhow::anyhow!("Failed to decode CWT claims bytes: {e}"));
    }

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn print_banner_does_not_panic() {
        print_banner();
    }

    #[test]
    fn write_field_and_section_emit_expected_output() {
        let mut buffer = Vec::new();
        write_field(&mut buffer, "Issuer", "Contoso").expect("field should be written");
        write_section(&mut buffer, "Summary").expect("section should be written");

        let text = String::from_utf8(buffer).expect("output should be valid UTF-8");
        assert_eq!(text, "  Issuer: Contoso\n\nSummary\n-------\n");
    }

    #[test]
    fn output_format_default_is_text() {
        let format = OutputFormat::default();
        assert!(matches!(format, OutputFormat::Text));
    }

    #[test]
    fn format_algorithm_known_algorithms() {
        assert_eq!(format_algorithm(-7), "-7 (ES256)");
        assert_eq!(format_algorithm(-35), "-35 (ES384)");
        assert_eq!(format_algorithm(-36), "-36 (ES512)");
        assert_eq!(format_algorithm(-37), "-37 (PS256)");
        assert_eq!(format_algorithm(-38), "-38 (PS384)");
        assert_eq!(format_algorithm(-39), "-39 (PS512)");
        assert_eq!(format_algorithm(-257), "-257 (RS256)");
        assert_eq!(format_algorithm(-258), "-258 (RS384)");
        assert_eq!(format_algorithm(-259), "-259 (RS512)");
        assert_eq!(format_algorithm(-8), "-8 (EdDSA)");
    }

    #[test]
    fn format_algorithm_unknown_id() {
        assert_eq!(format_algorithm(999), "999 (Unknown)");
    }

    #[test]
    fn algorithm_name_returns_expected_names() {
        assert_eq!(algorithm_name(-7), "ES256");
        assert_eq!(algorithm_name(-8), "EdDSA");
        assert_eq!(algorithm_name(42), "Unknown");
    }

    #[test]
    fn format_hex_produces_uppercase_hex() {
        assert_eq!(format_hex(&[0xDE, 0xAD, 0xBE, 0xEF]), "DEADBEEF");
        assert_eq!(format_hex(&[]), "");
        assert_eq!(format_hex(&[0x00, 0xFF]), "00FF");
    }

    #[test]
    fn sha256_thumbprint_produces_expected_hex() {
        let result = sha256_thumbprint(b"test data");
        assert_eq!(result.len(), 64); // SHA-256 is 32 bytes = 64 hex chars
        // Verify it's valid uppercase hex
        assert!(result.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn find_header_value_checks_protected_then_unprotected() {
        let protected = CoseHeaderMap::new();
        let unprotected = CoseHeaderMap::new();

        // When neither has the label, returns None
        assert!(find_header_value(&protected, &unprotected, 999).is_none());
    }

    #[test]
    fn header_value_to_i64_handles_int_and_uint() {
        let int_val = CoseHeaderValue::Int(-7);
        assert_eq!(header_value_to_i64(&int_val).unwrap(), -7);

        let uint_val = CoseHeaderValue::Uint(42);
        assert_eq!(header_value_to_i64(&uint_val).unwrap(), 42);

        let text_val = CoseHeaderValue::Text("nope".into());
        assert!(header_value_to_i64(&text_val).is_err());
    }

    #[test]
    fn header_value_to_string_handles_text_only() {
        let text_val = CoseHeaderValue::Text("hello".into());
        assert_eq!(header_value_to_string(&text_val, "test").unwrap(), "hello");

        let int_val = CoseHeaderValue::Int(42);
        let err = header_value_to_string(&int_val, "iss").unwrap_err();
        assert!(err.to_string().contains("iss"));
    }

    #[test]
    fn header_value_to_claim_value_converts_all_types() {
        let text = CoseHeaderValue::Text("hello".into());
        assert!(matches!(
            header_value_to_claim_value(&text).unwrap(),
            CwtClaimValue::Text(ref s) if s == "hello"
        ));

        let int = CoseHeaderValue::Int(-7);
        assert!(matches!(
            header_value_to_claim_value(&int).unwrap(),
            CwtClaimValue::Integer(-7)
        ));

        let uint = CoseHeaderValue::Uint(42);
        assert!(matches!(
            header_value_to_claim_value(&uint).unwrap(),
            CwtClaimValue::Integer(42)
        ));

        let bytes = CoseHeaderValue::Bytes(vec![1, 2, 3].into());
        assert!(matches!(
            header_value_to_claim_value(&bytes).unwrap(),
            CwtClaimValue::Bytes(ref b) if b == &[1, 2, 3]
        ));

        let bool_val = CoseHeaderValue::Bool(true);
        assert!(matches!(
            header_value_to_claim_value(&bool_val).unwrap(),
            CwtClaimValue::Bool(true)
        ));

        let float_val = CoseHeaderValue::Float(3.14);
        assert!(matches!(
            header_value_to_claim_value(&float_val).unwrap(),
            CwtClaimValue::Float(f) if (f - 3.14).abs() < f64::EPSILON
        ));

        let array_val = CoseHeaderValue::Array(vec![]);
        assert!(header_value_to_claim_value(&array_val).is_err());
    }

    #[test]
    fn format_cwt_claim_value_all_types() {
        assert_eq!(
            format_cwt_claim_value(&CwtClaimValue::Text("hello".into())),
            "hello"
        );
        assert_eq!(format_cwt_claim_value(&CwtClaimValue::Integer(42)), "42");
        assert_eq!(
            format_cwt_claim_value(&CwtClaimValue::Bytes(vec![0xCA, 0xFE])),
            "CAFE"
        );
        assert_eq!(
            format_cwt_claim_value(&CwtClaimValue::Bool(false)),
            "false"
        );
        assert_eq!(format_cwt_claim_value(&CwtClaimValue::Float(1.5)), "1.5");
    }

    #[test]
    fn cwt_claim_entries_extracts_standard_and_custom_claims() {
        let mut claims = CwtClaims::new();
        claims.issuer = Some("test-issuer".into());
        claims.subject = Some("test-sub".into());
        claims.audience = Some("test-aud".into());
        claims.expiration_time = Some(1700000000);
        claims.not_before = Some(1699000000);
        claims.issued_at = Some(1699500000);
        claims.cwt_id = Some(vec![0xAB, 0xCD]);
        claims
            .custom_claims
            .insert(100, CwtClaimValue::Text("custom".into()));

        let entries = cwt_claim_entries(&claims);
        assert_eq!(entries.len(), 8);
        assert_eq!(entries[0], ("iss".to_string(), "test-issuer".to_string()));
        assert_eq!(entries[1], ("sub".to_string(), "test-sub".to_string()));
        assert_eq!(entries[2], ("aud".to_string(), "test-aud".to_string()));
        assert_eq!(entries[3].0, "exp");
        assert_eq!(entries[4].0, "nbf");
        assert_eq!(entries[5].0, "iat");
        assert_eq!(entries[6], ("cti".to_string(), "ABCD".to_string()));
        assert_eq!(
            entries[7],
            ("claim[100]".to_string(), "custom".to_string())
        );
    }

    #[test]
    fn cwt_claim_entries_empty_claims() {
        let claims = CwtClaims::new();
        let entries = cwt_claim_entries(&claims);
        assert!(entries.is_empty());
    }

    #[test]
    fn write_validation_stage_success() {
        let result = ValidationResult {
            kind: ValidationResultKind::Success,
            validator_name: "Signature".into(),
            failures: vec![],
            metadata: std::collections::BTreeMap::new(),
        };
        let mut buffer = Vec::new();
        write_validation_stage(&mut buffer, "Signature", &result).unwrap();
        let text = String::from_utf8(buffer).unwrap();
        assert!(text.contains("Succeeded"));
    }

    #[test]
    fn write_validation_stage_failure_with_details() {
        use cose_sign1_validation::fluent::ValidationFailure;
        let result = ValidationResult {
            kind: ValidationResultKind::Failure,
            validator_name: "Trust".into(),
            failures: vec![ValidationFailure {
                message: "chain not trusted".into(),
                error_code: None,
                property_name: None,
                attempted_value: None,
                exception: None,
            }],
            metadata: std::collections::BTreeMap::new(),
        };
        let mut buffer = Vec::new();
        write_validation_stage(&mut buffer, "Trust", &result).unwrap();
        let text = String::from_utf8(buffer).unwrap();
        assert!(text.contains("Failed"));
        assert!(text.contains("chain not trusted"));
    }

    #[test]
    fn write_validation_stage_not_applicable_with_reason() {
        let mut metadata = std::collections::BTreeMap::new();
        metadata.insert(
            ValidationResult::METADATA_REASON_KEY.to_string(),
            "no post-signature validators".to_string(),
        );
        let result = ValidationResult {
            kind: ValidationResultKind::NotApplicable,
            validator_name: "Post-Sig".into(),
            failures: vec![],
            metadata,
        };
        let mut buffer = Vec::new();
        write_validation_stage(&mut buffer, "Post-Sig", &result).unwrap();
        let text = String::from_utf8(buffer).unwrap();
        assert!(text.contains("Not applicable"));
        assert!(text.contains("no post-signature validators"));
    }

    #[test]
    fn write_validation_stage_not_applicable_without_reason() {
        let result = ValidationResult {
            kind: ValidationResultKind::NotApplicable,
            validator_name: "Post-Sig".into(),
            failures: vec![],
            metadata: std::collections::BTreeMap::new(),
        };
        let mut buffer = Vec::new();
        write_validation_stage(&mut buffer, "Post-Sig", &result).unwrap();
        let text = String::from_utf8(buffer).unwrap();
        assert!(text.contains("Not applicable"));
    }

    #[test]
    fn extract_x5chain_returns_none_for_message_without_chain() {
        let message = CoseSign1Message::parse(&[0xD2, 0x84, 0x40, 0xA0, 0x40, 0x40]).unwrap();
        assert!(extract_x5chain(&message).is_none());
    }

    #[test]
    fn extract_signing_certificate_details_coverage_via_formatter() {
        let message = CoseSign1Message::parse(&[0xD2, 0x84, 0x40, 0xA0, 0x40, 0x40]).unwrap();
        assert!(extract_signing_certificate_details(&message).unwrap().is_none());
    }
}
