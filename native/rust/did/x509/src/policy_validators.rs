// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use crate::constants::*;
use crate::error::DidX509Error;
use crate::models::SanType;
use crate::san_parser;
use crate::x509_extensions;
use x509_parser::prelude::*;

/// Validate Extended Key Usage (EKU) policy
pub fn validate_eku(cert: &X509Certificate, expected_oids: &[String]) -> Result<(), DidX509Error> {
    let ekus = x509_extensions::extract_extended_key_usage(cert);

    if ekus.is_empty() {
        return Err(DidX509Error::PolicyValidationFailed(
            "EKU policy validation failed: Leaf certificate has no Extended Key Usage extension"
                .into(),
        ));
    }

    // Check that ALL expected OIDs are present
    for expected_oid in expected_oids {
        if !ekus.iter().any(|oid| oid == expected_oid) {
            return Err(DidX509Error::PolicyValidationFailed(format!(
                "EKU policy validation failed: Required EKU OID '{}' not found in leaf certificate",
                expected_oid
            )));
        }
    }

    Ok(())
}

/// Validate Subject Distinguished Name policy
pub fn validate_subject(
    cert: &X509Certificate,
    expected_attrs: &[(String, String)],
) -> Result<(), DidX509Error> {
    if expected_attrs.is_empty() {
        return Err(DidX509Error::PolicyValidationFailed(
            "Subject policy validation failed: Must contain at least one attribute".into(),
        ));
    }

    // Parse the certificate subject
    let subject = cert.subject();

    // Check that ALL expected attribute/value pairs match
    for (attr_label, expected_value) in expected_attrs {
        // Find the OID for this attribute label
        let oid = attribute_label_to_oid(attr_label).ok_or_else(|| {
            DidX509Error::PolicyValidationFailed(format!(
                "Subject policy validation failed: Unknown attribute '{}'",
                attr_label
            ))
        })?;

        // Find the attribute in the subject RDN sequence
        let mut found = false;
        let mut actual_value: Option<String> = None;

        for rdn in subject.iter() {
            for attr in rdn.iter() {
                if attr.attr_type().to_id_string() == oid {
                    found = true;
                    if let Ok(value) = attr.attr_value().as_str() {
                        actual_value = Some(value.to_string());
                        if value == expected_value {
                            // Exact match found, continue to next expected attribute
                            break;
                        }
                    }
                }
            }
            if found
                && actual_value
                    .as_ref()
                    .map(|v| v == expected_value)
                    .unwrap_or(false)
            {
                break;
            }
        }

        if !found {
            return Err(DidX509Error::PolicyValidationFailed(
                format!("Subject policy validation failed: Required attribute '{}' not found in leaf certificate subject", attr_label)
            ));
        }

        if let Some(actual) = actual_value {
            if actual != *expected_value {
                return Err(DidX509Error::PolicyValidationFailed(
                    format!("Subject policy validation failed: Attribute '{}' value mismatch (expected '{}', got '{}')", 
                        attr_label, expected_value, actual)
                ));
            }
        } else {
            return Err(DidX509Error::PolicyValidationFailed(format!(
                "Subject policy validation failed: Attribute '{}' value could not be parsed",
                attr_label
            )));
        }
    }

    Ok(())
}

/// Validate Subject Alternative Name (SAN) policy
pub fn validate_san(
    cert: &X509Certificate,
    san_type: &SanType,
    expected_value: &str,
) -> Result<(), DidX509Error> {
    let sans = san_parser::parse_sans_from_certificate(cert);

    if sans.is_empty() {
        return Err(DidX509Error::PolicyValidationFailed(
            "SAN policy validation failed: Leaf certificate has no Subject Alternative Names"
                .into(),
        ));
    }

    // Check that the expected SAN type+value exists
    let found = sans
        .iter()
        .any(|san| &san.san_type == san_type && san.value == expected_value);

    if !found {
        return Err(DidX509Error::PolicyValidationFailed(format!(
            "SAN policy validation failed: Required SAN '{}:{}' not found in leaf certificate",
            san_type.as_str(),
            expected_value
        )));
    }

    Ok(())
}

/// Validate Fulcio issuer policy
pub fn validate_fulcio_issuer(
    cert: &X509Certificate,
    expected_issuer: &str,
) -> Result<(), DidX509Error> {
    let fulcio_issuer = x509_extensions::extract_fulcio_issuer(cert);

    if fulcio_issuer.is_none() {
        return Err(DidX509Error::PolicyValidationFailed(
            "Fulcio issuer policy validation failed: Leaf certificate has no Fulcio issuer extension".into()
        ));
    }

    let actual_issuer = fulcio_issuer.unwrap();

    // The expected_issuer might not have the https:// prefix, so add it if needed
    let expected_url = if expected_issuer.starts_with("https://") {
        expected_issuer.to_string()
    } else {
        format!("https://{}", expected_issuer)
    };

    if actual_issuer != expected_url {
        return Err(DidX509Error::PolicyValidationFailed(format!(
            "Fulcio issuer policy validation failed: Expected '{}', got '{}'",
            expected_url, actual_issuer
        )));
    }

    Ok(())
}
