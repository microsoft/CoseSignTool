// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! PEM format certificate loading with inline parser.

use crate::certificate::Certificate;
use crate::error::CertLocalError;
use std::path::Path;
use x509_parser::prelude::*;

/// Loads a certificate from a PEM-encoded file.
///
/// The first certificate in the file is the leaf certificate.
/// Subsequent certificates are treated as the chain.
///
/// # Arguments
///
/// * `path` - Path to the PEM-encoded certificate file
///
/// # Errors
///
/// Returns `CertLocalError::IoError` if file cannot be read.
/// Returns `CertLocalError::LoadFailed` if PEM parsing fails.
pub fn load_cert_from_pem<P: AsRef<Path>>(path: P) -> Result<Certificate, CertLocalError> {
    let content = std::fs::read_to_string(path.as_ref())
        .map_err(|e| CertLocalError::IoError(e.to_string()))?;
    load_cert_from_pem_bytes(content.as_bytes())
}

/// Loads a certificate from PEM-encoded bytes.
///
/// The first certificate in the file is the leaf certificate.
/// Subsequent certificates are treated as the chain.
/// If a private key block is present, it is associated with the certificate.
///
/// # Arguments
///
/// * `bytes` - PEM-encoded certificate and optional private key bytes
///
/// # Errors
///
/// Returns `CertLocalError::LoadFailed` if PEM parsing fails.
pub fn load_cert_from_pem_bytes(bytes: &[u8]) -> Result<Certificate, CertLocalError> {
    let content = std::str::from_utf8(bytes)
        .map_err(|e| CertLocalError::LoadFailed(format!("invalid UTF-8 in PEM: {}", e)))?;

    let blocks = parse_pem(content)?;

    if blocks.is_empty() {
        return Err(CertLocalError::LoadFailed(
            "no valid PEM blocks found".into(),
        ));
    }

    let mut cert_der: Option<Vec<u8>> = None;
    let mut key_der: Option<Vec<u8>> = None;
    let mut chain: Vec<Vec<u8>> = Vec::new();

    for block in blocks {
        match block.label.as_str() {
            "CERTIFICATE" => {
                if cert_der.is_none() {
                    cert_der = Some(block.data);
                } else {
                    chain.push(block.data);
                }
            }
            "PRIVATE KEY" | "EC PRIVATE KEY" | "RSA PRIVATE KEY" => {
                if key_der.is_none() {
                    key_der = Some(block.data);
                }
            }
            _ => {}
        }
    }

    let cert_der =
        cert_der.ok_or_else(|| CertLocalError::LoadFailed("no certificate found in PEM".into()))?;

    X509Certificate::from_der(&cert_der)
        .map_err(|e| CertLocalError::LoadFailed(format!("invalid certificate in PEM: {}", e)))?;

    let mut cert = match key_der {
        Some(key) => Certificate::with_private_key(cert_der, key),
        None => Certificate::new(cert_der),
    };

    if !chain.is_empty() {
        cert = cert.with_chain(chain);
    }

    Ok(cert)
}

struct PemBlock {
    label: String,
    data: Vec<u8>,
}

fn parse_pem(content: &str) -> Result<Vec<PemBlock>, CertLocalError> {
    let mut blocks = Vec::new();
    let lines: Vec<&str> = content.lines().collect();
    let mut i = 0;

    while i < lines.len() {
        let line = lines[i].trim();

        if line.starts_with("-----BEGIN ") && line.ends_with("-----") {
            let label = line
                .strip_prefix("-----BEGIN ")
                .and_then(|s| s.strip_suffix("-----"))
                .ok_or_else(|| CertLocalError::LoadFailed("invalid PEM header".into()))?
                .trim()
                .to_string();

            let end_marker = format!("-----END {}-----", label);
            let mut base64_content = String::new();
            i += 1;

            while i < lines.len() {
                let data_line = lines[i].trim();
                if data_line == end_marker {
                    break;
                }
                if !data_line.is_empty() && !data_line.starts_with("-----") {
                    base64_content.push_str(data_line);
                }
                i += 1;
            }

            if i >= lines.len() || lines[i].trim() != end_marker {
                return Err(CertLocalError::LoadFailed(format!(
                    "missing end marker: {}",
                    end_marker
                )));
            }

            let data = base64_decode(&base64_content)
                .map_err(|e| CertLocalError::LoadFailed(format!("base64 decode failed: {}", e)))?;

            blocks.push(PemBlock { label, data });
        }

        i += 1;
    }

    Ok(blocks)
}

fn base64_decode(input: &str) -> Result<Vec<u8>, String> {
    const BASE64_TABLE: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut decode_table = [255u8; 256];

    for (i, &byte) in BASE64_TABLE.iter().enumerate() {
        decode_table[byte as usize] = i as u8;
    }
    decode_table[b'=' as usize] = 0;

    let input: Vec<u8> = input.bytes().filter(|b| !b.is_ascii_whitespace()).collect();
    let mut output = Vec::with_capacity((input.len() * 3) / 4);
    let mut buf = 0u32;
    let mut bits = 0;

    for &byte in &input {
        if byte == b'=' {
            break;
        }

        let value = decode_table[byte as usize];
        if value == 255 {
            return Err(format!("invalid base64 character: {}", byte as char));
        }

        buf = (buf << 6) | value as u32;
        bits += 6;

        if bits >= 8 {
            bits -= 8;
            output.push((buf >> bits) as u8);
            buf &= (1 << bits) - 1;
        }
    }

    Ok(output)
}
