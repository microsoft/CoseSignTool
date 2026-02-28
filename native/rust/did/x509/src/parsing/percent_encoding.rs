// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use crate::error::DidX509Error;

/// Percent-encodes a string according to DID:x509 specification.
/// Only ALPHA, DIGIT, '-', '.', '_' are allowed unencoded.
/// Note: Tilde (~) is NOT allowed unencoded per DID:x509 spec (differs from RFC 3986).
pub fn percent_encode(input: &str) -> String {
    if input.is_empty() {
        return String::new();
    }

    let mut encoded = String::with_capacity(input.len() * 2);

    for ch in input.chars() {
        if is_did_x509_allowed_character(ch) {
            encoded.push(ch);
        } else {
            // Encode as UTF-8 bytes
            let mut buf = [0u8; 4];
            let bytes = ch.encode_utf8(&mut buf).as_bytes();
            for &byte in bytes {
                encoded.push('%');
                encoded.push_str(&format!("{:02X}", byte));
            }
        }
    }

    encoded
}

/// Percent-decodes a string.
pub fn percent_decode(input: &str) -> Result<String, DidX509Error> {
    if input.is_empty() {
        return Ok(String::new());
    }

    if !input.contains('%') {
        return Ok(input.to_string());
    }

    let mut bytes = Vec::new();
    let mut result = String::with_capacity(input.len());
    let chars: Vec<char> = input.chars().collect();
    let mut i = 0;

    while i < chars.len() {
        let ch = chars[i];

        if ch == '%' && i + 2 < chars.len() {
            let hex1 = chars[i + 1];
            let hex2 = chars[i + 2];

            if is_hex_digit(hex1) && is_hex_digit(hex2) {
                let hex_str = format!("{}{}", hex1, hex2);
                let byte = u8::from_str_radix(&hex_str, 16)
                    .map_err(|_| DidX509Error::PercentDecodingError(format!("Invalid hex: {}", hex_str)))?;
                bytes.push(byte);
                i += 3;
                continue;
            }
        }

        // Flush accumulated bytes if any
        if !bytes.is_empty() {
            let decoded = String::from_utf8(bytes.clone())
                .map_err(|e| DidX509Error::PercentDecodingError(format!("Invalid UTF-8: {}", e)))?;
            result.push_str(&decoded);
            bytes.clear();
        }

        // Append non-encoded character
        result.push(ch);
        i += 1;
    }

    // Flush remaining bytes
    if !bytes.is_empty() {
        let decoded = String::from_utf8(bytes)
            .map_err(|e| DidX509Error::PercentDecodingError(format!("Invalid UTF-8: {}", e)))?;
        result.push_str(&decoded);
    }

    Ok(result)
}

/// Checks if a character is allowed unencoded in DID:x509.
/// Per spec: ALPHA / DIGIT / "-" / "." / "_"
pub fn is_did_x509_allowed_character(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '-' || c == '.' || c == '_'
}

fn is_hex_digit(c: char) -> bool {
    c.is_ascii_hexdigit()
}
