// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! ECDSA signature format conversion between DER and fixed-length (COSE).
//!
//! OpenSSL produces ECDSA signatures in DER format, but COSE requires fixed-length
//! concatenated (r || s) format. This module provides conversion utilities.

/// Parses a DER length field, handling both short and long form.
///
/// Returns (length_value, bytes_consumed).
fn parse_der_length(data: &[u8]) -> Result<(usize, usize), String> {
    if data.is_empty() {
        return Err("DER length field is empty".to_string());
    }

    let first = data[0];
    if first < 0x80 {
        // Short form: length is in the first byte
        Ok((first as usize, 1))
    } else {
        // Long form: first byte & 0x7F gives number of length bytes
        let num_len_bytes = (first & 0x7F) as usize;
        if num_len_bytes == 0 || num_len_bytes > 4 {
            return Err("Invalid DER long-form length".to_string());
        }

        if data.len() < 1 + num_len_bytes {
            return Err("DER length field truncated".to_string());
        }

        let mut length: usize = 0;
        for i in 0..num_len_bytes {
            length = (length << 8) | (data[1 + i] as usize);
        }

        Ok((length, 1 + num_len_bytes))
    }
}

/// Converts an ECDSA signature from DER format to fixed-length COSE format (r || s).
///
/// # Arguments
///
/// * `der_sig` - DER-encoded ECDSA signature
/// * `expected_len` - Expected byte length of the fixed-size output (e.g., 64 for ES256)
///
/// # Returns
///
/// The fixed-length signature bytes (r || s concatenated).
pub fn der_to_fixed(der_sig: &[u8], expected_len: usize) -> Result<Vec<u8>, String> {
    // DER SEQUENCE structure:
    // 0x30 <total_len> 0x02 <r_len> <r_bytes> 0x02 <s_len> <s_bytes>

    if der_sig.len() < 8 {
        return Err("DER signature too short".to_string());
    }

    if der_sig[0] != 0x30 {
        return Err("Invalid DER signature: missing SEQUENCE tag".to_string());
    }

    // Parse DER length (handles both short and long form)
    let (total_len, mut pos) = parse_der_length(&der_sig[1..])?;
    pos += 1; // Account for the SEQUENCE tag

    if der_sig.len() < total_len + pos {
        return Err("DER signature length mismatch".to_string());
    }

    // Parse r
    if pos >= der_sig.len() || der_sig[pos] != 0x02 {
        return Err("Invalid DER signature: missing INTEGER tag for r".to_string());
    }
    pos += 1;

    let (r_len, len_bytes) = parse_der_length(&der_sig[pos..])?;
    pos += len_bytes;

    if pos + r_len > der_sig.len() {
        return Err("DER signature r value out of bounds".to_string());
    }

    let r_bytes = &der_sig[pos..pos + r_len];
    pos += r_len;

    // Parse s
    if pos >= der_sig.len() || der_sig[pos] != 0x02 {
        return Err("Invalid DER signature: missing INTEGER tag for s".to_string());
    }
    pos += 1;

    let (s_len, len_bytes) = parse_der_length(&der_sig[pos..])?;
    pos += len_bytes;

    if pos + s_len > der_sig.len() {
        return Err("DER signature s value out of bounds".to_string());
    }

    let s_bytes = &der_sig[pos..pos + s_len];

    // Convert to fixed-length format
    let component_len = expected_len / 2;
    let mut result = vec![0u8; expected_len];

    // Copy r, removing leading zeros if needed, padding on left if needed
    copy_integer_to_fixed(&mut result[0..component_len], r_bytes)?;

    // Copy s, removing leading zeros if needed, padding on left if needed
    copy_integer_to_fixed(&mut result[component_len..expected_len], s_bytes)?;

    Ok(result)
}

/// Converts an ECDSA signature from fixed-length COSE format (r || s) to DER format.
///
/// # Arguments
///
/// * `fixed_sig` - Fixed-length signature bytes (r || s concatenated)
///
/// # Returns
///
/// DER-encoded ECDSA signature.
pub fn fixed_to_der(fixed_sig: &[u8]) -> Result<Vec<u8>, String> {
    if fixed_sig.len() % 2 != 0 {
        return Err("Fixed signature length must be even".to_string());
    }

    let component_len = fixed_sig.len() / 2;
    let r_bytes = &fixed_sig[0..component_len];
    let s_bytes = &fixed_sig[component_len..];

    // Convert each component to DER INTEGER format
    let r_der = integer_to_der(r_bytes);
    let s_der = integer_to_der(s_bytes);

    // Build SEQUENCE
    let total_len = r_der.len() + s_der.len();
    let mut result = Vec::with_capacity(4 + total_len); // Extra space for possible long-form length

    result.push(0x30); // SEQUENCE tag

    // Encode length (use long form if needed)
    if total_len < 128 {
        result.push(total_len as u8);
    } else if total_len < 256 {
        result.push(0x81); // Long form: 1 byte follows
        result.push(total_len as u8);
    } else {
        result.push(0x82); // Long form: 2 bytes follow
        result.push((total_len >> 8) as u8);
        result.push(total_len as u8);
    }

    result.extend_from_slice(&r_der);
    result.extend_from_slice(&s_der);

    Ok(result)
}

/// Copies a big-endian integer to a fixed-length buffer, handling padding and leading zeros.
fn copy_integer_to_fixed(dest: &mut [u8], src: &[u8]) -> Result<(), String> {
    // Remove leading zero padding bytes (DER may add 0x00 for positive numbers)
    let trimmed_src = if src.len() > 1 && src[0] == 0x00 {
        &src[1..]
    } else {
        src
    };

    if trimmed_src.len() > dest.len() {
        return Err(format!(
            "Integer value too large for fixed field: {} bytes for {} byte field",
            trimmed_src.len(),
            dest.len()
        ));
    }

    // Pad on the left with zeros if needed
    let padding = dest.len() - trimmed_src.len();
    dest[0..padding].fill(0);
    dest[padding..].copy_from_slice(trimmed_src);

    Ok(())
}

/// Converts a big-endian integer to DER INTEGER encoding.
fn integer_to_der(bytes: &[u8]) -> Vec<u8> {
    // Handle empty input
    if bytes.is_empty() {
        return vec![0x02, 0x01, 0x00]; // DER INTEGER for 0
    }

    // Remove leading zeros (but keep at least one byte)
    let mut start: usize = 0;
    while start < bytes.len() - 1 && bytes[start] == 0 {
        start += 1;
    }
    let trimmed = &bytes[start..];

    // Add leading 0x00 if high bit is set (to keep it positive)
    let needs_padding = !trimmed.is_empty() && (trimmed[0] & 0x80) != 0;
    let content_len = trimmed.len() + if needs_padding { 1 } else { 0 };

    let mut result = Vec::with_capacity(4 + content_len);
    result.push(0x02); // INTEGER tag

    // Encode length (use long form if needed)
    if content_len < 128 {
        result.push(content_len as u8);
    } else if content_len < 256 {
        result.push(0x81); // Long form: 1 byte follows
        result.push(content_len as u8);
    } else {
        result.push(0x82); // Long form: 2 bytes follow
        result.push((content_len >> 8) as u8);
        result.push(content_len as u8);
    }

    if needs_padding {
        result.push(0x00);
    }

    result.extend_from_slice(trimmed);
    result
}
