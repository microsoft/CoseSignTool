// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use cosesign1_abstractions::{HeaderValue, ParsedCoseSign1};

/// Extracts the COSE `x5c` header (label 33) as DER certificate bytes.
///
/// COSE (and RFC 9360 / X.509 COSE headers) allows `x5c` (aka `x5chain`) to be:
/// - a single CBOR bstr when only one certificate is present
/// - an array of CBOR bstr values when multiple certificates are present
///
/// Returns:
/// - `None` if the header is absent
/// - `Some(Ok(certs))` if present and well-formed
/// - `Some(Err(msg))` if present but malformed
pub(crate) fn extract_x5c_certs_der(parsed: &ParsedCoseSign1) -> Option<Result<Vec<Vec<u8>>, String>> {
    // COSE allows headers to be in protected or unprotected maps.
    if let Some(x5c) = parsed
        .protected_headers
        .get_array(33)
        .or_else(|| parsed.unprotected_headers.get_array(33))
    {
        let mut certs_der: Vec<Vec<u8>> = Vec::new();
        for v in x5c {
            match v {
                HeaderValue::Bytes(b) => certs_der.push(b.clone()),
                _ => {
                    return Some(Err("x5c must be a bstr or an array of bstr".to_string()));
                }
            }
        }
        return Some(Ok(certs_der));
    }

    if let Some(x5c_single) = parsed
        .protected_headers
        .get_bytes(33)
        .or_else(|| parsed.unprotected_headers.get_bytes(33))
    {
        if x5c_single.is_empty() {
            return Some(Err("x5c leaf certificate bytes were empty".to_string()));
        }

        return Some(Ok(vec![x5c_single.to_vec()]));
    }

    None
}
