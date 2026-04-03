// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! RFC 9290 CBOR Problem Details parser.
//!
//! Parses structured error bodies returned by the Azure Code Transparency Service
//! with Content-Type `application/concise-problem-details+cbor`.

use cbor_primitives::CborDecoder;
use std::collections::HashMap;
use std::fmt;

/// Parsed CBOR problem details per RFC 9290.
///
/// Standard CBOR integer keys:
/// - `-1` → type (URI reference)
/// - `-2` → title (human-readable summary)
/// - `-3` → status (HTTP status code)
/// - `-4` → detail (human-readable explanation)
/// - `-5` → instance (URI reference for the occurrence)
///
/// String keys (`"type"`, `"title"`, etc.) are also accepted for interoperability.
#[derive(Debug, Clone, Default)]
pub struct CborProblemDetails {
    /// Problem type URI reference (CBOR key: -1 or "type").
    pub problem_type: Option<String>,
    /// Short human-readable summary (CBOR key: -2 or "title").
    pub title: Option<String>,
    /// HTTP status code (CBOR key: -3 or "status").
    pub status: Option<i64>,
    /// Human-readable explanation (CBOR key: -4 or "detail").
    pub detail: Option<String>,
    /// URI reference for the specific occurrence (CBOR key: -5 or "instance").
    pub instance: Option<String>,
    /// Additional extension fields not covered by the standard keys.
    pub extensions: HashMap<String, String>,
}

impl CborProblemDetails {
    /// Attempts to parse CBOR problem details from a byte slice.
    ///
    /// Returns `None` if the bytes are empty or cannot be parsed as a CBOR map.
    pub fn try_parse(cbor_bytes: &[u8]) -> Option<Self> {
        if cbor_bytes.is_empty() {
            return None;
        }
        Self::parse_inner(cbor_bytes)
    }

    fn parse_inner(cbor_bytes: &[u8]) -> Option<Self> {
        let mut d = cose_sign1_primitives::provider::decoder(cbor_bytes);
        let map_len = d.decode_map_len().ok()?;
        let count = map_len.unwrap_or(0);

        let mut details = CborProblemDetails::default();

        for _ in 0..count {
            // Peek at the key type to decide how to decode it
            let key_type = d.peek_type().ok();
            match key_type {
                Some(cbor_primitives::CborType::NegativeInt)
                | Some(cbor_primitives::CborType::UnsignedInt) => {
                    let neg_key = d.decode_i64().ok()?;
                    match neg_key {
                        -1 => details.problem_type = d.decode_tstr().ok().map(|s| s.to_string()),
                        -2 => details.title = d.decode_tstr().ok().map(|s| s.to_string()),
                        -3 => details.status = d.decode_i64().ok(),
                        -4 => details.detail = d.decode_tstr().ok().map(|s| s.to_string()),
                        -5 => details.instance = d.decode_tstr().ok().map(|s| s.to_string()),
                        _ => {
                            let val = d
                                .decode_tstr()
                                .ok()
                                .map(|s| s.to_string())
                                .unwrap_or_default();
                            details.extensions.insert(format!("key_{}", neg_key), val);
                        }
                    }
                }
                Some(cbor_primitives::CborType::TextString) => {
                    let str_key = match d.decode_tstr().ok() {
                        Some(s) => s.to_string(),
                        None => break,
                    };
                    let str_key_lower = str_key.to_lowercase();
                    match str_key_lower.as_str() {
                        "type" => {
                            details.problem_type = d.decode_tstr().ok().map(|s| s.to_string())
                        }
                        "title" => details.title = d.decode_tstr().ok().map(|s| s.to_string()),
                        "status" => details.status = d.decode_i64().ok(),
                        "detail" => details.detail = d.decode_tstr().ok().map(|s| s.to_string()),
                        "instance" => {
                            details.instance = d.decode_tstr().ok().map(|s| s.to_string())
                        }
                        _ => {
                            let val = d.decode_tstr().ok().map(|s| s.to_string());
                            if let Some(v) = val {
                                details.extensions.insert(str_key, v);
                            }
                        }
                    }
                }
                _ => break,
            }
        }

        Some(details)
    }
}

impl fmt::Display for CborProblemDetails {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut parts = Vec::new();
        if let Some(ref title) = self.title {
            parts.push(format!("Title: {}", title));
        }
        if let Some(status) = self.status {
            parts.push(format!("Status: {}", status));
        }
        if let Some(ref detail) = self.detail {
            parts.push(format!("Detail: {}", detail));
        }
        if let Some(ref t) = self.problem_type {
            parts.push(format!("Type: {}", t));
        }
        if let Some(ref inst) = self.instance {
            parts.push(format!("Instance: {}", inst));
        }
        if parts.is_empty() {
            write!(f, "No details available")
        } else {
            write!(f, "{}", parts.join(", "))
        }
    }
}
