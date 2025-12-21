// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! COSE_Sign1 parsing and Sig_structure encoding.
//!
//! COSE_Sign1 is defined (originally) in RFC 8152 and updated in RFC 9052.
//! At a high level, the structure is:
//!
//! ```text
//! COSE_Sign1 = [ protected : bstr,
//!               unprotected : map,
//!               payload : bstr / null,
//!               signature : bstr ]
//! ```
//!
//! This module focuses on:
//! - Robust parsing with clear error messages.
//! - Strict handling of unsupported CBOR features (e.g., indefinite-length items).
//! - Constructing the `Sig_structure` bytes for signature verification.

use minicbor::data::Tag;
use minicbor::data::Type;
use minicbor::{Decoder, Encoder};

use crate::header_map::{decode_header_map_from_cbor, decode_header_map_from_decoder, CoseHeaderMap};

/// Standard CBOR tag number used for COSE_Sign1.
pub const COSE_SIGN1_TAG: u64 = 18;

/// Context string for COSE Sig_structure for COSE_Sign1.
pub const SIG_STRUCTURE_CONTEXT_SIGNATURE1: &str = "Signature1";

#[derive(Debug, Clone)]
pub struct SigStructureView<'a> {
    /// Context string (always "Signature1" for COSE_Sign1).
    pub context: &'static str,
    /// The protected headers bstr bytes (as it appears on the wire).
    pub body_protected: &'a [u8],
    /// External AAD (not used in this port; always empty).
    pub external_aad: &'a [u8],
    /// Payload bytes, if embedded.
    pub payload: Option<&'a [u8]>,
}

#[derive(Debug, Clone, Default)]
pub struct ParsedCoseSign1 {
    /// Decoded protected header map.
    pub protected_headers: CoseHeaderMap,
    /// Decoded unprotected header map.
    pub unprotected_headers: CoseHeaderMap,
    /// Embedded payload bytes.
    ///
    /// `None` represents a detached payload (`null` in the COSE_Sign1 array).
    pub payload: Option<Vec<u8>>,
    /// Signature bytes from the COSE_Sign1 structure.
    pub signature: Vec<u8>,
}

impl ParsedCoseSign1 {
    /// Produce a lightweight view of the COSE Sig_structure components.
    ///
    /// This is a convenience used by tests and callers who need to reason about
    /// which fields feed into signature verification.
    pub fn signature1_sig_structure_view(&self) -> SigStructureView<'_> {
        SigStructureView {
            context: SIG_STRUCTURE_CONTEXT_SIGNATURE1,
            body_protected: self.protected_headers.encoded_map_cbor(),
            external_aad: &[],
            payload: self.payload.as_deref(),
        }
    }
}

/// Parse a COSE_Sign1 structure from its CBOR encoding.
///
/// This parser is deliberately strict:
/// - Rejects empty input.
/// - Accepts an optional COSE_Sign1 tag (18), but rejects any other tag.
/// - Requires the top-level array length to be exactly 4.
/// - Rejects indefinite-length arrays/maps.
/// - Rejects trailing bytes.
pub fn parse_cose_sign1(input: &[u8]) -> Result<ParsedCoseSign1, String> {
    if input.is_empty() {
        return Err("empty input".to_string());
    }

    let mut dec = Decoder::new(input);

    // COSE_Sign1 may be tagged (CBOR tag 18) or untagged.
    // If a tag is present, it must be exactly 18.
    if matches!(dec.datatype().map_err(|e| e.to_string())?, Type::Tag) {
        let tag = dec.tag().map_err(|e| format!("failed to read CBOR tag: {e}"))?;
        if tag != Tag::new(COSE_SIGN1_TAG) {
            return Err("unexpected CBOR tag (expected COSE_Sign1 tag 18 or no tag)".to_string());
        }
    }

    let len = dec
        .array()
        .map_err(|e| format!("top-level item is not an array: {e}"))?
        .ok_or_else(|| "indefinite-length arrays are not supported".to_string())?;

    if len != 4 {
        return Err("array length was not 4".to_string());
    }

    // protected headers (bstr)
    // This is a CBOR byte string that itself encodes a CBOR map.
    let protected_bstr = dec
        .bytes()
        .map_err(|e| format!("failed to read protected headers (bstr): {e}"))?
        .to_vec();

    let protected_map = decode_header_map_from_cbor(&protected_bstr)
        .map_err(|e| if e.is_empty() { "failed to parse protected headers".to_string() } else { e })?;

    // unprotected headers (map)
    // This is an inline CBOR map (not wrapped in a bstr).
    if !matches!(dec.datatype().map_err(|e| e.to_string())?, Type::Map) {
        return Err("unprotected headers are not a map".to_string());
    }

    let unprotected_map = decode_header_map_from_decoder(&mut dec)
        .map_err(|e| if e.is_empty() { "failed to parse unprotected headers map".to_string() } else { e })?;

    // payload (bstr or null)
    // COSE_Sign1 uses `null` to represent a detached payload.
    let payload = match dec.datatype().map_err(|e| e.to_string())? {
        Type::Null => {
            dec.null().map_err(|e| e.to_string())?;
            None
        }
        Type::Bytes => Some(
            dec.bytes()
                .map_err(|e| format!("failed to read payload (bstr or null): {e}"))?
                .to_vec(),
        ),
        _ => return Err("failed to read payload (bstr or null)".to_string()),
    };

    // signature (bstr)
    let signature = dec
        .bytes()
        .map_err(|e| format!("failed to read signature (bstr): {e}"))?
        .to_vec();

    if dec.position() != input.len() {
        return Err("trailing bytes after COSE_Sign1".to_string());
    }

    // Preserve both:
    // - the original protected headers bytes (needed for Sig_structure)
    // - the decoded header map (needed for looking up header parameters like `alg`)
    let mut protected_headers = CoseHeaderMap::default();
    protected_headers.set_encoded_map_cbor(protected_bstr);
    protected_headers.set_map(protected_map);

    // Unprotected headers are not part of Sig_structure, so we intentionally
    // keep `encoded_map_cbor` empty for unprotected.
    let mut unprotected_headers = CoseHeaderMap::default();
    unprotected_headers.set_encoded_map_cbor(Vec::new());
    unprotected_headers.set_map(unprotected_map);

    Ok(ParsedCoseSign1 {
        protected_headers,
        unprotected_headers,
        payload,
        signature,
    })
}

/// Encode the COSE Sig_structure bytes for COSE_Sign1.
///
/// These bytes are what signature algorithms verify.
/// If the COSE_Sign1 payload is detached (`null`), callers must pass
/// `external_payload`.
pub fn encode_signature1_sig_structure(
    msg: &ParsedCoseSign1,
    external_payload: Option<&[u8]>,
) -> Result<Vec<u8>, String> {
    // Resolve which payload bytes are to be included in the Sig_structure.
    let payload = match (&msg.payload, external_payload) {
        (Some(p), _) => p.as_slice(),
        (None, Some(ext)) => ext,
        (None, None) => return Err("detached payload requires external payload bytes".to_string()),
    };

    // The Sig_structure is a CBOR array of 4 items:
    // [ context, body_protected, external_aad, payload ]
    let mut out = Vec::with_capacity(128 + msg.protected_headers.encoded_map_cbor().len() + payload.len());
    {
        let mut enc = Encoder::new(&mut out);
        enc.array(4).map_err(|e| e.to_string())?;
        enc.str(SIG_STRUCTURE_CONTEXT_SIGNATURE1).map_err(|e| e.to_string())?;
        enc.bytes(msg.protected_headers.encoded_map_cbor()).map_err(|e| e.to_string())?;
        enc.bytes(&[]).map_err(|e| e.to_string())?; // external_aad empty bstr
        enc.bytes(payload).map_err(|e| e.to_string())?;
    }
    Ok(out)
}
