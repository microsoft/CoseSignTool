// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use tinycbor::Decoder;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoseSign1<'a> {
    pub protected_header: &'a [u8],
    pub unprotected_header: tinycbor::Any<'a>,
    pub payload: Option<&'a [u8]>,
    pub signature: &'a [u8],
}

#[derive(Debug, thiserror::Error)]
pub enum CoseDecodeError {
    #[error("CBOR decode failed: {0}")]
    Cbor(String),

    #[error("COSE_Sign1 must be an array(4)")]
    NotSign1,
}

impl CoseDecodeError {
    /// Helper to normalize CBOR/COSE decoding failures into `CoseDecodeError::Cbor`.
    ///
    /// This is used to avoid leaking the underlying error type across this crate boundary.
    fn cbor<E: std::fmt::Display>(e: E) -> Self {
        Self::Cbor(e.to_string())
    }
}

impl<'a> CoseSign1<'a> {
    /// Decode a COSE_Sign1 message from CBOR.
    ///
    /// Accepts (and strips) an optional leading CBOR tag 18, which some encoders wrap around
    /// the COSE_Sign1 structure.
    pub fn from_cbor(cbor: &'a [u8]) -> Result<Self, CoseDecodeError> {
        // Some encoders wrap COSE_Sign1 in the standard CBOR tag 18.
        // Accept (and strip) an initial tag(18) if present.
        let cbor = match decode_cose_sign1_tag_prefix(cbor) {
            Ok(Some(rest)) => rest,
            Ok(None) => cbor,
            Err(e) => return Err(CoseDecodeError::Cbor(e)),
        };

        let mut d = Decoder(cbor);
        // COSE_Sign1 = [ protected : bstr, unprotected : map, payload : bstr / nil, signature : bstr ]
        // We accept both definite-length bstr and store the raw bytes slice as returned by tinycbor.
        // For unprotected header we keep original encoding using Any.
        let mut array = d.array_visitor().map_err(CoseDecodeError::cbor)?;

        let protected_header = array
            .visit::<&[u8]>()
            .ok_or(CoseDecodeError::NotSign1)?
            .map_err(CoseDecodeError::cbor)?;

        let unprotected_header = array
            .visit::<tinycbor::Any<'a>>()
            .ok_or(CoseDecodeError::NotSign1)?
            .map_err(CoseDecodeError::cbor)?;

        let payload = array
            .visit::<Option<&[u8]>>()
            .ok_or(CoseDecodeError::NotSign1)?
            .map_err(CoseDecodeError::cbor)?;

        let signature = array
            .visit::<&[u8]>()
            .ok_or(CoseDecodeError::NotSign1)?
            .map_err(CoseDecodeError::cbor)?;

        // Ensure there are no extra array items.
        if array.visit::<tinycbor::Any<'a>>().is_some() {
            return Err(CoseDecodeError::NotSign1);
        }

        Ok(Self {
            protected_header,
            unprotected_header,
            payload,
            signature,
        })
    }
}

/// If `input` begins with CBOR tag 18, returns a slice starting after the tag.
///
/// Returns:
/// - `Ok(Some(rest))` if tag 18 is present and decoded successfully.
/// - `Ok(None)` if no CBOR tag is present (caller should treat `input` as the message).
/// - `Err(...)` if a tag is present but is not tag 18, or the tag encoding is invalid.
fn decode_cose_sign1_tag_prefix(input: &[u8]) -> Result<Option<&[u8]>, String> {
    let first = match input.first() {
        Some(b) => *b,
        None => return Ok(None),
    };

    let major = first >> 5;
    let ai = first & 0x1f;
    if major != 6 {
        return Ok(None);
    }

    let (tag, used) = decode_cbor_uint_value(ai, &input[1..])
        .ok_or_else(|| "invalid CBOR tag encoding".to_string())?;
    let consumed = 1 + used;
    if tag != 18 {
        return Err(format!(
            "unexpected CBOR tag {tag} (expected 18 for COSE_Sign1)"
        ));
    }

    Ok(input.get(consumed..))
}

/// Decode the unsigned integer value for a CBOR additional-information (AI) field.
///
/// The returned tuple is `(value, bytes_consumed_from_rest)`.
fn decode_cbor_uint_value(ai: u8, rest: &[u8]) -> Option<(u64, usize)> {
    match ai {
        0..=23 => Some((ai as u64, 0)),
        24 => Some((u64::from(*rest.first()?), 1)),
        25 => {
            let b = rest.get(0..2)?;
            Some((u16::from_be_bytes([b[0], b[1]]) as u64, 2))
        }
        26 => {
            let b = rest.get(0..4)?;
            Some((u32::from_be_bytes([b[0], b[1], b[2], b[3]]) as u64, 4))
        }
        27 => {
            let b = rest.get(0..8)?;
            Some((
                u64::from_be_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]),
                8,
            ))
        }
        _ => None,
    }
}
