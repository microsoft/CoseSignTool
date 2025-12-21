// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use minicbor::data::Tag;
use minicbor::data::Type;
use minicbor::{Decoder, Encoder};

use crate::header_map::{decode_header_map_from_cbor, decode_header_map_from_decoder, CoseHeaderMap};

pub const COSE_SIGN1_TAG: u64 = 18;
pub const SIG_STRUCTURE_CONTEXT_SIGNATURE1: &str = "Signature1";

#[derive(Debug, Clone)]
pub struct SigStructureView<'a> {
    pub context: &'static str,
    pub body_protected: &'a [u8],
    pub external_aad: &'a [u8],
    pub payload: Option<&'a [u8]>,
}

#[derive(Debug, Clone, Default)]
pub struct ParsedCoseSign1 {
    pub protected_headers: CoseHeaderMap,
    pub unprotected_headers: CoseHeaderMap,
    pub payload: Option<Vec<u8>>, // None => detached payload
    pub signature: Vec<u8>,
}

impl ParsedCoseSign1 {
    pub fn signature1_sig_structure_view(&self) -> SigStructureView<'_> {
        SigStructureView {
            context: SIG_STRUCTURE_CONTEXT_SIGNATURE1,
            body_protected: self.protected_headers.encoded_map_cbor(),
            external_aad: &[],
            payload: self.payload.as_deref(),
        }
    }
}

pub fn parse_cose_sign1(input: &[u8]) -> Result<ParsedCoseSign1, String> {
    if input.is_empty() {
        return Err("empty input".to_string());
    }

    let mut dec = Decoder::new(input);

    // Optional COSE_Sign1 tag (18)
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
    let protected_bstr = dec
        .bytes()
        .map_err(|e| format!("failed to read protected headers (bstr): {e}"))?
        .to_vec();

    let protected_map = decode_header_map_from_cbor(&protected_bstr)
        .map_err(|e| if e.is_empty() { "failed to parse protected headers".to_string() } else { e })?;

    // unprotected headers (map)
    if !matches!(dec.datatype().map_err(|e| e.to_string())?, Type::Map) {
        return Err("unprotected headers are not a map".to_string());
    }

    let unprotected_map = decode_header_map_from_decoder(&mut dec)
        .map_err(|e| if e.is_empty() { "failed to parse unprotected headers map".to_string() } else { e })?;

    // payload (bstr or null)
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

    let mut protected_headers = CoseHeaderMap::default();
    protected_headers.set_encoded_map_cbor(protected_bstr);
    protected_headers.set_map(protected_map);

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

pub fn encode_signature1_sig_structure(
    msg: &ParsedCoseSign1,
    external_payload: Option<&[u8]>,
) -> Result<Vec<u8>, String> {
    let payload = match (&msg.payload, external_payload) {
        (Some(p), _) => p.as_slice(),
        (None, Some(ext)) => ext,
        (None, None) => return Err("detached payload requires external payload bytes".to_string()),
    };

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
