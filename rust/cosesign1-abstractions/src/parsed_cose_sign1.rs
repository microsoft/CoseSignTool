// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Parsed COSE_Sign1 message types.

use crate::header_map::CoseHeaderMap;

/// Standard CBOR tag number used for COSE_Sign1.
pub const COSE_SIGN1_TAG: u64 = 18;

/// Context string for COSE Sig_structure for COSE_Sign1.
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
    /// Embedded payload bytes; `None` represents detached payload (`null`).
    pub payload: Option<Vec<u8>>,
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
