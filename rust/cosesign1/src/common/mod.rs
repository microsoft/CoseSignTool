// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Common COSE_Sign1 parsing and encoding helpers.

pub mod cose_sign1;
pub mod header_map;

pub use cosesign1_abstractions::{
    CoseHeaderMap, HeaderKey, HeaderValue, ParsedCoseSign1, SigStructureView, COSE_SIGN1_TAG,
    SIG_STRUCTURE_CONTEXT_SIGNATURE1,
};

pub use cose_sign1::{
    encode_signature1_sig_structure,
    parse_cose_sign1,
    parse_cose_sign1_from_reader,
    parse_cose_sign1_from_reader_with_max_len,
};
