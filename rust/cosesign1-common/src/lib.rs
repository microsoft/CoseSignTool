// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

pub mod cose_sign1;
pub mod header_map;

pub use cose_sign1::{encode_signature1_sig_structure, parse_cose_sign1, ParsedCoseSign1, SigStructureView};
pub use header_map::{CoseHeaderMap, HeaderKey, HeaderValue};
