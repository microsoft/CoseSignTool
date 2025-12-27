// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Integration tests for `Sig_structure` encoding.
//!
//! These tests cover `encode_signature1_sig_structure` behavior, especially for
//! detached payloads.

mod common;

use common::*;

/// Detached payloads require an external payload in order to build Sig_structure.
#[test]
fn signature1_sig_structure_requires_external_payload_for_detached_messages() {
    let protected = encode_protected_header_bytes(&[(1, TestCborValue::Int(-7))]);
    let msg = encode_cose_sign1(false, &protected, &[], None, &[0u8; 64]);
    let parsed = cosesign1::parse_cose_sign1(&msg).unwrap();

    assert!(cosesign1::encode_signature1_sig_structure(&parsed, None).is_err());
}
