// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use cosesigntool_plugin_api::auth::{auth_key_from_hex, generate_auth_key, AuthError, AUTH_KEY_LENGTH};

#[test]
fn generate_auth_key_returns_a_non_zero_32_byte_key() {
    let key = generate_auth_key();

    assert_eq!(key.len(), AUTH_KEY_LENGTH);
    assert!(key.iter().any(|byte| *byte != 0));
}

#[test]
fn auth_key_from_hex_accepts_uppercase_hex() {
    let decoded = auth_key_from_hex(
        "00112233445566778899AABBCCDDEEFF102132435465768798A9BACBDCEDFE0F",
    )
    .expect("uppercase hex should decode");

    assert_eq!(decoded[0], 0x00);
    assert_eq!(decoded[10], 0xaa);
    assert_eq!(decoded[31], 0x0f);
}

#[test]
fn auth_key_from_hex_rejects_odd_length_input() {
    let error = auth_key_from_hex(
        "00112233445566778899aabbccddeeff102132435465768798a9bacbdcedfe0",
    )
    .expect_err("odd-length hex should fail");

    match error {
        AuthError::InvalidHexLength { expected, actual } => {
            assert_eq!(expected, AUTH_KEY_LENGTH * 2);
            assert_eq!(actual, (AUTH_KEY_LENGTH * 2) - 1);
        }
        other => panic!("unexpected error: {other:?}"),
    }
}

#[test]
fn auth_key_from_hex_rejects_wrong_length_input() {
    let error = auth_key_from_hex("0011").expect_err("wrong-length hex should fail");

    match error {
        AuthError::InvalidHexLength { expected, actual } => {
            assert_eq!(expected, AUTH_KEY_LENGTH * 2);
            assert_eq!(actual, 4);
        }
        other => panic!("unexpected error: {other:?}"),
    }
}