// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use std::sync::{Mutex, OnceLock};

use cosesigntool_plugin_api::auth::{
    auth_key_from_hex, auth_key_to_hex, constant_time_eq, read_and_clear_auth_key, AuthError,
    AUTH_KEY_ENV_VAR,
};

#[test]
fn auth_key_hex_roundtrips() {
    let auth_key = [
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee,
        0xff, 0x10, 0x21, 0x32, 0x43, 0x54, 0x65, 0x76, 0x87, 0x98, 0xa9, 0xba, 0xcb, 0xdc, 0xed,
        0xfe, 0x0f,
    ];

    let encoded = auth_key_to_hex(&auth_key);
    let decoded = auth_key_from_hex(encoded.as_str()).expect("hex string should decode");

    assert_eq!(
        encoded,
        "00112233445566778899aabbccddeeff102132435465768798a9bacbdcedfe0f"
    );
    assert_eq!(decoded, auth_key);
}

#[test]
fn auth_key_from_hex_rejects_invalid_character() {
    let invalid = "00112233445566778899aabbccddeeff102132435465768798a9bacbdcedfe0g";

    let error = auth_key_from_hex(invalid).expect_err("invalid hex should fail");

    match error {
        AuthError::InvalidHexCharacter { index, value } => {
            assert_eq!(index, 63);
            assert_eq!(value, 'g');
        }
        other => panic!("unexpected error: {:?}", other),
    }
}

#[test]
fn constant_time_eq_returns_expected_results() {
    let left = [0x01, 0x02, 0x03, 0x04];
    let same = [0x01, 0x02, 0x03, 0x04];
    let different = [0x01, 0x02, 0x03, 0x05];
    let shorter = [0x01, 0x02, 0x03];

    assert!(constant_time_eq(&left, &same));
    assert!(!constant_time_eq(&left, &different));
    assert!(!constant_time_eq(&left, &shorter));
}

#[test]
fn read_and_clear_auth_key_reads_then_removes_environment_variable() {
    let _guard = env_lock().lock().expect("env lock should be acquired");
    let auth_key_hex = "00112233445566778899aabbccddeeff102132435465768798a9bacbdcedfe0f";

    std::env::set_var(AUTH_KEY_ENV_VAR, auth_key_hex);

    let auth_key = read_and_clear_auth_key().expect("env auth key should decode");

    assert_eq!(auth_key_to_hex(&auth_key), auth_key_hex);
    assert!(std::env::var(AUTH_KEY_ENV_VAR).is_err());
}

fn env_lock() -> &'static Mutex<()> {
    static ENV_LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    ENV_LOCK.get_or_init(|| Mutex::new(()))
}
