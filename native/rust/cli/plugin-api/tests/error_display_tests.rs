// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Tests for error type Display implementations and conversions in plugin-api.

use cosesigntool_plugin_api::auth::{
    auth_key_from_hex, auth_key_to_hex, constant_time_eq, AuthError, AUTH_KEY_LENGTH,
};
use cosesigntool_plugin_api::client::ClientError;
use cosesigntool_plugin_api::protocol::ProtocolCodecError;
use cosesigntool_plugin_api::server::ServerError;

// ============================================================================
// AuthError Display + Error tests
// ============================================================================

#[test]
fn auth_error_display_environment_variable() {
    let err = AuthError::EnvironmentVariable("missing env var".into());
    assert_eq!(err.to_string(), "missing env var");
    assert!(std::error::Error::source(&err).is_none());
}

#[test]
fn auth_error_display_invalid_hex_length() {
    let err = AuthError::InvalidHexLength {
        expected: 64,
        actual: 32,
    };
    let msg = err.to_string();
    assert!(msg.contains("64"));
    assert!(msg.contains("32"));
    assert!(std::error::Error::source(&err).is_none());
}

#[test]
fn auth_error_display_invalid_hex_character() {
    let err = AuthError::InvalidHexCharacter {
        index: 5,
        value: 'G',
    };
    let msg = err.to_string();
    assert!(msg.contains("'G'"));
    assert!(msg.contains("index 5"));
    assert!(std::error::Error::source(&err).is_none());
}

#[test]
fn auth_error_display_io() {
    let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "test I/O error");
    let err = AuthError::Io(io_err);
    assert!(err.to_string().contains("I/O failed"));
    assert!(std::error::Error::source(&err).is_some());
}

#[test]
fn auth_error_from_io_error() {
    let io_err = std::io::Error::new(std::io::ErrorKind::Other, "test");
    let auth_err: AuthError = io_err.into();
    assert!(matches!(auth_err, AuthError::Io(_)));
}

// ============================================================================
// auth_key_to_hex / auth_key_from_hex roundtrip
// ============================================================================

#[test]
fn auth_key_hex_roundtrip() {
    let key = [0xAB; AUTH_KEY_LENGTH];
    let hex = auth_key_to_hex(&key);
    let decoded = auth_key_from_hex(&hex).unwrap();
    assert_eq!(key, decoded);
}

#[test]
fn auth_key_to_hex_all_zeros() {
    let key = [0u8; AUTH_KEY_LENGTH];
    let hex = auth_key_to_hex(&key);
    assert_eq!(hex, "0".repeat(AUTH_KEY_LENGTH * 2));
}

#[test]
fn auth_key_from_hex_rejects_invalid_char() {
    let mut hex = "0".repeat(AUTH_KEY_LENGTH * 2);
    // Replace char at position 3 with an invalid character
    let mut bytes: Vec<u8> = hex.into_bytes();
    bytes[3] = b'G';
    hex = String::from_utf8(bytes).unwrap();
    let err = auth_key_from_hex(&hex).unwrap_err();
    match err {
        AuthError::InvalidHexCharacter { index, value } => {
            assert_eq!(index, 3);
            assert_eq!(value, 'G');
        }
        other => panic!("expected InvalidHexCharacter, got: {other:?}"),
    }
}

// ============================================================================
// constant_time_eq tests
// ============================================================================

#[test]
fn constant_time_eq_equal_slices() {
    assert!(constant_time_eq(&[1, 2, 3], &[1, 2, 3]));
}

#[test]
fn constant_time_eq_different_slices() {
    assert!(!constant_time_eq(&[1, 2, 3], &[1, 2, 4]));
}

#[test]
fn constant_time_eq_different_lengths() {
    assert!(!constant_time_eq(&[1, 2], &[1, 2, 3]));
}

#[test]
fn constant_time_eq_empty_slices() {
    assert!(constant_time_eq(&[], &[]));
}

// ============================================================================
// ClientError Display + Error tests
// ============================================================================

#[test]
fn client_error_display_connection_timeout() {
    let err = ClientError::ConnectionTimeout("pipe-name".into());
    assert!(err.to_string().contains("pipe-name"));
    assert!(std::error::Error::source(&err).is_none());
}

#[test]
fn client_error_display_io() {
    let io_err = std::io::Error::new(std::io::ErrorKind::BrokenPipe, "broken");
    let err = ClientError::Io(io_err);
    assert!(err.to_string().contains("I/O failed"));
    assert!(std::error::Error::source(&err).is_some());
}

#[test]
fn client_error_display_plugin() {
    let err = ClientError::Plugin {
        method: "sign".into(),
        code: "SIGN_FAILED".into(),
        message: "key unavailable".into(),
    };
    let msg = err.to_string();
    assert!(msg.contains("sign"));
    assert!(msg.contains("SIGN_FAILED"));
    assert!(msg.contains("key unavailable"));
    assert!(std::error::Error::source(&err).is_none());
}

#[test]
fn client_error_display_unexpected_response() {
    let err = ClientError::UnexpectedResponse {
        method: "capabilities".into(),
        details: "expected plugin info".into(),
    };
    let msg = err.to_string();
    assert!(msg.contains("capabilities"));
    assert!(msg.contains("expected plugin info"));
    assert!(std::error::Error::source(&err).is_none());
}

#[test]
fn client_error_from_io_error() {
    let io_err = std::io::Error::new(std::io::ErrorKind::Other, "test");
    let client_err: ClientError = io_err.into();
    assert!(matches!(client_err, ClientError::Io(_)));
}

// ============================================================================
// ServerError Display + Error tests
// ============================================================================

#[test]
fn server_error_display_missing_argument() {
    let err = ServerError::MissingArgument("--pipe-name".into());
    assert!(err.to_string().contains("--pipe-name"));
    assert!(std::error::Error::source(&err).is_none());
}

#[test]
fn server_error_display_auth() {
    let auth_err = AuthError::EnvironmentVariable("missing".into());
    let err = ServerError::Auth(auth_err);
    assert!(err.to_string().contains("auth failed"));
    assert!(std::error::Error::source(&err).is_some());
}

#[test]
fn server_error_display_io() {
    let io_err = std::io::Error::new(std::io::ErrorKind::Other, "test");
    let err = ServerError::Io(io_err);
    assert!(err.to_string().contains("I/O failed"));
    assert!(std::error::Error::source(&err).is_some());
}

#[test]
fn server_error_display_authentication_failed() {
    let err = ServerError::AuthenticationFailed("bad key".into());
    let msg = err.to_string();
    assert!(msg.contains("authentication failed"));
    assert!(msg.contains("bad key"));
    assert!(std::error::Error::source(&err).is_none());
}

#[test]
fn server_error_from_auth_error() {
    let auth_err = AuthError::EnvironmentVariable("test".into());
    let server_err: ServerError = auth_err.into();
    assert!(matches!(server_err, ServerError::Auth(_)));
}

#[test]
fn server_error_from_io_error() {
    let io_err = std::io::Error::new(std::io::ErrorKind::Other, "test");
    let server_err: ServerError = io_err.into();
    assert!(matches!(server_err, ServerError::Io(_)));
}

// ============================================================================
// ProtocolCodecError Display tests
// ============================================================================

#[test]
fn protocol_codec_error_display_invalid_message() {
    let err = ProtocolCodecError::InvalidMessage("bad shape".into());
    assert!(err.to_string().contains("bad shape"));
}

#[test]
fn protocol_codec_error_display_cbor() {
    let err = ProtocolCodecError::Cbor("decode failed".into());
    assert!(err.to_string().contains("decode failed"));
}

#[test]
fn protocol_codec_error_display_io() {
    let err = ProtocolCodecError::Io(std::io::Error::new(std::io::ErrorKind::Other, "test"));
    assert!(err.to_string().contains("I/O error"));
}

#[test]
fn protocol_codec_error_from_io_error() {
    let io_err = std::io::Error::new(std::io::ErrorKind::Other, "test");
    let codec_err: ProtocolCodecError = io_err.into();
    assert!(matches!(codec_err, ProtocolCodecError::Io(_)));
}
