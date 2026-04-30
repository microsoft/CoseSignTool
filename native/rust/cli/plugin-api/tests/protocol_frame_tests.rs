// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Tests for protocol framing and validation edge cases.

use cosesigntool_plugin_api::protocol::{
    self, frame_length_prefix, read_frame, write_frame, Request, RequestParams, Response,
    ResponseResult,
};

#[test]
fn frame_length_prefix_zero_length() {
    let prefix = frame_length_prefix(0).unwrap();
    assert_eq!(prefix, [0, 0, 0, 0]);
}

#[test]
fn frame_length_prefix_small_length() {
    let prefix = frame_length_prefix(256).unwrap();
    assert_eq!(prefix, [0, 0, 1, 0]);
}

#[test]
fn frame_length_prefix_max_u32() {
    let prefix = frame_length_prefix(u32::MAX as usize).unwrap();
    assert_eq!(prefix, [0xFF, 0xFF, 0xFF, 0xFF]);
}

#[cfg(target_pointer_width = "64")]
#[test]
fn frame_length_prefix_exceeds_u32_returns_error() {
    let result = frame_length_prefix((u32::MAX as usize) + 1);
    assert!(result.is_err());
}

#[test]
fn write_frame_read_frame_roundtrip() {
    let payload = b"hello world";
    let mut buffer = Vec::new();
    write_frame(&mut buffer, payload).unwrap();

    let mut cursor = std::io::Cursor::new(buffer);
    let frame = read_frame(&mut cursor).unwrap();
    assert_eq!(frame.as_slice(), payload);
}

#[test]
fn read_frame_empty_stream_returns_eof_error() {
    let mut cursor = std::io::Cursor::new(Vec::<u8>::new());
    let result = read_frame(&mut cursor);
    assert!(result.is_err());
}

#[test]
fn write_request_read_request_roundtrip_capabilities() {
    let request = Request::capabilities();
    let mut buffer = Vec::new();
    protocol::write_request(&mut buffer, &request).unwrap();

    let mut cursor = std::io::Cursor::new(buffer);
    let decoded = protocol::read_request(&mut cursor)
        .unwrap()
        .expect("should decode request");
    assert_eq!(decoded.method, "capabilities");
    assert!(matches!(decoded.params, RequestParams::None));
}

#[test]
fn write_request_read_request_roundtrip_shutdown() {
    let request = Request::shutdown();
    let mut buffer = Vec::new();
    protocol::write_request(&mut buffer, &request).unwrap();

    let mut cursor = std::io::Cursor::new(buffer);
    let decoded = protocol::read_request(&mut cursor)
        .unwrap()
        .expect("should decode shutdown");
    assert_eq!(decoded.method, "shutdown");
}

#[test]
fn write_response_read_response_roundtrip_acknowledged() {
    let response = Response::ok(ResponseResult::Acknowledged);
    let mut buffer = Vec::new();
    protocol::write_response(&mut buffer, &response).unwrap();

    let mut cursor = std::io::Cursor::new(buffer);
    let decoded = protocol::read_response(&mut cursor).unwrap();
    assert!(decoded.error.is_none());
    assert!(matches!(decoded.result, ResponseResult::Acknowledged));
}

#[test]
fn write_response_read_response_roundtrip_error() {
    let response = Response::err("TEST_ERROR", "something went wrong");
    let mut buffer = Vec::new();
    protocol::write_response(&mut buffer, &response).unwrap();

    let mut cursor = std::io::Cursor::new(buffer);
    let decoded = protocol::read_response(&mut cursor).unwrap();
    let error = decoded.error.expect("should have error");
    assert_eq!(error.code, "TEST_ERROR");
    assert_eq!(error.message, "something went wrong");
}

#[test]
fn write_response_read_response_roundtrip_none() {
    let response = Response::ok(ResponseResult::None);
    let mut buffer = Vec::new();
    protocol::write_response(&mut buffer, &response).unwrap();

    let mut cursor = std::io::Cursor::new(buffer);
    let decoded = protocol::read_response(&mut cursor).unwrap();
    assert!(matches!(decoded.result, ResponseResult::None));
}

#[test]
fn write_request_read_request_roundtrip_authenticate() {
    let auth_key = vec![0xAB; 32];
    let request = Request::authenticate(auth_key.clone());
    let mut buffer = Vec::new();
    protocol::write_request(&mut buffer, &request).unwrap();

    let mut cursor = std::io::Cursor::new(buffer);
    let decoded = protocol::read_request(&mut cursor)
        .unwrap()
        .expect("should decode authenticate");
    assert_eq!(decoded.method, "authenticate");
    match decoded.params {
        RequestParams::Authenticate { auth_key: key } => {
            assert_eq!(key, auth_key);
        }
        other => panic!("expected Authenticate params, got: {other:?}"),
    }
}

#[test]
fn write_request_read_request_roundtrip_get_cert_chain() {
    let request = Request::get_cert_chain("svc-123");
    let mut buffer = Vec::new();
    protocol::write_request(&mut buffer, &request).unwrap();

    let mut cursor = std::io::Cursor::new(buffer);
    let decoded = protocol::read_request(&mut cursor)
        .unwrap()
        .expect("should decode");
    assert_eq!(decoded.method, "get_cert_chain");
    match decoded.params {
        RequestParams::ServiceId { service_id } => assert_eq!(service_id, "svc-123"),
        other => panic!("expected ServiceId, got: {other:?}"),
    }
}

#[test]
fn write_request_read_request_roundtrip_get_algorithm() {
    let request = Request::get_algorithm("svc-456");
    let mut buffer = Vec::new();
    protocol::write_request(&mut buffer, &request).unwrap();

    let mut cursor = std::io::Cursor::new(buffer);
    let decoded = protocol::read_request(&mut cursor)
        .unwrap()
        .expect("should decode");
    assert_eq!(decoded.method, "get_algorithm");
}

#[test]
fn write_request_read_request_roundtrip_trust_policy_info() {
    let request = Request::trust_policy_info();
    let mut buffer = Vec::new();
    protocol::write_request(&mut buffer, &request).unwrap();

    let mut cursor = std::io::Cursor::new(buffer);
    let decoded = protocol::read_request(&mut cursor)
        .unwrap()
        .expect("should decode");
    assert_eq!(decoded.method, "get_trust_policy_info");
}

#[test]
fn read_request_returns_none_on_clean_eof() {
    let mut cursor = std::io::Cursor::new(Vec::<u8>::new());
    let result = protocol::read_request(&mut cursor).unwrap();
    assert!(result.is_none());
}
