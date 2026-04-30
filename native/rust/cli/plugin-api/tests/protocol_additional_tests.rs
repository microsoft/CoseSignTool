// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use std::io::Cursor;

use cosesigntool_plugin_api::auth::AUTH_KEY_LENGTH;
use cosesigntool_plugin_api::protocol::{
    frame_length_prefix, read_frame, read_request, read_response, write_frame, write_request,
    write_response, Request, RequestParams, Response, ResponseResult,
};
use cosesigntool_plugin_api::traits::SignResponse;

#[test]
fn none_request_roundtrips_through_framed_cbor() {
    let request = Request::capabilities();
    let decoded = roundtrip_request(&request);

    assert_eq!(decoded.method, "capabilities");
    assert!(matches!(decoded.params, RequestParams::None));
}

#[test]
fn authenticate_request_roundtrips_through_framed_cbor() {
    let request = Request::authenticate(vec![0x55; AUTH_KEY_LENGTH]);
    let decoded = roundtrip_request(&request);

    match decoded.params {
        RequestParams::Authenticate { auth_key } => assert_eq!(auth_key, vec![0x55; AUTH_KEY_LENGTH]),
        other => panic!("unexpected params: {other:?}"),
    }
}

#[test]
fn service_id_request_roundtrips_through_framed_cbor() {
    let request = Request::get_algorithm("service-42");
    let decoded = roundtrip_request(&request);

    match decoded.params {
        RequestParams::ServiceId { service_id } => assert_eq!(service_id, "service-42"),
        other => panic!("unexpected params: {other:?}"),
    }
}

#[test]
fn raw_cbor_request_roundtrips_for_unknown_methods() {
    let raw_params = vec![0xa1, 0x63, 0x66, 0x6f, 0x6f, 0x18, 0x2a];
    let request = Request::new("custom_method", RequestParams::RawCbor(raw_params.clone()));
    let decoded = roundtrip_request(&request);

    match decoded.params {
        RequestParams::RawCbor(raw) => assert_eq!(raw, raw_params),
        other => panic!("unexpected params: {other:?}"),
    }
}

#[test]
fn none_create_service_sign_and_raw_cbor_responses_roundtrip() {
    assert!(matches!(roundtrip_response(&Response::ok(ResponseResult::None)).result, ResponseResult::None));

    match roundtrip_response(&Response::ok(ResponseResult::CreateService {
        service_id: "service-123".to_string(),
    }))
    .result
    {
        ResponseResult::CreateService { service_id } => assert_eq!(service_id, "service-123"),
        other => panic!("unexpected create_service result: {other:?}"),
    }

    match roundtrip_response(&Response::ok(ResponseResult::Sign(SignResponse {
        signature: vec![0xde, 0xad, 0xbe, 0xef],
    })))
    .result
    {
        ResponseResult::Sign(result) => assert_eq!(result.signature, vec![0xde, 0xad, 0xbe, 0xef]),
        other => panic!("unexpected sign result: {other:?}"),
    }

    match roundtrip_response(&Response::ok(ResponseResult::RawCbor(vec![0x18, 0x2a]))).result {
        ResponseResult::RawCbor(raw) => assert_eq!(raw, vec![0x18, 0x2a]),
        other => panic!("unexpected raw CBOR result: {other:?}"),
    }
}

#[test]
fn write_frame_and_read_frame_roundtrip_various_sizes() {
    for size in [0usize, 1, 7, 1024] {
        let payload = vec![0xa5; size];
        let mut buffer = Vec::new();

        write_frame(&mut buffer, payload.as_slice()).expect("frame should encode");

        let mut cursor = Cursor::new(buffer);
        let decoded = read_frame(&mut cursor).expect("frame should decode");
        assert_eq!(decoded, payload);
    }
}

#[test]
fn frame_length_prefix_rejects_sizes_larger_than_u32() {
    let error = frame_length_prefix((u32::MAX as usize) + 1)
        .expect_err("oversized frames should be rejected");

    assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
}

#[test]
fn read_frame_reports_eof_for_missing_or_truncated_frames() {
    let empty = read_frame(&mut Cursor::new(Vec::<u8>::new()))
        .expect_err("clean EOF should be reported as UnexpectedEof");
    assert_eq!(empty.kind(), std::io::ErrorKind::UnexpectedEof);

    let partial_prefix = read_frame(&mut Cursor::new(vec![0x00, 0x00, 0x00]))
        .expect_err("partial prefixes should fail");
    assert_eq!(partial_prefix.kind(), std::io::ErrorKind::UnexpectedEof);

    let truncated_frame = read_frame(&mut Cursor::new(vec![0x00, 0x00, 0x00, 0x02, 0xaa]))
        .expect_err("truncated frames should fail");
    assert_eq!(truncated_frame.kind(), std::io::ErrorKind::UnexpectedEof);
}

#[test]
fn read_request_returns_none_on_clean_eof() {
    let request = read_request(&mut Cursor::new(Vec::<u8>::new())).expect("clean EOF should succeed");
    assert!(request.is_none());
}

fn roundtrip_request(request: &Request) -> Request {
    let mut buffer = Vec::new();
    write_request(&mut buffer, request).expect("request should encode");

    let mut cursor = Cursor::new(buffer);
    read_request(&mut cursor)
        .expect("request should decode")
        .expect("request frame should be present")
}

fn roundtrip_response(response: &Response) -> Response {
    let mut buffer = Vec::new();
    write_response(&mut buffer, response).expect("response should encode");

    let mut cursor = Cursor::new(buffer);
    read_response(&mut cursor).expect("response should decode")
}