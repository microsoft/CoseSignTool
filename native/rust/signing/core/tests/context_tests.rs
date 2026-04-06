// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Tests for signing context and payload types.

use cose_sign1_signing::{SigningContext, SigningPayload};

#[test]
fn test_signing_context_from_bytes() {
    let payload = vec![1, 2, 3, 4, 5];
    let context = SigningContext::from_bytes(payload.clone());

    assert_eq!(context.payload_bytes(), Some(payload.as_slice()));
    assert!(!context.has_stream());
    assert!(context.content_type.is_none());
    assert!(context.additional_header_contributors.is_empty());
}

#[test]
fn test_signing_context_from_bytes_with_content_type() {
    let payload = vec![1, 2, 3, 4, 5];
    let mut context = SigningContext::from_bytes(payload.clone());
    context.content_type = Some("application/octet-stream".to_string());

    assert_eq!(context.payload_bytes(), Some(payload.as_slice()));
    assert_eq!(
        context.content_type.as_deref(),
        Some("application/octet-stream")
    );
}

#[test]
fn test_signing_payload_bytes() {
    let payload = vec![1, 2, 3];
    let payload_enum = SigningPayload::Bytes(payload.clone());

    match payload_enum {
        SigningPayload::Bytes(ref b) => assert_eq!(b, &payload),
        SigningPayload::Stream(_) => panic!("Expected Bytes variant"),
        SigningPayload::Borrowed(_) => panic!("Expected Bytes variant"),
    }
}

#[test]
fn test_signing_payload_borrowed() {
    let data = vec![4, 5, 6];
    let context = SigningContext::from_slice(&data);

    assert_eq!(context.payload_bytes(), Some(data.as_slice()));
    assert!(!context.has_stream());
}

#[test]
fn test_context_payload_bytes_returns_none_for_stream() {
    use cose_sign1_primitives::SizedReader;
    use std::io::Cursor;

    let data = vec![1, 2, 3, 4, 5];
    let cursor = Cursor::new(data.clone());
    let sized = SizedReader::new(cursor, data.len() as u64);
    let context = SigningContext::from_stream(Box::new(sized));

    assert_eq!(context.payload_bytes(), None);
    assert!(context.has_stream());
}

#[test]
fn test_context_has_stream() {
    let bytes_context = SigningContext::from_bytes(vec![1, 2, 3]);
    assert!(!bytes_context.has_stream());

    use cose_sign1_primitives::SizedReader;
    use std::io::Cursor;

    let data = vec![1, 2, 3];
    let cursor = Cursor::new(data.clone());
    let sized = SizedReader::new(cursor, data.len() as u64);
    let stream_context = SigningContext::from_stream(Box::new(sized));

    assert!(stream_context.has_stream());
}
