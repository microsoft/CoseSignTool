// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Tests for the TransactionNotCached fast-retry behavior in get_entry_statement.

use cbor_primitives::CborEncoder;
use cose_sign1_transparent_mst::http_client::{HttpTransport, MockHttpTransport};
use cose_sign1_transparent_mst::signing::client::{MstTransparencyClient, MstTransparencyClientOptions};
use cose_sign1_transparent_mst::signing::error::MstClientError;
use std::sync::Arc;
use std::time::Duration;
use url::Url;

use cbor_primitives_everparse::EverParseCborProvider;

/// Build a CBOR problem-details body with "TransactionNotCached" in the Detail field.
fn cbor_transaction_not_cached_detail() -> Vec<u8> {
    let _provider = EverParseCborProvider;
    let mut enc = cose_sign1_primitives::provider::encoder();
    enc.encode_map(2).unwrap();
    enc.encode_tstr("title").unwrap();
    enc.encode_tstr("Service Unavailable").unwrap();
    enc.encode_tstr("detail").unwrap();
    enc.encode_tstr("TransactionNotCached").unwrap();
    enc.into_bytes()
}

/// Build a CBOR problem-details body with "TransactionNotCached" in the Title field.
fn cbor_transaction_not_cached_title() -> Vec<u8> {
    let _provider = EverParseCborProvider;
    let mut enc = cose_sign1_primitives::provider::encoder();
    enc.encode_map(1).unwrap();
    enc.encode_tstr("title").unwrap();
    enc.encode_tstr("TransactionNotCached").unwrap();
    enc.into_bytes()
}

/// Build a CBOR problem-details body with a generic error (not TransactionNotCached).
fn cbor_generic_error() -> Vec<u8> {
    let _provider = EverParseCborProvider;
    let mut enc = cose_sign1_primitives::provider::encoder();
    enc.encode_map(1).unwrap();
    enc.encode_tstr("title").unwrap();
    enc.encode_tstr("Internal Server Error").unwrap();
    enc.into_bytes()
}

fn make_client(mock: Arc<MockHttpTransport>) -> MstTransparencyClient {
    MstTransparencyClient::with_http(
        Url::parse("https://mst.example.com").unwrap(),
        MstTransparencyClientOptions {
            transaction_not_cached_retry_delay: Duration::from_millis(1), // fast for tests
            transaction_not_cached_max_retries: 3,
            ..MstTransparencyClientOptions::default()
        },
        mock,
    )
}

fn statement_url() -> String {
    "https://mst.example.com/entries/entry-123/statement?api-version=2024-01-01".to_string()
}

// ============================================================================
// get_entry_statement with TransactionNotCached fast retry
// ============================================================================

#[test]
fn get_entry_statement_success_no_retry() {
    let mut mock = MockHttpTransport::new();
    mock.get_full_responses.insert(
        statement_url(),
        Ok((200, Some("application/cose".into()), b"cose-statement-bytes".to_vec())),
    );

    let client = make_client(Arc::new(mock));
    let result = client.get_entry_statement("entry-123");
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), b"cose-statement-bytes");
}

#[test]
fn get_entry_statement_503_non_tnc_returns_service_error() {
    // 503 but NOT TransactionNotCached — should not retry, return ServiceError immediately
    let mut mock = MockHttpTransport::new();
    mock.get_full_responses.insert(
        statement_url(),
        Ok((503, Some("application/cbor".into()), cbor_generic_error())),
    );

    let client = make_client(Arc::new(mock));
    let result = client.get_entry_statement("entry-123");
    match result.unwrap_err() {
        MstClientError::ServiceError { http_status, .. } => assert_eq!(http_status, 503),
        other => panic!("Expected ServiceError, got: {:?}", other),
    }
}

#[test]
fn get_entry_statement_non_503_error_returns_immediately() {
    let mut mock = MockHttpTransport::new();
    mock.get_full_responses.insert(
        statement_url(),
        Ok((404, None, b"Not Found".to_vec())),
    );

    let client = make_client(Arc::new(mock));
    let result = client.get_entry_statement("entry-123");
    match result.unwrap_err() {
        MstClientError::ServiceError { http_status, .. } => assert_eq!(http_status, 404),
        other => panic!("Expected ServiceError, got: {:?}", other),
    }
}

#[test]
fn get_entry_statement_tnc_detection_in_detail() {
    assert!(MstTransparencyClient::is_transaction_not_cached(
        Some("application/cbor"),
        &cbor_transaction_not_cached_detail(),
    ));
}

#[test]
fn get_entry_statement_tnc_detection_in_title() {
    assert!(MstTransparencyClient::is_transaction_not_cached(
        Some("application/cbor"),
        &cbor_transaction_not_cached_title(),
    ));
}

#[test]
fn get_entry_statement_tnc_detection_case_insensitive() {
    let _provider = EverParseCborProvider;
    let mut enc = cose_sign1_primitives::provider::encoder();
    enc.encode_map(1).unwrap();
    enc.encode_tstr("detail").unwrap();
    enc.encode_tstr("transactionnotcached").unwrap();
    let body = enc.into_bytes();

    assert!(MstTransparencyClient::is_transaction_not_cached(Some("application/cbor"), &body));
}

#[test]
fn get_entry_statement_tnc_not_detected_generic_error() {
    assert!(!MstTransparencyClient::is_transaction_not_cached(
        Some("application/cbor"),
        &cbor_generic_error(),
    ));
}

#[test]
fn get_entry_statement_tnc_not_detected_empty_body() {
    assert!(!MstTransparencyClient::is_transaction_not_cached(Some("application/cbor"), &[]));
}

#[test]
fn get_entry_statement_default_retry_config() {
    let opts = MstTransparencyClientOptions::default();
    assert_eq!(opts.transaction_not_cached_retry_delay, Duration::from_millis(250));
    assert_eq!(opts.transaction_not_cached_max_retries, 8);
}
