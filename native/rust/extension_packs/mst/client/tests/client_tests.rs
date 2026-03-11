// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Tests for `CodeTransparencyClient` using the `SequentialMockTransport`.

use cbor_primitives::CborEncoder;
use code_transparency_client::{
    mock_transport::{MockResponse, SequentialMockTransport},
    CodeTransparencyClient, CodeTransparencyClientConfig, CodeTransparencyClientOptions,
    CodeTransparencyError, CreateEntryResult, DelayStrategy, MstPollingOptions,
    TransactionNotCachedPolicy,
};
use std::time::Duration;
use url::Url;

use cbor_primitives_everparse::EverParseCborProvider;

fn cbor_map_1(k: &str, v: &str) -> Vec<u8> {
    let _p = EverParseCborProvider;
    let mut enc = cose_sign1_primitives::provider::encoder();
    enc.encode_map(1).unwrap();
    enc.encode_tstr(k).unwrap();
    enc.encode_tstr(v).unwrap();
    enc.into_bytes()
}

fn cbor_map_2(k1: &str, v1: &str, k2: &str, v2: &str) -> Vec<u8> {
    let _p = EverParseCborProvider;
    let mut enc = cose_sign1_primitives::provider::encoder();
    enc.encode_map(2).unwrap();
    enc.encode_tstr(k1).unwrap();
    enc.encode_tstr(v1).unwrap();
    enc.encode_tstr(k2).unwrap();
    enc.encode_tstr(v2).unwrap();
    enc.into_bytes()
}

fn mock_client(responses: Vec<MockResponse>) -> CodeTransparencyClient {
    let mock = SequentialMockTransport::new(responses);
    CodeTransparencyClient::with_options(
        Url::parse("https://mst.example.com").unwrap(),
        CodeTransparencyClientConfig {
            max_poll_retries: 3,
            poll_delay: Duration::from_millis(1),
            ..Default::default()
        },
        CodeTransparencyClientOptions {
            client_options: mock.into_client_options(),
        },
    )
}

// ============================================================================
// Default config
// ============================================================================

#[test]
fn default_config() {
    let cfg = CodeTransparencyClientConfig::default();
    assert_eq!(cfg.api_version, "2024-01-01");
    assert!(cfg.api_key.is_none());
    assert_eq!(cfg.max_poll_retries, 30);
    assert_eq!(cfg.poll_delay, Duration::from_secs(2));
    assert!(cfg.polling_options.is_none());
}

// ============================================================================
// create_entry
// ============================================================================

#[test]
fn create_entry_success() {
    let client = mock_client(vec![
        MockResponse::ok(cbor_map_1("OperationId", "op-1")),
        MockResponse::ok(cbor_map_2("Status", "Succeeded", "EntryId", "entry-42")),
    ]);
    let result = client.create_entry(b"cose-data").unwrap();
    assert_eq!(result.operation_id, "op-1");
    assert_eq!(result.entry_id, "entry-42");
}

#[test]
fn create_entry_post_error_returns_service_error() {
    let client = mock_client(vec![
        MockResponse::with_status(500, b"server error".to_vec()),
    ]);
    match client.create_entry(b"cose-data") {
        Err(CodeTransparencyError::ServiceError { http_status, .. }) => assert_eq!(http_status, 500),
        other => panic!("Expected ServiceError, got: {:?}", other),
    }
}

#[test]
fn create_entry_missing_operation_id() {
    let client = mock_client(vec![
        MockResponse::ok(cbor_map_1("Other", "value")),
    ]);
    match client.create_entry(b"cose-data") {
        Err(CodeTransparencyError::MissingField { field }) => assert_eq!(field, "OperationId"),
        other => panic!("Expected MissingField, got: {:?}", other),
    }
}

// ============================================================================
// poll_operation (via create_entry)
// ============================================================================

#[test]
fn poll_running_then_succeeded() {
    let client = mock_client(vec![
        MockResponse::ok(cbor_map_1("OperationId", "op-1")),
        MockResponse::ok(cbor_map_1("Status", "Running")),
        MockResponse::ok(cbor_map_2("Status", "Succeeded", "EntryId", "e-1")),
    ]);
    let result = client.create_entry(b"cose-data").unwrap();
    assert_eq!(result.entry_id, "e-1");
}

#[test]
fn poll_failed() {
    let client = mock_client(vec![
        MockResponse::ok(cbor_map_1("OperationId", "op-1")),
        MockResponse::ok(cbor_map_1("Status", "Failed")),
    ]);
    match client.create_entry(b"cose-data") {
        Err(CodeTransparencyError::OperationFailed { status, .. }) => assert_eq!(status, "Failed"),
        other => panic!("Expected OperationFailed, got: {:?}", other),
    }
}

#[test]
fn poll_timeout() {
    let client = mock_client(vec![
        MockResponse::ok(cbor_map_1("OperationId", "op-1")),
        MockResponse::ok(cbor_map_1("Status", "Running")),
        MockResponse::ok(cbor_map_1("Status", "Running")),
        MockResponse::ok(cbor_map_1("Status", "Running")),
    ]);
    match client.create_entry(b"cose-data") {
        Err(CodeTransparencyError::OperationTimeout { retries, .. }) => assert_eq!(retries, 3),
        other => panic!("Expected OperationTimeout, got: {:?}", other),
    }
}

// ============================================================================
// get_entry_statement / get_entry / get_public_keys
// ============================================================================

#[test]
fn get_entry_statement_success() {
    let client = mock_client(vec![
        MockResponse::ok(b"cose-statement".to_vec()),
    ]);
    let result = client.get_entry_statement("entry-1").unwrap();
    assert_eq!(result, b"cose-statement");
}

#[test]
fn get_entry_success() {
    let client = mock_client(vec![
        MockResponse::ok(b"receipt-bytes".to_vec()),
    ]);
    let result = client.get_entry("entry-1").unwrap();
    assert_eq!(result, b"receipt-bytes");
}

#[test]
fn get_public_keys_success() {
    let jwks = r#"{"keys":[]}"#;
    let client = mock_client(vec![
        MockResponse::ok(jwks.as_bytes().to_vec()),
    ]);
    let result = client.get_public_keys().unwrap();
    assert_eq!(result, jwks);
}

#[test]
fn get_transparency_config_success() {
    let client = mock_client(vec![
        MockResponse::ok(b"cbor-config".to_vec()),
    ]);
    let result = client.get_transparency_config_cbor().unwrap();
    assert_eq!(result, b"cbor-config");
}

// ============================================================================
// make_transparent
// ============================================================================

#[test]
fn make_transparent_success() {
    let client = mock_client(vec![
        MockResponse::ok(cbor_map_1("OperationId", "op-1")),
        MockResponse::ok(cbor_map_2("Status", "Succeeded", "EntryId", "entry-7")),
        MockResponse::ok(b"transparent-cose".to_vec()),
    ]);
    let result = client.make_transparent(b"cose-input").unwrap();
    assert_eq!(result, b"transparent-cose");
}

// ============================================================================
// endpoint accessor
// ============================================================================

#[test]
fn endpoint_accessor() {
    let client = mock_client(vec![]);
    assert_eq!(client.endpoint().as_str(), "https://mst.example.com/");
}

// ============================================================================
// Debug format
// ============================================================================

#[test]
fn debug_format() {
    let client = mock_client(vec![]);
    let s = format!("{:?}", client);
    assert!(s.contains("CodeTransparencyClient"));
    assert!(s.contains("mst.example.com"));
}

// ============================================================================
// Error display
// ============================================================================

#[test]
fn error_display() {
    let e = CodeTransparencyError::HttpError("conn refused".into());
    assert!(format!("{}", e).contains("conn refused"));

    let e = CodeTransparencyError::OperationTimeout { operation_id: "op-1".into(), retries: 5 };
    let s = format!("{}", e);
    assert!(s.contains("op-1"));
    assert!(s.contains("5"));

    let e = CodeTransparencyError::MissingField { field: "EntryId".into() };
    assert!(format!("{}", e).contains("EntryId"));
}

// ============================================================================
// Polling options
// ============================================================================

#[test]
fn delay_strategy_fixed() {
    let s = DelayStrategy::fixed(Duration::from_millis(500));
    assert_eq!(s.delay_for_retry(0), Duration::from_millis(500));
    assert_eq!(s.delay_for_retry(10), Duration::from_millis(500));
}

#[test]
fn delay_strategy_exponential() {
    let s = DelayStrategy::exponential(Duration::from_millis(100), 2.0, Duration::from_secs(10));
    assert_eq!(s.delay_for_retry(0), Duration::from_millis(100));
    assert_eq!(s.delay_for_retry(1), Duration::from_millis(200));
    assert_eq!(s.delay_for_retry(20), Duration::from_secs(10));
}

#[test]
fn polling_options_priority() {
    let fallback = Duration::from_secs(5);
    let opts = MstPollingOptions {
        delay_strategy: Some(DelayStrategy::fixed(Duration::from_millis(100))),
        polling_interval: Some(Duration::from_secs(1)),
        ..Default::default()
    };
    assert_eq!(opts.delay_for_retry(0, fallback), Duration::from_millis(100));

    let opts2 = MstPollingOptions {
        polling_interval: Some(Duration::from_millis(750)),
        ..Default::default()
    };
    assert_eq!(opts2.delay_for_retry(0, fallback), Duration::from_millis(750));

    assert_eq!(MstPollingOptions::default().delay_for_retry(0, fallback), fallback);
}

// ============================================================================
// is_transaction_not_cached
// ============================================================================

#[test]
fn tnc_detected() {
    assert!(TransactionNotCachedPolicy::is_tnc_body(&cbor_map_1("detail", "TransactionNotCached")));
    assert!(TransactionNotCachedPolicy::is_tnc_body(&cbor_map_1("title", "TransactionNotCached")));
    assert!(TransactionNotCachedPolicy::is_tnc_body(&cbor_map_1("detail", "transactionnotcached")));
}

#[test]
fn tnc_not_detected() {
    assert!(!TransactionNotCachedPolicy::is_tnc_body(&cbor_map_1("title", "Internal Server Error")));
    assert!(!TransactionNotCachedPolicy::is_tnc_body(&[]));
}
