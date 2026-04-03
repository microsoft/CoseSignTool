// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use code_transparency_client::{
    mock_transport::{MockResponse, SequentialMockTransport},
    CodeTransparencyClient, CodeTransparencyClientConfig, CodeTransparencyClientOptions,
    CodeTransparencyError, DelayStrategy, JwksDocument, MstPollingOptions, OfflineKeysBehavior,
    TransactionNotCachedPolicy,
};
use std::time::Duration;
use url::Url;

use cbor_primitives::CborEncoder;
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
        CodeTransparencyClientConfig::default(),
        CodeTransparencyClientOptions {
            client_options: mock.into_client_options(),
            ..Default::default()
        },
    )
}

#[test]
fn default_config() {
    let cfg = CodeTransparencyClientConfig::default();
    assert_eq!(cfg.api_version, "2024-01-01");
    assert!(cfg.api_key.is_none());
    assert!(cfg.offline_keys.is_none());
    assert_eq!(
        cfg.offline_keys_behavior,
        OfflineKeysBehavior::FallbackToNetwork
    );
}

#[test]
fn get_entry_statement_success() {
    let client = mock_client(vec![MockResponse::ok(b"cose-statement".to_vec())]);
    assert_eq!(
        client.get_entry_statement("e-1").unwrap(),
        b"cose-statement"
    );
}

#[test]
fn get_entry_success() {
    let client = mock_client(vec![MockResponse::ok(b"receipt-bytes".to_vec())]);
    assert_eq!(client.get_entry("e-1").unwrap(), b"receipt-bytes");
}

#[test]
fn get_public_keys_success() {
    let jwks = r#"{"keys":[]}"#;
    let client = mock_client(vec![MockResponse::ok(jwks.as_bytes().to_vec())]);
    assert_eq!(client.get_public_keys().unwrap(), jwks);
}

#[test]
fn get_public_keys_typed_success() {
    let jwks = r#"{"keys":[{"kty":"EC","kid":"key-1","crv":"P-256"}]}"#;
    let client = mock_client(vec![MockResponse::ok(jwks.as_bytes().to_vec())]);
    let doc = client.get_public_keys_typed().unwrap();
    assert_eq!(doc.keys.len(), 1);
    assert_eq!(doc.keys[0].kid, "key-1");
}

#[test]
fn get_transparency_config_success() {
    let client = mock_client(vec![MockResponse::ok(b"cbor-config".to_vec())]);
    assert_eq!(
        client.get_transparency_config_cbor().unwrap(),
        b"cbor-config"
    );
}

#[test]
fn endpoint_accessor() {
    let client = mock_client(vec![]);
    assert_eq!(client.endpoint().as_str(), "https://mst.example.com/");
}

#[test]
fn debug_format() {
    let client = mock_client(vec![]);
    let s = format!("{:?}", client);
    assert!(s.contains("CodeTransparencyClient"));
}

#[test]
fn error_display() {
    let e = CodeTransparencyError::HttpError("conn refused".into());
    assert!(format!("{}", e).contains("conn refused"));

    let e = CodeTransparencyError::MissingField {
        field: "EntryId".into(),
    };
    assert!(format!("{}", e).contains("EntryId"));
}

#[test]
fn tnc_detected() {
    assert!(TransactionNotCachedPolicy::is_tnc_body(&cbor_map_1(
        "detail",
        "TransactionNotCached"
    )));
    assert!(!TransactionNotCachedPolicy::is_tnc_body(&cbor_map_1(
        "title",
        "Internal Server Error"
    )));
    assert!(!TransactionNotCachedPolicy::is_tnc_body(&[]));
}

#[test]
fn jwks_document_parse() {
    let json = r#"{"keys":[{"kty":"EC","kid":"k1","crv":"P-256","x":"abc","y":"def"}]}"#;
    let doc = JwksDocument::from_json(json).unwrap();
    assert_eq!(doc.keys.len(), 1);
    assert_eq!(doc.find_key("k1").unwrap().kty, "EC");
    assert!(doc.find_key("missing").is_none());
    assert!(!doc.is_empty());
}

#[test]
fn resolve_signing_key_offline() {
    let jwks =
        JwksDocument::from_json(r#"{"keys":[{"kty":"EC","kid":"k1","crv":"P-256"}]}"#).unwrap();
    let mut offline = std::collections::HashMap::new();
    offline.insert("mst.example.com".to_string(), jwks);

    let mock = SequentialMockTransport::new(vec![]); // no HTTP calls expected
    let client = CodeTransparencyClient::with_options(
        Url::parse("https://mst.example.com").unwrap(),
        CodeTransparencyClientConfig {
            offline_keys: Some(offline),
            offline_keys_behavior: OfflineKeysBehavior::OfflineOnly,
            ..Default::default()
        },
        CodeTransparencyClientOptions {
            client_options: mock.into_client_options(),
            ..Default::default()
        },
    );
    let key = client.resolve_signing_key("k1").unwrap();
    assert_eq!(key.kid, "k1");
}

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
    assert_eq!(
        opts.delay_for_retry(0, fallback),
        Duration::from_millis(100)
    );
    assert_eq!(
        MstPollingOptions::default().delay_for_retry(0, fallback),
        fallback
    );
}
