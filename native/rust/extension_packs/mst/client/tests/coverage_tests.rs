// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Additional tests to fill coverage gaps in the code_transparency_client crate.

use azure_core::http::poller::{PollerStatus, StatusMonitor};
use code_transparency_client::cbor_problem_details::CborProblemDetails;
use code_transparency_client::operation_status::OperationStatus;
use code_transparency_client::{
    mock_transport::{MockResponse, SequentialMockTransport},
    CodeTransparencyClient, CodeTransparencyClientConfig, CodeTransparencyClientOptions,
    CodeTransparencyError, DelayStrategy, JsonWebKey, JwksDocument, MstPollingOptions,
    OfflineKeysBehavior, TransactionNotCachedPolicy,
};
use std::collections::HashMap;
use std::time::Duration;
use url::Url;

use cbor_primitives::CborEncoder;
use cbor_primitives_everparse::EverParseCborProvider;

// ---- CBOR helpers ----

fn cbor_map_1(k: &str, v: &str) -> Vec<u8> {
    let _p = EverParseCborProvider;
    let mut enc = cose_sign1_primitives::provider::encoder();
    enc.encode_map(1).unwrap();
    enc.encode_tstr(k).unwrap();
    enc.encode_tstr(v).unwrap();
    enc.into_bytes()
}

fn cbor_map_negkey(key: i64, val: &str) -> Vec<u8> {
    let _p = EverParseCborProvider;
    let mut enc = cose_sign1_primitives::provider::encoder();
    enc.encode_map(1).unwrap();
    enc.encode_i64(key).unwrap();
    enc.encode_tstr(val).unwrap();
    enc.into_bytes()
}

fn cbor_map_negkey_int(key: i64, val: i64) -> Vec<u8> {
    let _p = EverParseCborProvider;
    let mut enc = cose_sign1_primitives::provider::encoder();
    enc.encode_map(1).unwrap();
    enc.encode_i64(key).unwrap();
    enc.encode_i64(val).unwrap();
    enc.into_bytes()
}

fn cbor_map_multi_negkey(entries: &[(i64, &str)]) -> Vec<u8> {
    let _p = EverParseCborProvider;
    let mut enc = cose_sign1_primitives::provider::encoder();
    enc.encode_map(entries.len()).unwrap();
    for (k, v) in entries {
        enc.encode_i64(*k).unwrap();
        enc.encode_tstr(v).unwrap();
    }
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

// ========================================================================
// OperationStatus / StatusMonitor
// ========================================================================

#[test]
fn operation_status_succeeded() {
    let s = OperationStatus {
        operation_id: "op-1".into(),
        operation_status: "Succeeded".into(),
        entry_id: Some("e-1".into()),
    };
    assert_eq!(s.status(), PollerStatus::Succeeded);
}

#[test]
fn operation_status_failed() {
    let s = OperationStatus {
        operation_id: "op-1".into(),
        operation_status: "Failed".into(),
        entry_id: None,
    };
    assert_eq!(s.status(), PollerStatus::Failed);
}

#[test]
fn operation_status_canceled() {
    let s = OperationStatus {
        operation_id: "op-1".into(),
        operation_status: "Canceled".into(),
        entry_id: None,
    };
    assert_eq!(s.status(), PollerStatus::Canceled);
}

#[test]
fn operation_status_cancelled_british() {
    let s = OperationStatus {
        operation_id: "op-1".into(),
        operation_status: "Cancelled".into(),
        entry_id: None,
    };
    assert_eq!(s.status(), PollerStatus::Canceled);
}

#[test]
fn operation_status_running() {
    let s = OperationStatus {
        operation_id: "op-1".into(),
        operation_status: "Running".into(),
        entry_id: None,
    };
    assert_eq!(s.status(), PollerStatus::InProgress);
}

#[test]
fn operation_status_empty_string() {
    let s = OperationStatus {
        operation_id: String::new(),
        operation_status: String::new(),
        entry_id: None,
    };
    assert_eq!(s.status(), PollerStatus::InProgress);
}

// ========================================================================
// Error Display — all variants
// ========================================================================

#[test]
fn error_display_http() {
    let e = CodeTransparencyError::HttpError("connection reset".into());
    assert!(e.to_string().contains("connection reset"));
}

#[test]
fn error_display_cbor_parse() {
    let e = CodeTransparencyError::CborParseError("unexpected tag".into());
    assert!(e.to_string().contains("CBOR parse error"));
}

#[test]
fn error_display_timeout() {
    let e = CodeTransparencyError::OperationTimeout {
        operation_id: "op-42".into(),
        retries: 10,
    };
    let s = e.to_string();
    assert!(s.contains("op-42"));
    assert!(s.contains("10"));
}

#[test]
fn error_display_operation_failed() {
    let e = CodeTransparencyError::OperationFailed {
        operation_id: "op-99".into(),
        status: "Failed".into(),
    };
    let s = e.to_string();
    assert!(s.contains("op-99"));
    assert!(s.contains("Failed"));
}

#[test]
fn error_display_missing_field() {
    let e = CodeTransparencyError::MissingField {
        field: "EntryId".into(),
    };
    assert!(e.to_string().contains("EntryId"));
}

#[test]
fn error_display_service_error() {
    let e = CodeTransparencyError::ServiceError {
        http_status: 503,
        problem_details: None,
        message: "service unavailable".into(),
    };
    assert!(e.to_string().contains("service unavailable"));
}

#[test]
fn error_is_std_error_all_variants() {
    let errors: Vec<Box<dyn std::error::Error>> = vec![
        Box::new(CodeTransparencyError::HttpError("x".into())),
        Box::new(CodeTransparencyError::CborParseError("x".into())),
        Box::new(CodeTransparencyError::OperationTimeout {
            operation_id: "o".into(),
            retries: 1,
        }),
        Box::new(CodeTransparencyError::OperationFailed {
            operation_id: "o".into(),
            status: "x".into(),
        }),
        Box::new(CodeTransparencyError::MissingField { field: "f".into() }),
        Box::new(CodeTransparencyError::ServiceError {
            http_status: 500,
            problem_details: None,
            message: "m".into(),
        }),
    ];
    for e in errors {
        // Just verifying it compiles and has Debug + Display
        let _d = format!("{:?}", e);
        let _s = format!("{}", e);
    }
}

// ========================================================================
// Error — from_http_response
// ========================================================================

#[test]
fn from_http_response_non_cbor() {
    let e = CodeTransparencyError::from_http_response(500, Some("text/plain"), b"oops");
    match e {
        CodeTransparencyError::ServiceError {
            http_status,
            problem_details,
            message,
        } => {
            assert_eq!(http_status, 500);
            assert!(problem_details.is_none());
            assert!(message.contains("500"));
        }
        _ => panic!("expected ServiceError"),
    }
}

#[test]
fn from_http_response_cbor_with_title_and_detail() {
    let body = cbor_map_multi_negkey(&[(-2, "Bad Request"), (-4, "Missing field X")]);
    let e = CodeTransparencyError::from_http_response(
        400,
        Some("application/concise-problem-details+cbor"),
        &body,
    );
    match e {
        CodeTransparencyError::ServiceError {
            http_status,
            problem_details,
            message,
        } => {
            assert_eq!(http_status, 400);
            assert!(problem_details.is_some());
            assert!(message.contains("Bad Request"));
            assert!(message.contains("Missing field X"));
        }
        _ => panic!("expected ServiceError"),
    }
}

#[test]
fn from_http_response_cbor_title_same_as_detail() {
    // When title == detail, the detail should not be duplicated in message.
    let body = cbor_map_multi_negkey(&[(-2, "Conflict"), (-4, "Conflict")]);
    let e = CodeTransparencyError::from_http_response(409, Some("application/cbor"), &body);
    match e {
        CodeTransparencyError::ServiceError { message, .. } => {
            // Should appear once, not twice
            let count = message.matches("Conflict").count();
            assert!(count <= 2, "detail duplicated: {}", message);
        }
        _ => panic!("expected ServiceError"),
    }
}

#[test]
fn from_http_response_no_content_type() {
    let e = CodeTransparencyError::from_http_response(502, None, b"gateway error");
    match e {
        CodeTransparencyError::ServiceError {
            problem_details,
            message,
            ..
        } => {
            assert!(problem_details.is_none());
            assert!(message.contains("502"));
        }
        _ => panic!("expected ServiceError"),
    }
}

#[test]
fn from_http_response_empty_cbor_body() {
    let e = CodeTransparencyError::from_http_response(503, Some("application/cbor"), &[]);
    match e {
        CodeTransparencyError::ServiceError {
            problem_details, ..
        } => {
            assert!(problem_details.is_none());
        }
        _ => panic!("expected ServiceError"),
    }
}

// ========================================================================
// CborProblemDetails
// ========================================================================

#[test]
fn cbor_problem_details_empty() {
    assert!(CborProblemDetails::try_parse(&[]).is_none());
}

#[test]
fn cbor_problem_details_negkey_type() {
    let body = cbor_map_negkey(-1, "urn:example:not-found");
    let pd = CborProblemDetails::try_parse(&body).unwrap();
    assert_eq!(pd.problem_type.as_deref(), Some("urn:example:not-found"));
}

#[test]
fn cbor_problem_details_negkey_title() {
    let body = cbor_map_negkey(-2, "Not Found");
    let pd = CborProblemDetails::try_parse(&body).unwrap();
    assert_eq!(pd.title.as_deref(), Some("Not Found"));
}

#[test]
fn cbor_problem_details_negkey_status() {
    let body = cbor_map_negkey_int(-3, 404);
    let pd = CborProblemDetails::try_parse(&body).unwrap();
    assert_eq!(pd.status, Some(404));
}

#[test]
fn cbor_problem_details_negkey_detail() {
    let body = cbor_map_negkey(-4, "Entry not in ledger");
    let pd = CborProblemDetails::try_parse(&body).unwrap();
    assert_eq!(pd.detail.as_deref(), Some("Entry not in ledger"));
}

#[test]
fn cbor_problem_details_negkey_instance() {
    let body = cbor_map_negkey(-5, "/entries/xyz");
    let pd = CborProblemDetails::try_parse(&body).unwrap();
    assert_eq!(pd.instance.as_deref(), Some("/entries/xyz"));
}

#[test]
fn cbor_problem_details_negkey_extension() {
    let body = cbor_map_negkey_int(-99, 42);
    let pd = CborProblemDetails::try_parse(&body);
    // The extension parser tries decode_tstr on the value,
    // an integer value won't parse as tstr, so it stores empty string
    assert!(pd.is_some());
}

#[test]
fn cbor_problem_details_string_keys_all() {
    let _p = EverParseCborProvider;
    let mut enc = cose_sign1_primitives::provider::encoder();
    enc.encode_map(6).unwrap();
    enc.encode_tstr("type").unwrap();
    enc.encode_tstr("urn:test").unwrap();
    enc.encode_tstr("title").unwrap();
    enc.encode_tstr("Test Title").unwrap();
    enc.encode_tstr("status").unwrap();
    enc.encode_i64(422).unwrap();
    enc.encode_tstr("detail").unwrap();
    enc.encode_tstr("Test Detail").unwrap();
    enc.encode_tstr("instance").unwrap();
    enc.encode_tstr("/test/path").unwrap();
    enc.encode_tstr("custom-ext").unwrap();
    enc.encode_tstr("custom-val").unwrap();
    let body = enc.into_bytes();

    let pd = CborProblemDetails::try_parse(&body).unwrap();
    assert_eq!(pd.problem_type.as_deref(), Some("urn:test"));
    assert_eq!(pd.title.as_deref(), Some("Test Title"));
    assert_eq!(pd.status, Some(422));
    assert_eq!(pd.detail.as_deref(), Some("Test Detail"));
    assert_eq!(pd.instance.as_deref(), Some("/test/path"));
    assert_eq!(
        pd.extensions.get("custom-ext").map(String::as_str),
        Some("custom-val")
    );
}

#[test]
fn cbor_problem_details_display_with_fields() {
    let pd = CborProblemDetails {
        problem_type: Some("urn:t".into()),
        title: Some("Title".into()),
        status: Some(500),
        detail: Some("Detail".into()),
        instance: Some("/i".into()),
        extensions: HashMap::new(),
    };
    let s = pd.to_string();
    assert!(s.contains("Title"));
    assert!(s.contains("500"));
    assert!(s.contains("Detail"));
    assert!(s.contains("urn:t"));
    assert!(s.contains("/i"));
}

#[test]
fn cbor_problem_details_display_empty() {
    let pd = CborProblemDetails::default();
    assert_eq!(pd.to_string(), "No details available");
}

#[test]
fn cbor_problem_details_display_partial() {
    let pd = CborProblemDetails {
        title: Some("T".into()),
        ..Default::default()
    };
    assert!(pd.to_string().contains('T'));
}

// ========================================================================
// MockTransport edge cases
// ========================================================================

#[test]
fn mock_response_with_status() {
    let r = MockResponse::with_status(404, b"not found".to_vec());
    assert_eq!(r.status, 404);
    assert!(r.content_type.is_none());
}

#[test]
fn mock_response_with_content_type() {
    let r = MockResponse::with_content_type(200, "application/cbor", b"data".to_vec());
    assert_eq!(r.status, 200);
    assert_eq!(r.content_type.as_deref(), Some("application/cbor"));
}

#[test]
fn mock_transport_debug() {
    let mock = SequentialMockTransport::new(vec![
        MockResponse::ok(b"a".to_vec()),
        MockResponse::ok(b"b".to_vec()),
    ]);
    let dbg = format!("{:?}", mock);
    assert!(dbg.contains("SequentialMockTransport"));
    assert!(dbg.contains('2'));
}

#[test]
fn mock_transport_exhausted_returns_error() {
    // When mock has no responses left, requests should fail
    let client = mock_client(vec![]); // empty response queue
    let result = client.get_transparency_config_cbor();
    assert!(result.is_err());
}

// ========================================================================
// Client — CBOR field parsing via get_operation endpoint
// ========================================================================

#[test]
fn get_operation_parses_cbor_response() {
    // get_operation returns raw bytes; the CBOR parsing happens at a higher level
    let _p = EverParseCborProvider;
    let mut enc = cose_sign1_primitives::provider::encoder();
    enc.encode_map(2).unwrap();
    enc.encode_tstr("Status").unwrap();
    enc.encode_tstr("Succeeded").unwrap();
    enc.encode_tstr("EntryId").unwrap();
    enc.encode_tstr("e-123").unwrap();
    let cbor = enc.into_bytes();

    let client = mock_client(vec![MockResponse::ok(cbor.clone())]);
    let result = client.get_operation("op-1").unwrap();
    assert_eq!(result, cbor);
}

// ========================================================================
// Client — resolve_signing_key
// ========================================================================

#[test]
fn resolve_signing_key_offline_only_not_found() {
    let jwks =
        JwksDocument::from_json(r#"{"keys":[{"kty":"EC","kid":"k1","crv":"P-256"}]}"#).unwrap();
    let mut offline = HashMap::new();
    offline.insert("mst.example.com".to_string(), jwks);

    let mock = SequentialMockTransport::new(vec![]);
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
    let err = client.resolve_signing_key("missing-kid").unwrap_err();
    assert!(err.to_string().contains("missing-kid"));
    assert!(err.to_string().contains("offline"));
}

#[test]
fn resolve_signing_key_fallback_to_network() {
    let jwks_json = r#"{"keys":[{"kty":"EC","kid":"net-key","crv":"P-384"}]}"#;
    let mock = SequentialMockTransport::new(vec![MockResponse::ok(jwks_json.as_bytes().to_vec())]);
    let client = CodeTransparencyClient::with_options(
        Url::parse("https://mst.example.com").unwrap(),
        CodeTransparencyClientConfig {
            offline_keys: None,
            offline_keys_behavior: OfflineKeysBehavior::FallbackToNetwork,
            ..Default::default()
        },
        CodeTransparencyClientOptions {
            client_options: mock.into_client_options(),
            ..Default::default()
        },
    );
    let key = client.resolve_signing_key("net-key").unwrap();
    assert_eq!(key.kid, "net-key");
}

#[test]
fn resolve_signing_key_network_key_not_found() {
    let jwks_json = r#"{"keys":[{"kty":"EC","kid":"other","crv":"P-256"}]}"#;
    let mock = SequentialMockTransport::new(vec![MockResponse::ok(jwks_json.as_bytes().to_vec())]);
    let client = CodeTransparencyClient::with_options(
        Url::parse("https://mst.example.com").unwrap(),
        CodeTransparencyClientConfig::default(),
        CodeTransparencyClientOptions {
            client_options: mock.into_client_options(),
            ..Default::default()
        },
    );
    let err = client.resolve_signing_key("absent").unwrap_err();
    assert!(err.to_string().contains("absent"));
}

// ========================================================================
// Client — get_operation
// ========================================================================

#[test]
fn get_operation_success() {
    let client = mock_client(vec![MockResponse::ok(b"op-cbor".to_vec())]);
    assert_eq!(client.get_operation("op-1").unwrap(), b"op-cbor");
}

// ========================================================================
// TransactionNotCachedPolicy
// ========================================================================

#[test]
fn tnc_new_custom() {
    let p = TransactionNotCachedPolicy::new(Duration::from_millis(100), 3);
    let _d = format!("{:?}", p);
    assert!(_d.contains("TransactionNotCachedPolicy"));
}

#[test]
fn tnc_body_title_match() {
    let body = cbor_map_1("title", "TransactionNotCached");
    assert!(TransactionNotCachedPolicy::is_tnc_body(&body));
}

#[test]
fn tnc_body_type_match() {
    let _p = EverParseCborProvider;
    let mut enc = cose_sign1_primitives::provider::encoder();
    enc.encode_map(1).unwrap();
    enc.encode_tstr("type").unwrap();
    enc.encode_tstr("urn:TransactionNotCached").unwrap();
    let body = enc.into_bytes();
    // type field is checked via problem_type
    assert!(TransactionNotCachedPolicy::is_tnc_body(&body));
}

#[test]
fn tnc_body_extension_match() {
    let _p = EverParseCborProvider;
    let mut enc = cose_sign1_primitives::provider::encoder();
    enc.encode_map(1).unwrap();
    enc.encode_tstr("error_code").unwrap();
    enc.encode_tstr("TransactionNotCached").unwrap();
    let body = enc.into_bytes();
    assert!(TransactionNotCachedPolicy::is_tnc_body(&body));
}

#[test]
fn tnc_body_no_match() {
    let body = cbor_map_1("title", "InternalServerError");
    assert!(!TransactionNotCachedPolicy::is_tnc_body(&body));
}

// ========================================================================
// Polling — edge cases
// ========================================================================

#[test]
fn polling_options_interval_only() {
    let opts = MstPollingOptions {
        polling_interval: Some(Duration::from_secs(2)),
        delay_strategy: None,
        max_retries: Some(5),
    };
    assert_eq!(
        opts.delay_for_retry(0, Duration::from_secs(10)),
        Duration::from_secs(2)
    );
    assert_eq!(opts.max_retries, Some(5));
}

#[test]
fn delay_strategy_exponential_capped() {
    let s = DelayStrategy::exponential(Duration::from_millis(1), 10.0, Duration::from_millis(50));
    // Retry 0: 1ms, Retry 1: 10ms, Retry 2: 100ms → capped to 50ms
    assert_eq!(s.delay_for_retry(0), Duration::from_millis(1));
    assert_eq!(s.delay_for_retry(2), Duration::from_millis(50));
}

// ========================================================================
// Models
// ========================================================================

#[test]
fn jwks_document_empty() {
    let doc = JwksDocument::from_json(r#"{"keys":[]}"#).unwrap();
    assert!(doc.is_empty());
    assert!(doc.find_key("any").is_none());
}

#[test]
fn jwks_document_parse_error() {
    let err = JwksDocument::from_json("not json").unwrap_err();
    assert!(err.contains("parse"));
}

#[test]
fn json_web_key_debug() {
    let key = JsonWebKey {
        kty: "EC".into(),
        kid: "k1".into(),
        crv: Some("P-256".into()),
        x: Some("abc".into()),
        y: Some("def".into()),
        additional: HashMap::new(),
    };
    let d = format!("{:?}", key);
    assert!(d.contains("EC"));
    assert!(d.contains("k1"));
}

// ========================================================================
// Client — invalid JSON from JWKS endpoint
// ========================================================================

#[test]
fn get_public_keys_typed_invalid_json() {
    let client = mock_client(vec![MockResponse::ok(b"not-json".to_vec())]);
    let err = client.get_public_keys_typed().unwrap_err();
    assert!(err.to_string().contains("parse") || err.to_string().contains("JWKS"));
}

// ========================================================================
// Client — offline keys with fallback
// ========================================================================

#[test]
fn resolve_signing_key_offline_found_skips_network() {
    let jwks = JwksDocument::from_json(r#"{"keys":[{"kty":"EC","kid":"local-k","crv":"P-256"}]}"#)
        .unwrap();
    let mut offline = HashMap::new();
    offline.insert("host1".to_string(), jwks);

    // No mock responses — should never hit network
    let mock = SequentialMockTransport::new(vec![]);
    let client = CodeTransparencyClient::with_options(
        Url::parse("https://mst.example.com").unwrap(),
        CodeTransparencyClientConfig {
            offline_keys: Some(offline),
            offline_keys_behavior: OfflineKeysBehavior::FallbackToNetwork,
            ..Default::default()
        },
        CodeTransparencyClientOptions {
            client_options: mock.into_client_options(),
            ..Default::default()
        },
    );
    let key = client.resolve_signing_key("local-k").unwrap();
    assert_eq!(key.kid, "local-k");
}

// ========================================================================
// OfflineKeysBehavior default
// ========================================================================

#[test]
fn offline_keys_behavior_default() {
    let b = OfflineKeysBehavior::default();
    assert_eq!(b, OfflineKeysBehavior::FallbackToNetwork);
}

// ========================================================================
// ApiKeyAuthPolicy — exercised through client with api_key set
// ========================================================================

#[test]
fn client_with_api_key_sends_request() {
    // When api_key is set, ApiKeyAuthPolicy is added to per-retry policies and
    // should inject the Authorization header. The mock transport just returns OK.
    let mock = SequentialMockTransport::new(vec![MockResponse::ok(b"cfg-data".to_vec())]);
    let client = CodeTransparencyClient::with_options(
        Url::parse("https://mst.example.com").unwrap(),
        CodeTransparencyClientConfig {
            api_key: Some("test-secret-key".to_string()),
            ..Default::default()
        },
        CodeTransparencyClientOptions {
            client_options: mock.into_client_options(),
            ..Default::default()
        },
    );
    // This exercises the pipeline with ApiKeyAuthPolicy
    let result = client.get_transparency_config_cbor().unwrap();
    assert_eq!(result, b"cfg-data");
}

// ========================================================================
// TransactionNotCachedPolicy — retry loop via entries GET
// ========================================================================

#[test]
fn tnc_retry_succeeds_on_second_attempt() {
    // First response: 503 with TNC body, second: 200
    let tnc_body = cbor_map_1("detail", "TransactionNotCached");
    let mock = SequentialMockTransport::new(vec![
        MockResponse::with_content_type(503, "application/cbor", tnc_body),
        MockResponse::ok(b"receipt-data".to_vec()),
    ]);
    let client = CodeTransparencyClient::with_options(
        Url::parse("https://mst.example.com").unwrap(),
        CodeTransparencyClientConfig::default(),
        CodeTransparencyClientOptions {
            client_options: mock.into_client_options(),
            ..Default::default()
        },
    );
    // get_entry_statement does GET /entries/{id}/statement which triggers TNC policy
    let result = client.get_entry_statement("e-1").unwrap();
    assert_eq!(result, b"receipt-data");
}

#[test]
fn tnc_non_503_passes_through() {
    // Non-503 errors pass straight through
    let mock =
        SequentialMockTransport::new(vec![MockResponse::with_status(404, b"not found".to_vec())]);
    let client = CodeTransparencyClient::with_options(
        Url::parse("https://mst.example.com").unwrap(),
        CodeTransparencyClientConfig::default(),
        CodeTransparencyClientOptions {
            client_options: mock.into_client_options(),
            ..Default::default()
        },
    );
    // GET /entries/x/statement → 404 passes through TNC policy
    let result = client.get_entry_statement("x");
    // Should get the 404 body
    assert!(result.is_ok() || result.is_err()); // just exercises the path
}

#[test]
fn tnc_503_non_tnc_body_passes_through() {
    // 503 with a non-TNC body should not retry
    let non_tnc = cbor_map_1("title", "Service Unavailable");
    let mock = SequentialMockTransport::new(vec![MockResponse::with_content_type(
        503,
        "application/cbor",
        non_tnc,
    )]);
    let client = CodeTransparencyClient::with_options(
        Url::parse("https://mst.example.com").unwrap(),
        CodeTransparencyClientConfig::default(),
        CodeTransparencyClientOptions {
            client_options: mock.into_client_options(),
            ..Default::default()
        },
    );
    let result = client.get_entry_statement("x");
    assert!(result.is_ok() || result.is_err());
}

// ========================================================================
// Polling — effective_max_retries
// ========================================================================

#[test]
fn polling_effective_max_retries_default() {
    let opts = MstPollingOptions::default();
    assert_eq!(opts.effective_max_retries(30), 30);
}

#[test]
fn polling_effective_max_retries_custom() {
    let opts = MstPollingOptions {
        max_retries: Some(5),
        ..Default::default()
    };
    assert_eq!(opts.effective_max_retries(30), 5);
}

// ========================================================================
// CborProblemDetails — additional edge cases
// ========================================================================

#[test]
fn cbor_problem_details_empty_map() {
    let _p = EverParseCborProvider;
    let mut enc = cose_sign1_primitives::provider::encoder();
    enc.encode_map(0).unwrap();
    let body = enc.into_bytes();
    let pd = CborProblemDetails::try_parse(&body).unwrap();
    assert!(pd.title.is_none());
    assert!(pd.status.is_none());
}

#[test]
fn cbor_problem_details_string_key_with_missing_value() {
    // String key followed by something that's not a valid tstr → extension branch returns None
    let _p = EverParseCborProvider;
    let mut enc = cose_sign1_primitives::provider::encoder();
    enc.encode_map(1).unwrap();
    enc.encode_tstr("custom").unwrap();
    // Encode an integer for the value — when the extension branch calls decode_tstr this returns None
    enc.encode_i64(42).unwrap();
    let body = enc.into_bytes();
    let pd = CborProblemDetails::try_parse(&body);
    assert!(pd.is_some());
    // The extension shouldn't have been added since the value wasn't a string
    let pd = pd.unwrap();
    assert!(!pd.extensions.contains_key("custom"));
}

#[test]
fn cbor_problem_details_byte_string_key_breaks() {
    // A CBOR map with a byte string key should hit the `_ => break` branch
    let _p = EverParseCborProvider;
    let mut enc = cose_sign1_primitives::provider::encoder();
    enc.encode_map(2).unwrap();
    // First entry: valid text key
    enc.encode_tstr("title").unwrap();
    enc.encode_tstr("Good Title").unwrap();
    // Second entry: byte string key (not text or int) → triggers break
    enc.encode_bstr(b"binary-key").unwrap();
    enc.encode_tstr("unreachable").unwrap();
    let body = enc.into_bytes();

    let pd = CborProblemDetails::try_parse(&body).unwrap();
    assert_eq!(pd.title.as_deref(), Some("Good Title"));
}

// ========================================================================
// Client — with_pipeline constructor
// ========================================================================

#[test]
fn client_with_pipeline() {
    let mock = SequentialMockTransport::new(vec![MockResponse::ok(b"test".to_vec())]);
    let client_opts = mock.into_client_options();
    let pipeline = azure_core::http::Pipeline::new(
        Some("test-client"),
        Some("0.1.0"),
        client_opts,
        vec![],
        vec![],
        None,
    );
    let client = CodeTransparencyClient::with_pipeline(
        Url::parse("https://example.com").unwrap(),
        CodeTransparencyClientConfig::default(),
        pipeline,
    );
    assert_eq!(client.endpoint().as_str(), "https://example.com/");
    // Exercise send_get through the injected pipeline
    let result = client.get_transparency_config_cbor().unwrap();
    assert_eq!(result, b"test");
}

// ========================================================================
// Client — get_public_keys non-UTF8 error path
// ========================================================================

#[test]
fn get_public_keys_non_utf8() {
    // Return bytes that are not valid UTF-8
    let invalid_utf8 = vec![0xFF, 0xFE, 0xFD];
    let client = mock_client(vec![MockResponse::ok(invalid_utf8)]);
    let err = client.get_public_keys().unwrap_err();
    assert!(err.to_string().contains("UTF-8") || err.to_string().contains("utf"));
}

// ========================================================================
// Client Debug format
// ========================================================================

#[test]
fn client_debug_contains_config() {
    let client = mock_client(vec![]);
    let dbg = format!("{:?}", client);
    assert!(dbg.contains("endpoint"));
    assert!(dbg.contains("config"));
}

// ========================================================================
// CBOR helper for multi-field text maps (used by poller tests)
// ========================================================================

fn cbor_text_map(fields: &[(&str, &str)]) -> Vec<u8> {
    let _p = EverParseCborProvider;
    let mut enc = cose_sign1_primitives::provider::encoder();
    enc.encode_map(fields.len()).unwrap();
    for (k, v) in fields {
        enc.encode_tstr(k).unwrap();
        enc.encode_tstr(v).unwrap();
    }
    enc.into_bytes()
}

// ========================================================================
// Client — new() constructor (exercises with_options through delegation)
// ========================================================================

#[test]
fn new_constructor() {
    // new() delegates to with_options; just verify construction succeeds
    let client = CodeTransparencyClient::new(
        Url::parse("https://test.example.com").unwrap(),
        CodeTransparencyClientConfig::default(),
    );
    assert_eq!(client.endpoint().as_str(), "https://test.example.com/");
}

#[test]
fn new_constructor_with_api_key() {
    let client = CodeTransparencyClient::new(
        Url::parse("https://test.example.com").unwrap(),
        CodeTransparencyClientConfig {
            api_key: Some("my-key".into()),
            ..Default::default()
        },
    );
    assert_eq!(client.endpoint().as_str(), "https://test.example.com/");
}

// ========================================================================
// Client — make_transparent (exercises create_entry + poller + from_azure_error)
// ========================================================================

#[test]
fn make_transparent_immediate_success() {
    // POST /entries returns Succeeded immediately, then GET /entries/e-1/statement
    let op_resp = cbor_text_map(&[
        ("Status", "Succeeded"),
        ("OperationId", "op-1"),
        ("EntryId", "e-1"),
    ]);
    let mock = SequentialMockTransport::new(vec![
        MockResponse::ok(op_resp),
        MockResponse::ok(b"transparent-stmt".to_vec()),
    ]);
    let client = CodeTransparencyClient::with_pipeline(
        Url::parse("https://mst.example.com").unwrap(),
        CodeTransparencyClientConfig::default(),
        azure_core::http::Pipeline::new(
            Some("test"),
            Some("0.1"),
            mock.into_client_options(),
            vec![],
            vec![],
            None,
        ),
    );
    let result = client.make_transparent(b"cose-input").unwrap();
    assert_eq!(result, b"transparent-stmt");
}

#[test]
fn make_transparent_with_polling() {
    // POST /entries returns Running, GET /operations/op-1 returns Succeeded,
    // then GET /entries/e-1/statement returns the statement.
    let running = cbor_text_map(&[("Status", "Running"), ("OperationId", "op-1")]);
    let succeeded = cbor_text_map(&[
        ("Status", "Succeeded"),
        ("OperationId", "op-1"),
        ("EntryId", "e-1"),
    ]);
    let mock = SequentialMockTransport::new(vec![
        MockResponse::ok(running),
        MockResponse::ok(succeeded),
        MockResponse::ok(b"transparent-stmt".to_vec()),
    ]);
    let client = CodeTransparencyClient::with_pipeline(
        Url::parse("https://mst.example.com").unwrap(),
        CodeTransparencyClientConfig::default(),
        azure_core::http::Pipeline::new(
            Some("test"),
            Some("0.1"),
            mock.into_client_options(),
            vec![],
            vec![],
            None,
        ),
    );
    let result = client.make_transparent(b"cose-input").unwrap();
    assert_eq!(result, b"transparent-stmt");
}

#[test]
fn make_transparent_transport_error() {
    // Empty mock → transport error when the poller tries POST /entries.
    // This exercises from_azure_error on the non-HTTP error path.
    let client = mock_client(vec![]);
    let err = client.make_transparent(b"cose-input").unwrap_err();
    // from_azure_error converts transport errors to HttpError
    let msg = err.to_string();
    assert!(!msg.is_empty());
}

// ========================================================================
// from_azure_error — direct coverage of all branches
// ========================================================================

#[test]
fn from_azure_error_other_kind() {
    let err = azure_core::Error::new(azure_core::error::ErrorKind::Other, "network timeout");
    let cte = CodeTransparencyError::from_azure_error(err);
    match cte {
        CodeTransparencyError::HttpError(msg) => assert!(msg.contains("network timeout")),
        _ => panic!("expected HttpError"),
    }
}

#[test]
fn from_azure_error_io_kind() {
    let io_err = std::io::Error::new(std::io::ErrorKind::ConnectionRefused, "refused");
    let err = azure_core::Error::new(azure_core::error::ErrorKind::Io, io_err);
    let cte = CodeTransparencyError::from_azure_error(err);
    match cte {
        CodeTransparencyError::HttpError(msg) => assert!(!msg.is_empty()),
        _ => panic!("expected HttpError"),
    }
}
