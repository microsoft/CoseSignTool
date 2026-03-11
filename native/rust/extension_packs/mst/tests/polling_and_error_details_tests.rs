// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use cbor_primitives::{CborEncoder, CborDecoder};
use cose_sign1_transparent_mst::signing::cbor_problem_details::CborProblemDetails;
use cose_sign1_transparent_mst::signing::error::MstClientError;
use cose_sign1_transparent_mst::signing::polling::{DelayStrategy, MstPollingOptions};
use cose_sign1_transparent_mst::signing::client::MstTransparencyClientOptions;
use std::time::Duration;

// ============================================================================
// CborProblemDetails tests
// ============================================================================

#[test]
fn cbor_problem_details_try_parse_empty_returns_none() {
    assert!(CborProblemDetails::try_parse(&[]).is_none());
}

#[test]
fn cbor_problem_details_try_parse_invalid_cbor_returns_none() {
    assert!(CborProblemDetails::try_parse(&[0xFF, 0xFF]).is_none());
}

#[test]
fn cbor_problem_details_try_parse_non_map_returns_none() {
    // CBOR unsigned integer 42
    assert!(CborProblemDetails::try_parse(&[0x18, 0x2A]).is_none());
}

#[test]
fn cbor_problem_details_parse_integer_keys() {
    use cbor_primitives_everparse::EverParseCborProvider;
    let _provider = EverParseCborProvider;

    // Build a CBOR map with integer keys per RFC 9290:
    // {-1: "urn:error:bad-request", -2: "Bad Request", -3: 400, -4: "Missing field X"}
    let mut enc = cose_sign1_primitives::provider::encoder();
    enc.encode_map(4).unwrap();
    enc.encode_i64(-1).unwrap();
    enc.encode_tstr("urn:error:bad-request").unwrap();
    enc.encode_i64(-2).unwrap();
    enc.encode_tstr("Bad Request").unwrap();
    enc.encode_i64(-3).unwrap();
    enc.encode_i64(400).unwrap();
    enc.encode_i64(-4).unwrap();
    enc.encode_tstr("Missing field X").unwrap();
    let bytes = enc.into_bytes();

    let pd = CborProblemDetails::try_parse(&bytes).unwrap();
    assert_eq!(pd.problem_type.as_deref(), Some("urn:error:bad-request"));
    assert_eq!(pd.title.as_deref(), Some("Bad Request"));
    assert_eq!(pd.status, Some(400));
    assert_eq!(pd.detail.as_deref(), Some("Missing field X"));
    assert!(pd.instance.is_none());
    assert!(pd.extensions.is_empty());
}

#[test]
fn cbor_problem_details_parse_string_keys() {
    use cbor_primitives_everparse::EverParseCborProvider;
    let _provider = EverParseCborProvider;

    let mut enc = cose_sign1_primitives::provider::encoder();
    enc.encode_map(3).unwrap();
    enc.encode_tstr("title").unwrap();
    enc.encode_tstr("Not Found").unwrap();
    enc.encode_tstr("detail").unwrap();
    enc.encode_tstr("Entry does not exist").unwrap();
    enc.encode_tstr("instance").unwrap();
    enc.encode_tstr("/entries/missing-123").unwrap();
    let bytes = enc.into_bytes();

    let pd = CborProblemDetails::try_parse(&bytes).unwrap();
    assert_eq!(pd.title.as_deref(), Some("Not Found"));
    assert_eq!(pd.detail.as_deref(), Some("Entry does not exist"));
    assert_eq!(pd.instance.as_deref(), Some("/entries/missing-123"));
}

#[test]
fn cbor_problem_details_extensions_captured() {
    use cbor_primitives_everparse::EverParseCborProvider;
    let _provider = EverParseCborProvider;

    let mut enc = cose_sign1_primitives::provider::encoder();
    enc.encode_map(2).unwrap();
    enc.encode_tstr("title").unwrap();
    enc.encode_tstr("Error").unwrap();
    enc.encode_tstr("requestId").unwrap();
    enc.encode_tstr("abc-123").unwrap();
    let bytes = enc.into_bytes();

    let pd = CborProblemDetails::try_parse(&bytes).unwrap();
    assert_eq!(pd.title.as_deref(), Some("Error"));
    assert_eq!(pd.extensions.get("requestId").map(|s| s.as_str()), Some("abc-123"));
}

#[test]
fn cbor_problem_details_display_with_fields() {
    let pd = CborProblemDetails {
        title: Some("Bad Request".into()),
        status: Some(400),
        detail: Some("Missing field".into()),
        ..Default::default()
    };
    let s = format!("{}", pd);
    assert!(s.contains("Bad Request"));
    assert!(s.contains("400"));
    assert!(s.contains("Missing field"));
}

#[test]
fn cbor_problem_details_display_empty() {
    let pd = CborProblemDetails::default();
    assert_eq!(format!("{}", pd), "No details available");
}

// ============================================================================
// MstClientError::ServiceError tests
// ============================================================================

#[test]
fn service_error_from_http_non_cbor() {
    let err = MstClientError::from_http_response(500, Some("text/plain"), b"Server Error");
    match err {
        MstClientError::ServiceError { http_status, problem_details, message } => {
            assert_eq!(http_status, 500);
            assert!(problem_details.is_none());
            assert!(message.contains("500"));
        }
        _ => panic!("Expected ServiceError"),
    }
}

#[test]
fn service_error_from_http_cbor_with_details() {
    use cbor_primitives_everparse::EverParseCborProvider;
    let _provider = EverParseCborProvider;

    let mut enc = cose_sign1_primitives::provider::encoder();
    enc.encode_map(2).unwrap();
    enc.encode_tstr("title").unwrap();
    enc.encode_tstr("Rate Limited").unwrap();
    enc.encode_tstr("detail").unwrap();
    enc.encode_tstr("Too many requests").unwrap();
    let cbor_body = enc.into_bytes();

    let err = MstClientError::from_http_response(
        429,
        Some("application/concise-problem-details+cbor"),
        &cbor_body,
    );
    match err {
        MstClientError::ServiceError { http_status, problem_details, message } => {
            assert_eq!(http_status, 429);
            let pd = problem_details.unwrap();
            assert_eq!(pd.title.as_deref(), Some("Rate Limited"));
            assert_eq!(pd.detail.as_deref(), Some("Too many requests"));
            assert!(message.contains("Rate Limited"));
            assert!(message.contains("Too many requests"));
        }
        _ => panic!("Expected ServiceError"),
    }
}

#[test]
fn service_error_from_http_no_content_type() {
    let err = MstClientError::from_http_response(502, None, b"");
    match err {
        MstClientError::ServiceError { http_status, problem_details, .. } => {
            assert_eq!(http_status, 502);
            assert!(problem_details.is_none());
        }
        _ => panic!("Expected ServiceError"),
    }
}

#[test]
fn service_error_display() {
    let err = MstClientError::from_http_response(400, None, b"");
    let display = format!("{}", err);
    assert!(display.contains("400"));
}

// ============================================================================
// DelayStrategy tests
// ============================================================================

#[test]
fn delay_strategy_fixed() {
    let strategy = DelayStrategy::fixed(Duration::from_millis(500));
    assert_eq!(strategy.delay_for_retry(0), Duration::from_millis(500));
    assert_eq!(strategy.delay_for_retry(5), Duration::from_millis(500));
    assert_eq!(strategy.delay_for_retry(100), Duration::from_millis(500));
}

#[test]
fn delay_strategy_exponential() {
    let strategy = DelayStrategy::exponential(
        Duration::from_millis(100),
        2.0,
        Duration::from_secs(10),
    );
    assert_eq!(strategy.delay_for_retry(0), Duration::from_millis(100));
    assert_eq!(strategy.delay_for_retry(1), Duration::from_millis(200));
    assert_eq!(strategy.delay_for_retry(2), Duration::from_millis(400));
    assert_eq!(strategy.delay_for_retry(3), Duration::from_millis(800));
    // Capped at max
    assert_eq!(strategy.delay_for_retry(20), Duration::from_secs(10));
}

#[test]
fn delay_strategy_exponential_cap_respected() {
    let strategy = DelayStrategy::exponential(
        Duration::from_secs(1),
        3.0,
        Duration::from_secs(5),
    );
    // 1 * 3^3 = 27s → capped at 5s
    assert_eq!(strategy.delay_for_retry(3), Duration::from_secs(5));
}

// ============================================================================
// MstPollingOptions tests
// ============================================================================

#[test]
fn polling_options_default() {
    let opts = MstPollingOptions::default();
    assert!(opts.polling_interval.is_none());
    assert!(opts.delay_strategy.is_none());
    assert!(opts.max_retries.is_none());
}

#[test]
fn polling_options_delay_for_retry_uses_strategy() {
    let opts = MstPollingOptions {
        delay_strategy: Some(DelayStrategy::fixed(Duration::from_millis(250))),
        polling_interval: Some(Duration::from_secs(1)), // ignored when strategy set
        ..Default::default()
    };
    let fallback = Duration::from_secs(5);
    // Strategy takes precedence
    assert_eq!(opts.delay_for_retry(0, fallback), Duration::from_millis(250));
}

#[test]
fn polling_options_delay_for_retry_uses_interval() {
    let opts = MstPollingOptions {
        polling_interval: Some(Duration::from_millis(750)),
        ..Default::default()
    };
    let fallback = Duration::from_secs(5);
    assert_eq!(opts.delay_for_retry(0, fallback), Duration::from_millis(750));
}

#[test]
fn polling_options_delay_for_retry_uses_fallback() {
    let opts = MstPollingOptions::default();
    let fallback = Duration::from_secs(2);
    assert_eq!(opts.delay_for_retry(0, fallback), Duration::from_secs(2));
}

#[test]
fn polling_options_effective_max_retries() {
    let opts = MstPollingOptions {
        max_retries: Some(10),
        ..Default::default()
    };
    assert_eq!(opts.effective_max_retries(30), 10);

    let default_opts = MstPollingOptions::default();
    assert_eq!(default_opts.effective_max_retries(30), 30);
}

// ============================================================================
// MstTransparencyClientOptions with polling_options
// ============================================================================

#[test]
fn client_options_default_has_no_polling_options() {
    let opts = MstTransparencyClientOptions::default();
    assert!(opts.polling_options.is_none());
}

#[test]
fn client_options_with_polling_options() {
    let opts = MstTransparencyClientOptions {
        polling_options: Some(MstPollingOptions {
            delay_strategy: Some(DelayStrategy::exponential(
                Duration::from_millis(200),
                2.0,
                Duration::from_secs(30),
            )),
            max_retries: Some(50),
            ..Default::default()
        }),
        ..MstTransparencyClientOptions::default()
    };
    let po = opts.polling_options.as_ref().unwrap();
    assert_eq!(po.effective_max_retries(30), 50);
    assert_eq!(po.delay_for_retry(0, Duration::from_secs(1)), Duration::from_millis(200));
    assert_eq!(po.delay_for_retry(1, Duration::from_secs(1)), Duration::from_millis(400));
}

// ============================================================================
// Client creates ServiceError on non-2xx POST (integration with mock)
// ============================================================================

#[test]
fn client_returns_service_error_with_cbor_problem_details() {
    use cose_sign1_transparent_mst::http_client::MockHttpTransport;
    use cose_sign1_transparent_mst::signing::client::MstTransparencyClient;
    use std::sync::Arc;

    use cbor_primitives_everparse::EverParseCborProvider;
    let _provider = EverParseCborProvider;

    // Build CBOR problem details body
    let mut enc = cose_sign1_primitives::provider::encoder();
    enc.encode_map(2).unwrap();
    enc.encode_tstr("title").unwrap();
    enc.encode_tstr("Payload Too Large").unwrap();
    enc.encode_tstr("detail").unwrap();
    enc.encode_tstr("Message exceeds 1MB limit").unwrap();
    let cbor_body = enc.into_bytes();

    let mut mock = MockHttpTransport::new();
    let entries_url = "https://mst.example.com/entries?api-version=2024-01-01";
    mock.post_responses.insert(
        entries_url.to_string(),
        Ok((413, Some("application/concise-problem-details+cbor".to_string()), cbor_body)),
    );

    let client = MstTransparencyClient::with_http(
        url::Url::parse("https://mst.example.com").unwrap(),
        MstTransparencyClientOptions::default(),
        Arc::new(mock),
    );

    let result = client.create_entry(b"large-payload");
    match result.unwrap_err() {
        MstClientError::ServiceError { http_status, problem_details, message } => {
            assert_eq!(http_status, 413);
            let pd = problem_details.unwrap();
            assert_eq!(pd.title.as_deref(), Some("Payload Too Large"));
            assert_eq!(pd.detail.as_deref(), Some("Message exceeds 1MB limit"));
            assert!(message.contains("Payload Too Large"));
        }
        other => panic!("Expected ServiceError, got: {:?}", other),
    }
}
