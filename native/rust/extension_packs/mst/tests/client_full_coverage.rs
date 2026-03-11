// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Tests for MstTransparencyClient with full mock coverage.

use cose_sign1_transparent_mst::http_client::{HttpTransport, MockHttpTransport};
use cose_sign1_transparent_mst::signing::{
    MstClientError, MstTransparencyClient, MstTransparencyClientOptions
};
use cbor_primitives::{CborEncoder, CborProvider};
use cbor_primitives_everparse::{EverparseCborEncoder, EverParseCborProvider};
use std::time::Duration;
use url::Url;
use std::sync::Arc;

fn create_mock_cbor_map(fields: Vec<(&str, &str)>) -> Vec<u8> {
    let provider = EverParseCborProvider;
    let mut enc = provider.encoder();
    enc.encode_map(fields.len()).unwrap();
    for (key, value) in fields {
        enc.encode_tstr(key).unwrap();
        enc.encode_tstr(value).unwrap();
    }
    enc.into_bytes()
}

#[test]
fn test_mst_transparency_client_options_default() {
    let options = MstTransparencyClientOptions::default();
    assert_eq!(options.api_version, "2024-01-01");
    assert!(options.api_key.is_none());
    assert_eq!(options.max_poll_retries, 30);
    assert_eq!(options.poll_delay, Duration::from_secs(2));
}

#[test]
fn test_mst_transparency_client_new() {
    let endpoint = Url::parse("https://transparency.example.com").unwrap();
    let options = MstTransparencyClientOptions::default();
    let client = MstTransparencyClient::new(endpoint, options);
    
    // Just verify it can be constructed
    assert!(format!("{:?}", client).contains("MstTransparencyClient"));
}

#[test]
fn test_mst_transparency_client_with_http() {
    let endpoint = Url::parse("https://transparency.example.com").unwrap();
    let options = MstTransparencyClientOptions::default();
    let mock_http = Arc::new(MockHttpTransport::new());
    
    let client = MstTransparencyClient::with_http(endpoint, options, mock_http.clone());
    
    // Just verify it can be constructed
    assert!(format!("{:?}", client).contains("MstTransparencyClient"));
}

#[test]
fn test_create_entry_success() {
    let endpoint = Url::parse("https://transparency.example.com").unwrap();
    let options = MstTransparencyClientOptions::default();
    let mut mock_http = MockHttpTransport::new();
    
    // Mock POST response for create entry
    let post_response_body = create_mock_cbor_map(vec![("OperationId", "op-123")]);
    mock_http.post_responses.insert(
        "https://transparency.example.com/entries?api-version=2024-01-01".to_string(),
        Ok((202, None, post_response_body))
    );
    
    // Mock GET responses for polling (first in progress, then success)
    let poll_in_progress = create_mock_cbor_map(vec![("Status", "Running")]);
    let poll_success = create_mock_cbor_map(vec![("Status", "Succeeded"), ("EntryId", "entry-456")]);
    
    mock_http.get_responses.insert(
        "https://transparency.example.com/operations/op-123?api-version=2024-01-01".to_string(),
        Ok(poll_success)
    );
    
    let client = MstTransparencyClient::with_http(endpoint, options, Arc::new(mock_http));
    let cose_bytes = b"mock cose data";
    
    let result = client.create_entry(cose_bytes).unwrap();
    assert_eq!(result.operation_id, "op-123");
    assert_eq!(result.entry_id, "entry-456");
}

#[test]
fn test_create_entry_http_error() {
    let endpoint = Url::parse("https://transparency.example.com").unwrap();
    let options = MstTransparencyClientOptions::default();
    let mut mock_http = MockHttpTransport::new();
    
    // Mock POST error
    mock_http.post_responses.insert(
        "https://transparency.example.com/entries?api-version=2024-01-01".to_string(),
        Err("Network error".to_string())
    );
    
    let client = MstTransparencyClient::with_http(endpoint, options, Arc::new(mock_http));
    let cose_bytes = b"mock cose data";
    
    let result = client.create_entry(cose_bytes);
    assert!(matches!(result, Err(MstClientError::HttpError(_))));
}

#[test]
fn test_create_entry_http_status_error() {
    let endpoint = Url::parse("https://transparency.example.com").unwrap();
    let options = MstTransparencyClientOptions::default();
    let mut mock_http = MockHttpTransport::new();
    
    // Mock POST with error status
    mock_http.post_responses.insert(
        "https://transparency.example.com/entries?api-version=2024-01-01".to_string(),
        Ok((500, None, b"Internal Server Error".to_vec()))
    );
    
    let client = MstTransparencyClient::with_http(endpoint, options, Arc::new(mock_http));
    let cose_bytes = b"mock cose data";
    
    let result = client.create_entry(cose_bytes);
    assert!(matches!(result, Err(MstClientError::ServiceError { http_status: 500, .. })));
}

#[test]
fn test_create_entry_missing_operation_id() {
    let endpoint = Url::parse("https://transparency.example.com").unwrap();
    let options = MstTransparencyClientOptions::default();
    let mut mock_http = MockHttpTransport::new();
    
    // Mock POST response without OperationId
    let post_response_body = create_mock_cbor_map(vec![("Status", "Created")]);
    mock_http.post_responses.insert(
        "https://transparency.example.com/entries?api-version=2024-01-01".to_string(),
        Ok((202, None, post_response_body))
    );
    
    let client = MstTransparencyClient::with_http(endpoint, options, Arc::new(mock_http));
    let cose_bytes = b"mock cose data";
    
    let result = client.create_entry(cose_bytes);
    assert!(matches!(result, Err(MstClientError::MissingField { field }) if field == "OperationId"));
}

#[test]
fn test_poll_operation_timeout() {
    let endpoint = Url::parse("https://transparency.example.com").unwrap();
    let mut options = MstTransparencyClientOptions::default();
    options.max_poll_retries = 2; // Set low for faster test
    options.poll_delay = Duration::from_millis(10); // Short delay
    
    let mut mock_http = MockHttpTransport::new();
    
    // Mock POST response
    let post_response_body = create_mock_cbor_map(vec![("OperationId", "op-timeout")]);
    mock_http.post_responses.insert(
        "https://transparency.example.com/entries?api-version=2024-01-01".to_string(),
        Ok((202, None, post_response_body))
    );
    
    // Mock GET responses that never complete
    let poll_running = create_mock_cbor_map(vec![("Status", "Running")]);
    mock_http.get_responses.insert(
        "https://transparency.example.com/operations/op-timeout?api-version=2024-01-01".to_string(),
        Ok(poll_running)
    );
    
    let client = MstTransparencyClient::with_http(endpoint, options, Arc::new(mock_http));
    let cose_bytes = b"mock cose data";
    
    let result = client.create_entry(cose_bytes);
    assert!(matches!(result, Err(MstClientError::OperationTimeout { operation_id, retries }) 
                    if operation_id == "op-timeout" && retries == 2));
}

#[test]
fn test_poll_operation_failed() {
    let endpoint = Url::parse("https://transparency.example.com").unwrap();
    let options = MstTransparencyClientOptions::default();
    let mut mock_http = MockHttpTransport::new();
    
    // Mock POST response
    let post_response_body = create_mock_cbor_map(vec![("OperationId", "op-failed")]);
    mock_http.post_responses.insert(
        "https://transparency.example.com/entries?api-version=2024-01-01".to_string(),
        Ok((202, None, post_response_body))
    );
    
    // Mock GET response with failed status
    let poll_failed = create_mock_cbor_map(vec![("Status", "Failed")]);
    mock_http.get_responses.insert(
        "https://transparency.example.com/operations/op-failed?api-version=2024-01-01".to_string(),
        Ok(poll_failed)
    );
    
    let client = MstTransparencyClient::with_http(endpoint, options, Arc::new(mock_http));
    let cose_bytes = b"mock cose data";
    
    let result = client.create_entry(cose_bytes);
    assert!(matches!(result, Err(MstClientError::OperationFailed { operation_id, status }) 
                    if operation_id == "op-failed" && status == "Failed"));
}

#[test]
fn test_get_entry_statement_success() {
    let endpoint = Url::parse("https://transparency.example.com").unwrap();
    let options = MstTransparencyClientOptions::default();
    let mut mock_http = MockHttpTransport::new();
    
    let expected_statement = b"mock statement data";
    mock_http.get_responses.insert(
        "https://transparency.example.com/entries/entry-123/statement?api-version=2024-01-01".to_string(),
        Ok(expected_statement.to_vec())
    );
    
    let client = MstTransparencyClient::with_http(endpoint, options, Arc::new(mock_http));
    
    let result = client.get_entry_statement("entry-123").unwrap();
    assert_eq!(result, expected_statement);
}

#[test]
fn test_get_entry_statement_error() {
    let endpoint = Url::parse("https://transparency.example.com").unwrap();
    let options = MstTransparencyClientOptions::default();
    let mut mock_http = MockHttpTransport::new();
    
    mock_http.get_responses.insert(
        "https://transparency.example.com/entries/entry-404/statement?api-version=2024-01-01".to_string(),
        Err("Not found".to_string())
    );
    
    let client = MstTransparencyClient::with_http(endpoint, options, Arc::new(mock_http));
    
    let result = client.get_entry_statement("entry-404");
    assert!(matches!(result, Err(MstClientError::HttpError(_))));
}

#[test]
fn test_make_transparent_success() {
    let endpoint = Url::parse("https://transparency.example.com").unwrap();
    let options = MstTransparencyClientOptions::default();
    let mut mock_http = MockHttpTransport::new();
    
    // Mock POST response
    let post_response_body = create_mock_cbor_map(vec![("OperationId", "op-transparent")]);
    mock_http.post_responses.insert(
        "https://transparency.example.com/entries?api-version=2024-01-01".to_string(),
        Ok((202, None, post_response_body))
    );
    
    // Mock GET response for polling
    let poll_success = create_mock_cbor_map(vec![("Status", "Succeeded"), ("EntryId", "entry-transparent")]);
    mock_http.get_responses.insert(
        "https://transparency.example.com/operations/op-transparent?api-version=2024-01-01".to_string(),
        Ok(poll_success)
    );
    
    // Mock GET response for statement
    let expected_statement = b"transparent statement";
    mock_http.get_responses.insert(
        "https://transparency.example.com/entries/entry-transparent/statement?api-version=2024-01-01".to_string(),
        Ok(expected_statement.to_vec())
    );
    
    let client = MstTransparencyClient::with_http(endpoint, options, Arc::new(mock_http));
    let cose_bytes = b"mock cose data";
    
    let result = client.make_transparent(cose_bytes).unwrap();
    assert_eq!(result, expected_statement);
}

#[test]
fn test_mst_client_error_display() {
    let errors = vec![
        MstClientError::HttpError("Network failed".to_string()),
        MstClientError::CborParseError("Invalid CBOR".to_string()),
        MstClientError::OperationTimeout { operation_id: "op-123".to_string(), retries: 10 },
        MstClientError::OperationFailed { operation_id: "op-456".to_string(), status: "Failed".to_string() },
        MstClientError::MissingField { field: "EntryId".to_string() },
    ];
    
    let expected = vec![
        "HTTP error: Network failed",
        "CBOR parse error: Invalid CBOR", 
        "Operation op-123 timed out after 10 retries",
        "Operation op-456 failed with status: Failed",
        "Missing required field: EntryId",
    ];
    
    for (error, expected_msg) in errors.iter().zip(expected.iter()) {
        assert_eq!(error.to_string(), *expected_msg);
    }
}

#[test]
fn test_mst_client_error_is_std_error() {
    let error = MstClientError::HttpError("test".to_string());
    let _: &dyn std::error::Error = &error;
}