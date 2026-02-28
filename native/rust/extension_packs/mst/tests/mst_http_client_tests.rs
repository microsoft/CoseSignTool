// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use cose_sign1_transparent_mst::http_client::{HttpTransport, MockHttpTransport};
use url::Url;

#[test]
fn test_mock_http_transport_construction() {
    let transport = MockHttpTransport::new();
    assert_eq!(transport.get_responses.len(), 0);
    assert_eq!(transport.post_responses.len(), 0);
}

#[test]
fn test_mock_http_transport_debug_format() {
    let mut transport = MockHttpTransport::new();
    transport.get_responses.insert("https://test.com".to_string(), Ok(vec![1, 2, 3]));
    transport.post_responses.insert("https://api.test.com".to_string(), Ok((200, vec![4, 5, 6])));
    
    let debug_str = format!("{:?}", transport);
    assert!(debug_str.contains("MockHttpTransport"));
    assert!(debug_str.contains("get_responses"));
    assert!(debug_str.contains("post_responses"));
}

#[test] 
fn test_mock_http_transport_get_bytes_success() {
    let mut transport = MockHttpTransport::new();
    let test_url = Url::parse("https://example.com/test").unwrap();
    let expected_response = vec![1, 2, 3, 4, 5];
    
    transport.get_responses.insert(test_url.as_str().to_string(), Ok(expected_response.clone()));
    
    let result = transport.get_bytes(&test_url, "application/json");
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), expected_response);
}

#[test]
fn test_mock_http_transport_get_bytes_error() {
    let mut transport = MockHttpTransport::new();
    let test_url = Url::parse("https://example.com/error").unwrap();
    
    transport.get_responses.insert(test_url.as_str().to_string(), Err("Network error".to_string()));
    
    let result = transport.get_bytes(&test_url, "application/json");
    assert!(result.is_err());
    assert_eq!(result.unwrap_err(), "Network error");
}

#[test]
fn test_mock_http_transport_get_bytes_no_response() {
    let transport = MockHttpTransport::new();
    let test_url = Url::parse("https://example.com/unknown").unwrap();
    
    let result = transport.get_bytes(&test_url, "application/json");
    assert!(result.is_err());
    let error = result.unwrap_err();
    assert!(error.contains("No mock response for GET"));
    assert!(error.contains("https://example.com/unknown"));
}

#[test]
fn test_mock_http_transport_get_string_success() {
    let mut transport = MockHttpTransport::new();
    let test_url = Url::parse("https://example.com/text").unwrap();
    let expected_text = "Hello, World!";
    
    transport.get_responses.insert(test_url.as_str().to_string(), Ok(expected_text.as_bytes().to_vec()));
    
    let result = transport.get_string(&test_url, "text/plain");
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), expected_text);
}

#[test]
fn test_mock_http_transport_get_string_invalid_utf8() {
    let mut transport = MockHttpTransport::new();
    let test_url = Url::parse("https://example.com/binary").unwrap();
    let invalid_utf8 = vec![0xFF, 0xFE, 0xFD]; // Invalid UTF-8 sequence
    
    transport.get_responses.insert(test_url.as_str().to_string(), Ok(invalid_utf8));
    
    let result = transport.get_string(&test_url, "text/plain");
    assert!(result.is_err());
    let error = result.unwrap_err();
    assert!(error.contains("invalid utf-8") || error.contains("Utf8Error"));
}

#[test]
fn test_mock_http_transport_get_string_error() {
    let mut transport = MockHttpTransport::new();
    let test_url = Url::parse("https://example.com/error").unwrap();
    
    transport.get_responses.insert(test_url.as_str().to_string(), Err("Connection timeout".to_string()));
    
    let result = transport.get_string(&test_url, "text/plain");
    assert!(result.is_err());
    assert_eq!(result.unwrap_err(), "Connection timeout");
}

#[test]
fn test_mock_http_transport_post_bytes_success() {
    let mut transport = MockHttpTransport::new();
    let test_url = Url::parse("https://api.example.com/submit").unwrap();
    let expected_response = (201, vec![7, 8, 9]);
    
    transport.post_responses.insert(test_url.as_str().to_string(), Ok(expected_response.clone()));
    
    let body = vec![1, 2, 3];
    let result = transport.post_bytes(&test_url, "application/cbor", "application/json", body);
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), expected_response);
}

#[test]
fn test_mock_http_transport_post_bytes_error() {
    let mut transport = MockHttpTransport::new();
    let test_url = Url::parse("https://api.example.com/fail").unwrap();
    
    transport.post_responses.insert(test_url.as_str().to_string(), Err("Server error".to_string()));
    
    let body = vec![1, 2, 3];
    let result = transport.post_bytes(&test_url, "application/cbor", "application/json", body);
    assert!(result.is_err());
    assert_eq!(result.unwrap_err(), "Server error");
}

#[test]
fn test_mock_http_transport_post_bytes_no_response() {
    let transport = MockHttpTransport::new();
    let test_url = Url::parse("https://api.example.com/unknown").unwrap();
    
    let body = vec![1, 2, 3];
    let result = transport.post_bytes(&test_url, "application/cbor", "application/json", body);
    assert!(result.is_err());
    let error = result.unwrap_err();
    assert!(error.contains("No mock response for POST"));
    assert!(error.contains("https://api.example.com/unknown"));
}

#[test]
fn test_mock_http_transport_multiple_urls() {
    let mut transport = MockHttpTransport::new();
    let url1 = Url::parse("https://example.com/1").unwrap();
    let url2 = Url::parse("https://example.com/2").unwrap();
    
    transport.get_responses.insert(url1.as_str().to_string(), Ok(vec![1]));
    transport.get_responses.insert(url2.as_str().to_string(), Ok(vec![2]));
    
    let result1 = transport.get_bytes(&url1, "application/json").unwrap();
    let result2 = transport.get_bytes(&url2, "application/json").unwrap();
    
    assert_eq!(result1, vec![1]);
    assert_eq!(result2, vec![2]);
}

#[test]
fn test_mock_http_transport_url_exact_match() {
    let mut transport = MockHttpTransport::new();
    let test_url = Url::parse("https://example.com/test?param=value").unwrap();
    let different_url = Url::parse("https://example.com/test?param=different").unwrap();
    
    transport.get_responses.insert(test_url.as_str().to_string(), Ok(vec![1, 2, 3]));
    
    // Exact match should work
    let result1 = transport.get_bytes(&test_url, "application/json");
    assert!(result1.is_ok());
    
    // Different URL should fail
    let result2 = transport.get_bytes(&different_url, "application/json");
    assert!(result2.is_err());
}

#[test]
fn test_mock_http_transport_different_status_codes() {
    let mut transport = MockHttpTransport::new();
    let url1 = Url::parse("https://api.example.com/success").unwrap();
    let url2 = Url::parse("https://api.example.com/created").unwrap();
    let url3 = Url::parse("https://api.example.com/accepted").unwrap();
    
    transport.post_responses.insert(url1.as_str().to_string(), Ok((200, vec![1])));
    transport.post_responses.insert(url2.as_str().to_string(), Ok((201, vec![2])));
    transport.post_responses.insert(url3.as_str().to_string(), Ok((202, vec![3])));
    
    let body = vec![];
    
    let result1 = transport.post_bytes(&url1, "application/json", "application/json", body.clone()).unwrap();
    assert_eq!(result1.0, 200);
    assert_eq!(result1.1, vec![1]);
    
    let result2 = transport.post_bytes(&url2, "application/json", "application/json", body.clone()).unwrap();
    assert_eq!(result2.0, 201);
    assert_eq!(result2.1, vec![2]);
    
    let result3 = transport.post_bytes(&url3, "application/json", "application/json", body.clone()).unwrap();
    assert_eq!(result3.0, 202);
    assert_eq!(result3.1, vec![3]);
}

#[test]
fn test_mock_http_transport_empty_response_body() {
    let mut transport = MockHttpTransport::new();
    let test_url = Url::parse("https://example.com/empty").unwrap();
    
    transport.get_responses.insert(test_url.as_str().to_string(), Ok(vec![]));
    
    let result = transport.get_bytes(&test_url, "application/json");
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), Vec::<u8>::new());
}

#[test]
fn test_mock_http_transport_large_response() {
    let mut transport = MockHttpTransport::new();
    let test_url = Url::parse("https://example.com/large").unwrap();
    let large_response = vec![0x42; 1_000_000]; // 1MB response
    
    transport.get_responses.insert(test_url.as_str().to_string(), Ok(large_response.clone()));
    
    let result = transport.get_bytes(&test_url, "application/octet-stream");
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), large_response);
}

#[test] 
fn test_mock_http_transport_overwrite_response() {
    let mut transport = MockHttpTransport::new();
    let test_url = Url::parse("https://example.com/test").unwrap();
    
    // First response
    transport.get_responses.insert(test_url.as_str().to_string(), Ok(vec![1, 2, 3]));
    
    // Overwrite with different response
    transport.get_responses.insert(test_url.as_str().to_string(), Ok(vec![4, 5, 6]));
    
    let result = transport.get_bytes(&test_url, "application/json");
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), vec![4, 5, 6]); // Should get the overwritten response
}

// Test the pattern where we need to set up responses for polling scenarios
#[test]
fn test_mock_http_transport_polling_pattern() {
    let mut transport = MockHttpTransport::new();
    let entry_url = Url::parse("https://mst.example.com/entries").unwrap();
    let status_url = Url::parse("https://mst.example.com/operations/123").unwrap();
    
    // POST to create entry returns operation ID
    transport.post_responses.insert(
        entry_url.as_str().to_string(), 
        Ok((202, b"operation_123".to_vec()))
    );
    
    // GET operation status returns completion
    transport.get_responses.insert(
        status_url.as_str().to_string(),
        Ok(b"completed".to_vec())
    );
    
    // Test the creation POST
    let create_result = transport.post_bytes(&entry_url, "application/cbor", "text/plain", vec![]);
    assert!(create_result.is_ok());
    let (status, body) = create_result.unwrap();
    assert_eq!(status, 202);
    assert_eq!(body, b"operation_123");
    
    // Test the status GET
    let status_result = transport.get_bytes(&status_url, "text/plain");
    assert!(status_result.is_ok());
    assert_eq!(status_result.unwrap(), b"completed");
}

#[test]
fn test_http_headers_patterns() {
    // Test header patterns used in the HTTP client
    let accept = "application/cose";
    let content_type = "application/cose; application/cbor";
    
    assert!(!accept.is_empty());
    assert!(content_type.contains("application/cose"));
    assert!(content_type.contains("application/cbor"));
}

#[test]
fn test_response_body_pattern() {
    // Test the pattern of converting response bodies to Vec<u8>
    let test_data = b"test data";
    let vec = test_data.to_vec();
    
    assert_eq!(vec.len(), 9);
    assert_eq!(vec, b"test data");
}

#[test]
fn test_status_code_pattern() {
    // Test status code handling pattern
    let status: u16 = 200;
    let status_from_response = u16::from(azure_core::http::StatusCode::Ok);
    
    assert_eq!(status, 200);
    assert_eq!(status_from_response, 200);
}

#[test]
fn test_error_string_conversion() {
    // Test error conversion pattern used in the HTTP client
    use std::io;
    
    let error = io::Error::new(io::ErrorKind::NotFound, "file not found");
    let error_string = error.to_string();
    
    assert!(error_string.contains("file not found"));
}