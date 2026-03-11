// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Tests for HTTP transport abstraction.

use azure_core::http::ClientOptions;
use cose_sign1_transparent_mst::http_client::{DefaultHttpTransport, HttpTransport, MockHttpTransport};
use url::Url;

#[test]
fn test_default_http_transport_construction() {
    let transport = DefaultHttpTransport::new();
    // Just verify it can be constructed without panicking
    assert!(format!("{:?}", transport).contains("DefaultHttpTransport"));
}

#[test]
fn test_default_http_transport_with_options() {
    // Test that we can create a transport with custom ClientOptions
    let options = ClientOptions::default();
    let transport = DefaultHttpTransport::with_options(options);
    // Verify it can be constructed without panicking
    assert!(format!("{:?}", transport).contains("DefaultHttpTransport"));
}

#[test]
fn test_default_http_transport_with_custom_options() {
    // Test with ClientOptions (verify custom options path works)
    let options = ClientOptions::default();
    // Verify we can construct with passed options (same as default)
    let transport = DefaultHttpTransport::with_options(options);
    let debug_str = format!("{:?}", transport);
    assert!(debug_str.contains("DefaultHttpTransport"));
    assert!(debug_str.contains("pipeline"));
}

#[test]
fn test_mock_http_transport_get_bytes() {
    let mut mock = MockHttpTransport::new();
    let url = Url::parse("https://example.com/test").unwrap();
    let expected_response = b"test response".to_vec();
    
    mock.get_responses.insert(
        url.to_string(), 
        Ok(expected_response.clone())
    );
    
    let result = mock.get_bytes(&url, "application/json");
    assert_eq!(result.unwrap(), expected_response);
}

#[test]
fn test_mock_http_transport_get_string() {
    let mut mock = MockHttpTransport::new();
    let url = Url::parse("https://example.com/test").unwrap();
    let expected_response = "test response";
    
    mock.get_responses.insert(
        url.to_string(), 
        Ok(expected_response.as_bytes().to_vec())
    );
    
    let result = mock.get_string(&url, "application/json");
    assert_eq!(result.unwrap(), expected_response);
}

#[test]
fn test_mock_http_transport_post_bytes() {
    let mut mock = MockHttpTransport::new();
    let url = Url::parse("https://example.com/test").unwrap();
    let expected_response = (200u16, None::<String>, b"success".to_vec());
    
    mock.post_responses.insert(
        url.to_string(), 
        Ok(expected_response.clone())
    );
    
    let result = mock.post_bytes(&url, "application/json", "application/json", b"request body".to_vec());
    assert_eq!(result.unwrap(), expected_response);
}

#[test]
fn test_mock_http_transport_missing_response() {
    let mock = MockHttpTransport::new();
    let url = Url::parse("https://example.com/missing").unwrap();
    
    let result = mock.get_bytes(&url, "application/json");
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("No mock response for GET"));
}

#[test]
fn test_mock_http_transport_error_response() {
    let mut mock = MockHttpTransport::new();
    let url = Url::parse("https://example.com/error").unwrap();
    
    mock.get_responses.insert(
        url.to_string(), 
        Err("Network error".to_string())
    );
    
    let result = mock.get_bytes(&url, "application/json");
    assert_eq!(result.unwrap_err(), "Network error");
}