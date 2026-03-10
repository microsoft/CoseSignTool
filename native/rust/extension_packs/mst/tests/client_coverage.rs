// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Test coverage for MST client functionality.

use cose_sign1_transparent_mst::signing::{
    client::{MstTransparencyClient, MstTransparencyClientOptions},
    error::MstClientError,
};
use std::time::Duration;
use url::Url;

#[test]
fn test_mst_transparency_client_options_default() {
    let options = MstTransparencyClientOptions::default();
    
    assert_eq!(options.api_version, "2024-01-01");
    assert_eq!(options.api_key, None);
    assert_eq!(options.max_poll_retries, 30);
    assert_eq!(options.poll_delay, Duration::from_secs(2));
}

#[test]
fn test_mst_transparency_client_new() {
    let endpoint = Url::parse("https://example.com").unwrap();
    let options = MstTransparencyClientOptions::default();
    
    let client = MstTransparencyClient::new(endpoint.clone(), options);
    
    // Basic construction should succeed
    // We can't access private fields but we can ensure no panic occurred
    assert!(format!("{:?}", client).contains("MstTransparencyClient"));
}

#[test]
fn test_mst_transparency_client_url_construction() {
    let endpoint = Url::parse("https://example.com/base/").unwrap();
    let options = MstTransparencyClientOptions::default();
    let client = MstTransparencyClient::new(endpoint, options);
    
    // Basic construction should succeed
    // We can't access private fields but we can ensure no panic occurred
    assert!(format!("{:?}", client).contains("MstTransparencyClient"));
    assert!(format!("{:?}", client).contains("example.com"));
}

#[test]
fn test_mst_transparency_client_with_api_key() {
    let endpoint = Url::parse("https://example.com").unwrap();
    let mut options = MstTransparencyClientOptions::default();
    options.api_key = Some("test-api-key".to_string());
    let client = MstTransparencyClient::new(endpoint, options);
    
    // Construction with API key should succeed  
    assert!(format!("{:?}", client).contains("MstTransparencyClient"));
}

#[test]
fn test_mst_transparency_client_custom_options() {
    let endpoint = Url::parse("https://example.com").unwrap();
    let mut options = MstTransparencyClientOptions::default();
    options.api_version = "2023-01-01".to_string();
    options.max_poll_retries = 5;
    options.poll_delay = Duration::from_secs(1);
    
    let client = MstTransparencyClient::new(endpoint, options);
    
    // Construction with custom options should succeed
    assert!(format!("{:?}", client).contains("MstTransparencyClient"));
}

#[test]
fn test_mst_client_error_display_http_error() {
    let error = MstClientError::HttpError("Connection failed".to_string());
    let display = format!("{}", error);
    assert_eq!(display, "HTTP error: Connection failed");
}

#[test]
fn test_mst_client_error_display_cbor_parse_error() {
    let error = MstClientError::CborParseError("Invalid CBOR".to_string());
    let display = format!("{}", error);
    assert_eq!(display, "CBOR parse error: Invalid CBOR");
}

#[test]
fn test_mst_client_error_display_operation_timeout() {
    let error = MstClientError::OperationTimeout {
        operation_id: "op123".to_string(),
        retries: 5,
    };
    let display = format!("{}", error);
    assert_eq!(display, "Operation op123 timed out after 5 retries");
}

#[test]
fn test_mst_client_error_display_operation_failed() {
    let error = MstClientError::OperationFailed {
        operation_id: "op456".to_string(),
        status: "Failed".to_string(),
    };
    let display = format!("{}", error);
    assert_eq!(display, "Operation op456 failed with status: Failed");
}

#[test]
fn test_mst_client_error_display_missing_field() {
    let error = MstClientError::MissingField {
        field: "OperationId".to_string(),
    };
    let display = format!("{}", error);
    assert_eq!(display, "Missing required field: OperationId");
}

#[test]
fn test_mst_client_error_is_error() {
    let error = MstClientError::HttpError("test".to_string());
    // Test that it implements std::error::Error
    let _: &dyn std::error::Error = &error;
}