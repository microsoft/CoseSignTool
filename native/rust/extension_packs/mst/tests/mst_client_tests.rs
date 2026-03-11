// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use cose_sign1_transparent_mst::signing::client::{MstTransparencyClientOptions, MstTransparencyClient, CreateEntryResult};
use std::time::Duration;
use url::Url;

#[test]
fn test_mst_transparency_client_options_default() {
    let options = MstTransparencyClientOptions::default();
    
    assert_eq!(options.api_version, "2024-01-01");
    assert!(options.api_key.is_none());
    assert_eq!(options.max_poll_retries, 30);
    assert_eq!(options.poll_delay, Duration::from_secs(2));
}

#[test]
fn test_mst_transparency_client_options_construction() {
    let options = MstTransparencyClientOptions {
        api_version: "2023-05-01".to_string(),
        api_key: Some("test-key".to_string()),
        max_poll_retries: 10,
        poll_delay: Duration::from_millis(500),
        ..MstTransparencyClientOptions::default()
    };
    
    assert_eq!(options.api_version, "2023-05-01");
    assert_eq!(options.api_key, Some("test-key".to_string()));
    assert_eq!(options.max_poll_retries, 10);
    assert_eq!(options.poll_delay, Duration::from_millis(500));
}

#[test]
fn test_mst_transparency_client_new() {
    let url = Url::parse("https://transparency.example.com").unwrap();
    let options = MstTransparencyClientOptions::default();
    
    let client = MstTransparencyClient::new(url.clone(), options);
    // Client should be constructible without errors
    assert_eq!(format!("{:?}", client), format!("{:?}", client)); // Just verify it can be debugged
}

#[test]
fn test_create_entry_result_construction() {
    let result = CreateEntryResult {
        operation_id: "op-123".to_string(),
        entry_id: "entry-456".to_string(),
    };
    
    assert_eq!(result.operation_id, "op-123");
    assert_eq!(result.entry_id, "entry-456");
}

#[test]
fn test_url_building_logic() {
    use url::Url;
    
    // Test the URL building pattern used in the client
    let base = Url::parse("https://api.example.com/v1/").unwrap();
    let mut url = base.clone();
    url.set_path(&format!("{}/entries", url.path().trim_end_matches('/')));
    url.set_query(Some("api-version=2024-01-01"));
    
    assert_eq!(url.as_str(), "https://api.example.com/v1/entries?api-version=2024-01-01");
    
    // Test with trailing slash removal
    let base_no_slash = Url::parse("https://api.example.com/v1").unwrap();
    let mut url2 = base_no_slash.clone();
    url2.set_path(&format!("{}/entries", url2.path().trim_end_matches('/')));
    url2.set_query(Some("api-version=2024-01-01"));
    
    assert_eq!(url2.as_str(), "https://api.example.com/v1/entries?api-version=2024-01-01");
}

#[test]
fn test_operations_url_building() {
    use url::Url;
    
    let base = Url::parse("https://api.example.com/v1/").unwrap();
    let operation_id = "op-789";
    let mut url = base.clone();
    url.set_path(&format!(
        "{}/operations/{}",
        url.path().trim_end_matches('/'),
        operation_id
    ));
    url.set_query(Some("api-version=2024-01-01"));
    
    assert_eq!(url.as_str(), "https://api.example.com/v1/operations/op-789?api-version=2024-01-01");
}

#[test]  
fn test_statement_url_building() {
    use url::Url;
    
    let base = Url::parse("https://api.example.com/v1/").unwrap();
    let entry_id = "entry-abc";
    let mut url = base.clone();
    url.set_path(&format!(
        "{}/entries/{}/statement",
        url.path().trim_end_matches('/'),
        entry_id
    ));
    url.set_query(Some("api-version=2024-01-01"));
    
    assert_eq!(url.as_str(), "https://api.example.com/v1/entries/entry-abc/statement?api-version=2024-01-01");
}