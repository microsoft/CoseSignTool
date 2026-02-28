// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use cose_sign1_transparent_mst::signing::{MstTransparencyProvider, MstTransparencyClient, MstTransparencyClientOptions};
use cose_sign1_transparent_mst::http_client::MockHttpTransport;
use cose_sign1_signing::transparency::TransparencyProvider;
use url::Url;

#[test]
fn test_mst_transparency_provider_name() {
    let transport = MockHttpTransport::new();
    let endpoint = Url::parse("https://api.rekor.example.com").unwrap();
    let options = MstTransparencyClientOptions::default();
    let client = MstTransparencyClient::new(endpoint, options);
    let provider = MstTransparencyProvider::new(client);
    assert_eq!(provider.provider_name(), "Microsoft Signing Transparency");
}

#[test] 
fn test_mst_transparency_provider_verify_empty_bytes() {
    let transport = MockHttpTransport::new();
    let endpoint = Url::parse("https://api.rekor.example.com").unwrap();
    let options = MstTransparencyClientOptions::default();
    let client = MstTransparencyClient::new(endpoint, options);
    let provider = MstTransparencyProvider::new(client);
    
    // Empty bytes should cause message parsing to fail
    let empty_bytes = vec![];
    let result = provider.verify_transparency_proof(&empty_bytes);
    assert!(result.is_err());
}

#[test]
fn test_mst_transparency_provider_verify_invalid_cbor() {
    let transport = MockHttpTransport::new();
    let endpoint = Url::parse("https://api.rekor.example.com").unwrap();
    let options = MstTransparencyClientOptions::default();
    let client = MstTransparencyClient::new(endpoint, options);
    let provider = MstTransparencyProvider::new(client);
    
    // Invalid CBOR bytes
    let invalid_bytes = vec![0xFF, 0xFE, 0xFD];
    let result = provider.verify_transparency_proof(&invalid_bytes);
    assert!(result.is_err());
}