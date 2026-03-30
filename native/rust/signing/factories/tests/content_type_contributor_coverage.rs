// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Tests for ContentTypeHeaderContributor.

use cose_sign1_factories::direct::ContentTypeHeaderContributor;
use cose_sign1_primitives::{ContentType, CoseHeaderMap, CryptoError, CryptoSigner};
use cose_sign1_signing::{
    HeaderContributor, HeaderContributorContext, HeaderMergeStrategy, SigningContext,
};

/// Mock crypto signer for testing.
struct MockCryptoSigner;

impl CryptoSigner for MockCryptoSigner {
    fn sign(&self, _data: &[u8]) -> Result<Vec<u8>, CryptoError> {
        Ok(vec![0u8; 64])
    }

    fn algorithm(&self) -> i64 {
        -7
    }

    fn key_type(&self) -> &str {
        "EC2"
    }

    fn key_id(&self) -> Option<&[u8]> {
        Some(b"test-key")
    }

    fn supports_streaming(&self) -> bool {
        false
    }
}

#[test]
fn test_content_type_contributor_new() {
    let contributor = ContentTypeHeaderContributor::new("application/json");
    assert_eq!(
        contributor.merge_strategy(),
        HeaderMergeStrategy::KeepExisting
    );
}

#[test]
fn test_content_type_contributor_contribute_protected_headers() {
    let contributor = ContentTypeHeaderContributor::new("application/json");
    let mut headers = CoseHeaderMap::new();
    let signing_context = SigningContext::from_bytes(b"test payload".to_vec());
    let signer = MockCryptoSigner;
    let context = HeaderContributorContext::new(&signing_context, &signer);

    contributor.contribute_protected_headers(&mut headers, &context);

    assert!(headers.content_type().is_some());
    if let Some(ContentType::Text(ct)) = headers.content_type() {
        assert_eq!(ct, "application/json");
    } else {
        panic!("Expected text content type");
    }
}

#[test]
fn test_content_type_contributor_keeps_existing() {
    let contributor = ContentTypeHeaderContributor::new("application/json");
    let mut headers = CoseHeaderMap::new();
    headers.set_content_type(ContentType::Text("existing/type".to_string()));
    let signing_context = SigningContext::from_bytes(b"test payload".to_vec());
    let signer = MockCryptoSigner;
    let context = HeaderContributorContext::new(&signing_context, &signer);

    contributor.contribute_protected_headers(&mut headers, &context);

    // Should keep existing value
    if let Some(ContentType::Text(ct)) = headers.content_type() {
        assert_eq!(ct, "existing/type");
    } else {
        panic!("Expected existing content type to be preserved");
    }
}

#[test]
fn test_content_type_contributor_unprotected_headers_noop() {
    let contributor = ContentTypeHeaderContributor::new("application/json");
    let mut headers = CoseHeaderMap::new();
    let signing_context = SigningContext::from_bytes(b"test payload".to_vec());
    let signer = MockCryptoSigner;
    let context = HeaderContributorContext::new(&signing_context, &signer);

    // contribute_unprotected_headers should do nothing
    contributor.contribute_unprotected_headers(&mut headers, &context);

    assert!(headers.content_type().is_none());
}

#[test]
fn test_content_type_contributor_merge_strategy() {
    let contributor = ContentTypeHeaderContributor::new("text/plain");
    assert_eq!(
        contributor.merge_strategy(),
        HeaderMergeStrategy::KeepExisting
    );
}
