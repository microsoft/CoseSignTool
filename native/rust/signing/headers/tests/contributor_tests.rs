// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use cose_sign1_headers::{CWTClaimsHeaderLabels, CwtClaims, CwtClaimsHeaderContributor};
use cose_sign1_primitives::{CoseHeaderMap, CryptoError, CryptoSigner};
use cose_sign1_signing::{
    HeaderContributor, HeaderContributorContext, HeaderMergeStrategy, SigningContext,
};

// Mock CryptoSigner for testing
struct MockCryptoSigner;

impl CryptoSigner for MockCryptoSigner {
    fn key_id(&self) -> Option<&[u8]> {
        None
    }

    fn key_type(&self) -> &str {
        "EC2"
    }

    fn algorithm(&self) -> i64 {
        -7 // ES256
    }

    fn sign(&self, _data: &[u8]) -> Result<Vec<u8>, CryptoError> {
        Ok(vec![1, 2, 3])
    }
}

#[test]
fn test_cwt_claims_contributor_adds_to_protected_headers() {
    let claims = CwtClaims::new()
        .with_issuer("https://example.com")
        .with_subject("test@example.com");

    let contributor =
        CwtClaimsHeaderContributor::new(&claims).expect("Failed to create contributor");

    let mut headers = CoseHeaderMap::new();
    let signing_context = SigningContext::from_bytes(vec![1, 2, 3]);
    let key = MockCryptoSigner;
    let context = HeaderContributorContext::new(&signing_context, &key);

    contributor.contribute_protected_headers(&mut headers, &context);

    // Verify the CWT claims header was added at label 15
    let header_value = headers.get(&CWTClaimsHeaderLabels::CWT_CLAIMS_HEADER.into());
    assert!(
        header_value.is_some(),
        "CWT claims header should be present"
    );
}

#[test]
fn test_cwt_claims_contributor_no_unprotected_headers() {
    let claims = CwtClaims::new().with_subject("test");
    let contributor =
        CwtClaimsHeaderContributor::new(&claims).expect("Failed to create contributor");

    let mut headers = CoseHeaderMap::new();
    let signing_context = SigningContext::from_bytes(vec![1, 2, 3]);
    let key = MockCryptoSigner;
    let context = HeaderContributorContext::new(&signing_context, &key);

    // Should not add anything to unprotected headers
    let initial_count = headers.len();
    contributor.contribute_unprotected_headers(&mut headers, &context);
    assert_eq!(
        headers.len(),
        initial_count,
        "Should not add unprotected headers"
    );
}

#[test]
fn test_cwt_claims_contributor_roundtrip() {
    let original_claims = CwtClaims::new()
        .with_issuer("https://issuer.com")
        .with_subject("user@example.com")
        .with_audience("https://audience.com")
        .with_expiration_time(1234567890)
        .with_not_before(1234567800)
        .with_issued_at(1234567850);

    let contributor =
        CwtClaimsHeaderContributor::new(&original_claims).expect("Failed to create contributor");

    let mut headers = CoseHeaderMap::new();
    let signing_context = SigningContext::from_bytes(vec![1, 2, 3]);
    let key = MockCryptoSigner;
    let context = HeaderContributorContext::new(&signing_context, &key);

    contributor.contribute_protected_headers(&mut headers, &context);

    // Extract and decode the CWT claims
    let header_value = headers
        .get(&CWTClaimsHeaderLabels::CWT_CLAIMS_HEADER.into())
        .unwrap();

    if let cose_sign1_primitives::CoseHeaderValue::Bytes(bytes) = header_value {
        let decoded_claims = CwtClaims::from_cbor_bytes(bytes).unwrap();

        // Verify all fields match
        assert_eq!(
            decoded_claims.issuer,
            Some("https://issuer.com".to_string())
        );
        assert_eq!(decoded_claims.subject, Some("user@example.com".to_string()));
        assert_eq!(
            decoded_claims.audience,
            Some("https://audience.com".to_string())
        );
        assert_eq!(decoded_claims.expiration_time, Some(1234567890));
        assert_eq!(decoded_claims.not_before, Some(1234567800));
        assert_eq!(decoded_claims.issued_at, Some(1234567850));
    } else {
        panic!("Expected Bytes header value");
    }
}

#[test]
fn test_cwt_claims_contributor_merge_strategy() {
    let claims = CwtClaims::new().with_subject("test");
    let contributor =
        CwtClaimsHeaderContributor::new(&claims).expect("Failed to create contributor");

    // Verify merge strategy is Replace
    assert_eq!(contributor.merge_strategy(), HeaderMergeStrategy::Replace);
}

#[test]
fn test_cwt_claims_contributor_label_constant() {
    // Test that the CWT_CLAIMS_LABEL constant has the correct value
    assert_eq!(CwtClaimsHeaderContributor::CWT_CLAIMS_LABEL, 15);
}

#[test]
fn test_cwt_claims_contributor_new_error_handling() {
    // Create claims that would fail CBOR encoding if we could force an error
    // Since the CwtClaims::to_cbor_bytes() doesn't have many failure modes,
    // this is more of a structural test to ensure the error path exists
    let claims = CwtClaims::new().with_issuer("valid issuer");

    // This should succeed normally
    let result = CwtClaimsHeaderContributor::new(&claims);
    assert!(result.is_ok());
}
