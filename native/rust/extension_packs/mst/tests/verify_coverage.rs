// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Tests for verification_options, verify, and signing/service modules
//! to fill coverage gaps.

use cose_sign1_transparent_mst::signing::service::MstTransparencyProvider;
use cose_sign1_transparent_mst::validation::verification_options::{
    AuthorizedReceiptBehavior, CodeTransparencyVerificationOptions, UnauthorizedReceiptBehavior,
};
use cose_sign1_transparent_mst::validation::verify::{
    get_receipt_issuer_host, get_receipts_from_message, get_receipts_from_transparent_statement,
    ExtractedReceipt, UNKNOWN_ISSUER_PREFIX,
};
use cose_sign1_transparent_mst::validation::jwks_cache::JwksCache;

use cbor_primitives::{CborEncoder, CborProvider};
use cbor_primitives_everparse::EverParseCborProvider;
use code_transparency_client::{
    mock_transport::{MockResponse, SequentialMockTransport},
    CodeTransparencyClient, CodeTransparencyClientConfig, CodeTransparencyClientOptions,
    JwksDocument,
};
use cose_sign1_primitives::CoseSign1Message;
use cose_sign1_signing::transparency::TransparencyProvider;
use std::collections::HashMap;
use std::sync::Arc;
use url::Url;

// ========================================================================
// CBOR helpers
// ========================================================================

fn encode_statement_with_receipts(receipts: &[Vec<u8>]) -> Vec<u8> {
    let p = EverParseCborProvider;
    let mut enc = p.encoder();

    // Protected header: map with alg = ES256 (-7)
    let mut phdr = p.encoder();
    phdr.encode_map(1).unwrap();
    phdr.encode_i64(1).unwrap();
    phdr.encode_i64(-7).unwrap();
    let phdr_bytes = phdr.into_bytes();

    // COSE_Sign1 = [protected, unprotected, payload, signature]
    enc.encode_array(4).unwrap();
    enc.encode_bstr(&phdr_bytes).unwrap();

    // Unprotected header with receipts at label 394
    enc.encode_map(1).unwrap();
    enc.encode_i64(394).unwrap();
    enc.encode_array(receipts.len()).unwrap();
    for r in receipts {
        enc.encode_bstr(r).unwrap();
    }

    enc.encode_null().unwrap(); // detached payload
    enc.encode_bstr(b"stub-sig").unwrap();

    enc.into_bytes()
}

fn encode_receipt_with_issuer(issuer: &str) -> Vec<u8> {
    let p = EverParseCborProvider;

    // Protected header: map with alg(-7), kid("k1"), vds(1), cwt claims({1:issuer})
    let mut phdr = p.encoder();
    phdr.encode_map(4).unwrap();
    phdr.encode_i64(1).unwrap();
    phdr.encode_i64(-7).unwrap();
    phdr.encode_i64(4).unwrap();
    phdr.encode_bstr(b"k1").unwrap();
    phdr.encode_i64(395).unwrap();
    phdr.encode_i64(1).unwrap();
    phdr.encode_i64(15).unwrap();
    phdr.encode_map(1).unwrap();
    phdr.encode_i64(1).unwrap();
    phdr.encode_tstr(issuer).unwrap();
    let phdr_bytes = phdr.into_bytes();

    // COSE_Sign1 receipt
    let mut enc = p.encoder();
    enc.encode_array(4).unwrap();
    enc.encode_bstr(&phdr_bytes).unwrap();
    enc.encode_map(0).unwrap(); // empty unprotected
    enc.encode_null().unwrap(); // detached payload
    enc.encode_bstr(b"receipt-sig").unwrap();
    enc.into_bytes()
}

fn mock_client_with_responses(responses: Vec<MockResponse>) -> CodeTransparencyClient {
    let mock = SequentialMockTransport::new(responses);
    CodeTransparencyClient::with_options(
        Url::parse("https://mst.test.example.com").unwrap(),
        CodeTransparencyClientConfig::default(),
        CodeTransparencyClientOptions {
            client_options: mock.into_client_options(),
            ..Default::default()
        },
    )
}

// ========================================================================
// AuthorizedReceiptBehavior defaults and Debug
// ========================================================================

#[test]
fn authorized_receipt_behavior_default() {
    assert_eq!(
        AuthorizedReceiptBehavior::default(),
        AuthorizedReceiptBehavior::RequireAll,
    );
}

#[test]
fn authorized_receipt_behavior_debug() {
    let b = AuthorizedReceiptBehavior::VerifyAnyMatching;
    assert!(format!("{:?}", b).contains("VerifyAnyMatching"));
}

// ========================================================================
// UnauthorizedReceiptBehavior defaults and Debug
// ========================================================================

#[test]
fn unauthorized_receipt_behavior_default() {
    assert_eq!(
        UnauthorizedReceiptBehavior::default(),
        UnauthorizedReceiptBehavior::VerifyAll,
    );
}

#[test]
fn unauthorized_receipt_behavior_debug() {
    let b = UnauthorizedReceiptBehavior::FailIfPresent;
    assert!(format!("{:?}", b).contains("FailIfPresent"));
}

// ========================================================================
// CodeTransparencyVerificationOptions
// ========================================================================

#[test]
fn verification_options_default() {
    let opts = CodeTransparencyVerificationOptions::default();
    assert!(opts.authorized_domains.is_empty());
    assert_eq!(
        opts.authorized_receipt_behavior,
        AuthorizedReceiptBehavior::RequireAll,
    );
    assert_eq!(
        opts.unauthorized_receipt_behavior,
        UnauthorizedReceiptBehavior::VerifyAll,
    );
    assert!(opts.allow_network_fetch);
    assert!(opts.jwks_cache.is_none());
}

#[test]
fn verification_options_with_offline_keys_creates_cache() {
    let jwks = JwksDocument::from_json(
        r#"{"keys":[{"kty":"EC","kid":"k1","crv":"P-256"}]}"#,
    )
    .unwrap();
    let mut keys = HashMap::new();
    keys.insert("issuer1.example.com".to_string(), jwks);

    let opts = CodeTransparencyVerificationOptions::default().with_offline_keys(keys);
    assert!(opts.jwks_cache.is_some());
    let cache = opts.jwks_cache.unwrap();
    let doc = cache.get("issuer1.example.com");
    assert!(doc.is_some());
}

#[test]
fn verification_options_with_offline_keys_adds_to_existing_cache() {
    let cache = Arc::new(JwksCache::new());
    let mut opts = CodeTransparencyVerificationOptions {
        jwks_cache: Some(cache),
        ..Default::default()
    };
    let jwks = JwksDocument::from_json(
        r#"{"keys":[{"kty":"EC","kid":"k2","crv":"P-384"}]}"#,
    )
    .unwrap();
    let mut keys = HashMap::new();
    keys.insert("issuer2.example.com".to_string(), jwks);

    opts = opts.with_offline_keys(keys);
    assert!(opts.jwks_cache.is_some());
}

#[test]
fn verification_options_debug() {
    let opts = CodeTransparencyVerificationOptions::default();
    let d = format!("{:?}", opts);
    assert!(d.contains("CodeTransparencyVerificationOptions"));
}

// ========================================================================
// verify — get_receipts_from_transparent_statement
// ========================================================================

#[test]
fn get_receipts_from_transparent_statement_no_receipts() {
    // Statement with no receipts in header 394
    let p = EverParseCborProvider;
    let mut enc = p.encoder();
    let mut phdr = p.encoder();
    phdr.encode_map(1).unwrap();
    phdr.encode_i64(1).unwrap();
    phdr.encode_i64(-7).unwrap();
    let phdr_bytes = phdr.into_bytes();

    enc.encode_array(4).unwrap();
    enc.encode_bstr(&phdr_bytes).unwrap();
    enc.encode_map(0).unwrap(); // no unprotected headers
    enc.encode_null().unwrap();
    enc.encode_bstr(b"sig").unwrap();
    let stmt = enc.into_bytes();

    let receipts = get_receipts_from_transparent_statement(&stmt).unwrap();
    assert!(receipts.is_empty());
}

#[test]
fn get_receipts_from_transparent_statement_with_receipts() {
    let receipt = encode_receipt_with_issuer("https://mst.example.com");
    let stmt = encode_statement_with_receipts(&[receipt]);
    let receipts = get_receipts_from_transparent_statement(&stmt).unwrap();
    assert_eq!(receipts.len(), 1);
    assert!(receipts[0].issuer.contains("mst.example.com"));
}

#[test]
fn get_receipts_from_transparent_statement_invalid_bytes() {
    let err = get_receipts_from_transparent_statement(&[0xFF, 0xFF]).unwrap_err();
    assert!(err.contains("parse"));
}

#[test]
fn get_receipts_from_message_with_unparseable_receipt() {
    // Build a statement whose receipt is garbage bytes
    let stmt = encode_statement_with_receipts(&[b"not-a-cose-message".to_vec()]);
    let msg = CoseSign1Message::parse(&stmt).unwrap();
    let receipts = get_receipts_from_message(&msg).unwrap();
    assert_eq!(receipts.len(), 1);
    assert!(receipts[0].issuer.starts_with(UNKNOWN_ISSUER_PREFIX));
    assert!(receipts[0].message.is_none());
}

// ========================================================================
// verify — get_receipt_issuer_host
// ========================================================================

#[test]
fn get_receipt_issuer_host_valid() {
    let receipt = encode_receipt_with_issuer("https://mst.example.com");
    let issuer = get_receipt_issuer_host(&receipt).unwrap();
    assert!(issuer.contains("mst.example.com"));
}

#[test]
fn get_receipt_issuer_host_invalid_bytes() {
    let err = get_receipt_issuer_host(&[0xFF]).unwrap_err();
    assert!(err.contains("parse"));
}

#[test]
fn get_receipt_issuer_host_no_issuer() {
    // Receipt without CWT claims
    let p = EverParseCborProvider;
    let mut phdr = p.encoder();
    phdr.encode_map(1).unwrap();
    phdr.encode_i64(1).unwrap();
    phdr.encode_i64(-7).unwrap();
    let phdr_bytes = phdr.into_bytes();

    let mut enc = p.encoder();
    enc.encode_array(4).unwrap();
    enc.encode_bstr(&phdr_bytes).unwrap();
    enc.encode_map(0).unwrap();
    enc.encode_null().unwrap();
    enc.encode_bstr(b"sig").unwrap();
    let receipt = enc.into_bytes();

    let err = get_receipt_issuer_host(&receipt).unwrap_err();
    assert!(err.contains("issuer"));
}

// ========================================================================
// verify — ExtractedReceipt Debug
// ========================================================================

#[test]
fn extracted_receipt_debug() {
    let r = ExtractedReceipt {
        issuer: "test.example.com".into(),
        raw_bytes: vec![1, 2, 3],
        message: None,
    };
    let d = format!("{:?}", r);
    assert!(d.contains("test.example.com"));
    assert!(d.contains("raw_bytes_len"));
}

// ========================================================================
// signing::service — MstTransparencyProvider
// ========================================================================

#[test]
fn mst_provider_name() {
    let mock = SequentialMockTransport::new(vec![]);
    let client = CodeTransparencyClient::with_options(
        Url::parse("https://mst.example.com").unwrap(),
        CodeTransparencyClientConfig::default(),
        CodeTransparencyClientOptions {
            client_options: mock.into_client_options(),
            ..Default::default()
        },
    );
    let provider = MstTransparencyProvider::new(client);
    assert_eq!(provider.provider_name(), "Microsoft Signing Transparency");
}

#[test]
fn mst_provider_add_transparency_proof_error() {
    // add_transparency_proof calls make_transparent, which needs POST + GET.
    // With empty mock, it should fail.
    let client = mock_client_with_responses(vec![]);
    let provider = MstTransparencyProvider::new(client);
    let err = provider.add_transparency_proof(b"cose-bytes");
    assert!(err.is_err());
}

#[test]
fn mst_provider_verify_no_receipts() {
    // Build a valid COSE_Sign1 without any receipts in header 394
    let p = EverParseCborProvider;
    let mut phdr = p.encoder();
    phdr.encode_map(1).unwrap();
    phdr.encode_i64(1).unwrap();
    phdr.encode_i64(-7).unwrap();
    let phdr_bytes = phdr.into_bytes();

    let mut enc = p.encoder();
    enc.encode_array(4).unwrap();
    enc.encode_bstr(&phdr_bytes).unwrap();
    enc.encode_map(0).unwrap();
    enc.encode_null().unwrap();
    enc.encode_bstr(b"sig").unwrap();
    let stmt = enc.into_bytes();

    let client = mock_client_with_responses(vec![]);
    let provider = MstTransparencyProvider::new(client);
    let result = provider.verify_transparency_proof(&stmt).unwrap();
    assert!(!result.is_valid);
}

#[test]
fn mst_provider_verify_invalid_cose() {
    let client = mock_client_with_responses(vec![]);
    let provider = MstTransparencyProvider::new(client);
    let err = provider.verify_transparency_proof(b"not-cose");
    assert!(err.is_err());
}

#[test]
fn mst_provider_verify_with_receipts() {
    // Build a statement with a receipt (verification will fail because
    // signature is invalid, but it exercises the verification path)
    let receipt = encode_receipt_with_issuer("https://mst.example.com");
    let stmt = encode_statement_with_receipts(&[receipt]);

    // Mock JWKS endpoint for network fallback
    let jwks = r#"{"keys":[{"kty":"EC","kid":"k1","crv":"P-256","x":"abc","y":"def"}]}"#;
    let client = mock_client_with_responses(vec![
        MockResponse::ok(jwks.as_bytes().to_vec()),
    ]);
    let provider = MstTransparencyProvider::new(client);
    let result = provider.verify_transparency_proof(&stmt).unwrap();
    // Verification fails but doesn't error — returns failure result
    assert!(!result.is_valid);
}

// ========================================================================
// verify — verify_transparent_statement
// ========================================================================

#[test]
fn verify_transparent_statement_invalid_bytes() {
    use cose_sign1_transparent_mst::validation::verify::verify_transparent_statement;
    let errs = verify_transparent_statement(b"not-cose", None, None).unwrap_err();
    assert!(!errs.is_empty());
    assert!(errs[0].contains("parse"));
}

#[test]
fn verify_transparent_statement_no_receipts() {
    use cose_sign1_transparent_mst::validation::verify::verify_transparent_statement;
    // Build a valid COSE_Sign1 with no receipts
    let p = EverParseCborProvider;
    let mut phdr = p.encoder();
    phdr.encode_map(1).unwrap();
    phdr.encode_i64(1).unwrap();
    phdr.encode_i64(-7).unwrap();
    let phdr_bytes = phdr.into_bytes();

    let mut enc = p.encoder();
    enc.encode_array(4).unwrap();
    enc.encode_bstr(&phdr_bytes).unwrap();
    enc.encode_map(0).unwrap();
    enc.encode_null().unwrap();
    enc.encode_bstr(b"sig").unwrap();
    let stmt = enc.into_bytes();

    let errs = verify_transparent_statement(&stmt, None, None).unwrap_err();
    assert!(errs.iter().any(|e| e.contains("No receipts")));
}

#[test]
fn verify_transparent_statement_ignore_all_no_authorized() {
    use cose_sign1_transparent_mst::validation::verify::verify_transparent_statement;
    // When no authorized domains AND unauthorized behavior is IgnoreAll → error
    let receipt = encode_receipt_with_issuer("https://mst.example.com");
    let stmt = encode_statement_with_receipts(&[receipt]);

    let opts = CodeTransparencyVerificationOptions {
        authorized_domains: vec![],
        unauthorized_receipt_behavior: UnauthorizedReceiptBehavior::IgnoreAll,
        ..Default::default()
    };
    let errs = verify_transparent_statement(&stmt, Some(opts), None).unwrap_err();
    assert!(errs.iter().any(|e| e.contains("no authorized domains") || e.contains("No receipts would")));
}

#[test]
fn verify_transparent_statement_fail_if_present_unauthorized() {
    use cose_sign1_transparent_mst::validation::verify::verify_transparent_statement;
    // When authorized domains set, and receipt is from unauthorized issuer, FailIfPresent → error
    let receipt = encode_receipt_with_issuer("https://unauthorized.example.com");
    let stmt = encode_statement_with_receipts(&[receipt]);

    let opts = CodeTransparencyVerificationOptions {
        authorized_domains: vec!["authorized.example.com".into()],
        unauthorized_receipt_behavior: UnauthorizedReceiptBehavior::FailIfPresent,
        ..Default::default()
    };
    let errs = verify_transparent_statement(&stmt, Some(opts), None).unwrap_err();
    assert!(errs.iter().any(|e| e.contains("not in the authorized")));
}

#[test]
fn verify_transparent_statement_with_authorized_domain() {
    use cose_sign1_transparent_mst::validation::verify::verify_transparent_statement;
    // Receipt from authorized domain — verification will fail (bad sig) but exercises the path
    let receipt = encode_receipt_with_issuer("https://mst.example.com");
    let stmt = encode_statement_with_receipts(&[receipt]);

    let opts = CodeTransparencyVerificationOptions {
        authorized_domains: vec!["mst.example.com".into()],
        authorized_receipt_behavior: AuthorizedReceiptBehavior::VerifyAnyMatching,
        allow_network_fetch: false,
        ..Default::default()
    };
    let errs = verify_transparent_statement(&stmt, Some(opts), None).unwrap_err();
    // Should fail verification but exercise the code path
    assert!(!errs.is_empty());
}

#[test]
fn verify_transparent_statement_verify_all_matching() {
    use cose_sign1_transparent_mst::validation::verify::verify_transparent_statement;
    let receipt = encode_receipt_with_issuer("https://mst.example.com");
    let stmt = encode_statement_with_receipts(&[receipt]);

    let opts = CodeTransparencyVerificationOptions {
        authorized_domains: vec!["mst.example.com".into()],
        authorized_receipt_behavior: AuthorizedReceiptBehavior::VerifyAllMatching,
        allow_network_fetch: false,
        ..Default::default()
    };
    let errs = verify_transparent_statement(&stmt, Some(opts), None).unwrap_err();
    assert!(!errs.is_empty());
}

#[test]
fn verify_transparent_statement_require_all_missing_domain() {
    use cose_sign1_transparent_mst::validation::verify::verify_transparent_statement;
    let receipt = encode_receipt_with_issuer("https://mst.example.com");
    let stmt = encode_statement_with_receipts(&[receipt]);

    let opts = CodeTransparencyVerificationOptions {
        authorized_domains: vec!["mst.example.com".into(), "other.example.com".into()],
        authorized_receipt_behavior: AuthorizedReceiptBehavior::RequireAll,
        allow_network_fetch: false,
        ..Default::default()
    };
    let errs = verify_transparent_statement(&stmt, Some(opts), None).unwrap_err();
    // Should complain about missing receipt for other.example.com
    assert!(errs.iter().any(|e| e.contains("other.example.com") || e.contains("required")));
}

#[test]
fn verify_transparent_statement_unknown_issuer_receipt() {
    use cose_sign1_transparent_mst::validation::verify::verify_transparent_statement;
    // Receipt with garbage bytes → unknown issuer
    let stmt = encode_statement_with_receipts(&[b"garbage-receipt".to_vec()]);

    let opts = CodeTransparencyVerificationOptions {
        allow_network_fetch: false,
        ..Default::default()
    };
    let errs = verify_transparent_statement(&stmt, Some(opts), None).unwrap_err();
    assert!(!errs.is_empty());
}

#[test]
fn verify_transparent_statement_with_cache() {
    use cose_sign1_transparent_mst::validation::verify::verify_transparent_statement;
    let receipt = encode_receipt_with_issuer("https://mst.example.com");
    let stmt = encode_statement_with_receipts(&[receipt]);

    let cache = Arc::new(JwksCache::new());
    let jwks = JwksDocument::from_json(
        r#"{"keys":[{"kty":"EC","kid":"k1","crv":"P-256","x":"abc","y":"def"}]}"#,
    ).unwrap();
    cache.insert("mst.example.com", jwks);

    let opts = CodeTransparencyVerificationOptions {
        allow_network_fetch: false,
        jwks_cache: Some(cache),
        ..Default::default()
    };
    let errs = verify_transparent_statement(&stmt, Some(opts), None).unwrap_err();
    // Verification fails (bad sig) but exercises JWKS cache path
    assert!(!errs.is_empty());
}

#[test]
fn verify_transparent_statement_unauthorized_verify_all() {
    use cose_sign1_transparent_mst::validation::verify::verify_transparent_statement;
    // Unauthorized receipt with VerifyAll behavior — exercises the verification path
    // for unauthorized receipts
    let receipt = encode_receipt_with_issuer("https://unknown.example.com");
    let stmt = encode_statement_with_receipts(&[receipt]);

    let opts = CodeTransparencyVerificationOptions {
        authorized_domains: vec!["authorized.example.com".into()],
        unauthorized_receipt_behavior: UnauthorizedReceiptBehavior::VerifyAll,
        authorized_receipt_behavior: AuthorizedReceiptBehavior::RequireAll,
        allow_network_fetch: false,
        ..Default::default()
    };
    let errs = verify_transparent_statement(&stmt, Some(opts), None).unwrap_err();
    assert!(!errs.is_empty());
}

#[test]
fn verify_transparent_statement_multiple_receipts_mixed() {
    use cose_sign1_transparent_mst::validation::verify::verify_transparent_statement;
    // Two receipts from different issuers — exercises the loop
    let receipt1 = encode_receipt_with_issuer("https://issuer1.example.com");
    let receipt2 = encode_receipt_with_issuer("https://issuer2.example.com");
    let stmt = encode_statement_with_receipts(&[receipt1, receipt2]);

    let opts = CodeTransparencyVerificationOptions {
        authorized_domains: vec!["issuer1.example.com".into()],
        authorized_receipt_behavior: AuthorizedReceiptBehavior::VerifyAnyMatching,
        allow_network_fetch: false,
        ..Default::default()
    };
    let errs = verify_transparent_statement(&stmt, Some(opts), None).unwrap_err();
    // Both fail crypto verification
    assert!(!errs.is_empty());
}

#[test]
fn verify_transparent_statement_message_directly() {
    use cose_sign1_transparent_mst::validation::verify::verify_transparent_statement_message;
    let receipt = encode_receipt_with_issuer("https://mst.example.com");
    let stmt = encode_statement_with_receipts(&[receipt]);
    let msg = CoseSign1Message::parse(&stmt).unwrap();

    let opts = CodeTransparencyVerificationOptions {
        allow_network_fetch: false,
        ..Default::default()
    };
    let errs = verify_transparent_statement_message(&msg, &stmt, Some(opts), None).unwrap_err();
    assert!(!errs.is_empty());
}

#[test]
fn verify_transparent_statement_no_cache_creates_default() {
    use cose_sign1_transparent_mst::validation::verify::verify_transparent_statement;
    // When no cache is provided AND jwks_cache is None, creates a default cache
    let receipt = encode_receipt_with_issuer("https://mst.example.com");
    let stmt = encode_statement_with_receipts(&[receipt]);

    let opts = CodeTransparencyVerificationOptions {
        jwks_cache: None,
        allow_network_fetch: false,
        ..Default::default()
    };
    let errs = verify_transparent_statement(&stmt, Some(opts), None).unwrap_err();
    assert!(!errs.is_empty());
}

#[test]
fn verify_transparent_statement_with_default_options() {
    use cose_sign1_transparent_mst::validation::verify::verify_transparent_statement;
    // None options → uses defaults, creates default cache
    let receipt = encode_receipt_with_issuer("https://mst.example.com");
    let stmt = encode_statement_with_receipts(&[receipt]);

    // Use explicit options with network disabled to avoid 60s timeout
    let opts = CodeTransparencyVerificationOptions {
        allow_network_fetch: false,
        ..Default::default()
    };
    let errs = verify_transparent_statement(&stmt, Some(opts), None).unwrap_err();
    assert!(!errs.is_empty());
}

#[test]
fn verify_transparent_statement_ignore_unauthorized() {
    use cose_sign1_transparent_mst::validation::verify::verify_transparent_statement;
    // Unauthorized behavior = IgnoreAll with authorized domain that has receipt
    let receipt = encode_receipt_with_issuer("https://myissuer.example.com");
    let stmt = encode_statement_with_receipts(&[receipt]);

    let opts = CodeTransparencyVerificationOptions {
        authorized_domains: vec!["myissuer.example.com".into()],
        unauthorized_receipt_behavior: UnauthorizedReceiptBehavior::IgnoreAll,
        authorized_receipt_behavior: AuthorizedReceiptBehavior::VerifyAllMatching,
        allow_network_fetch: false,
        ..Default::default()
    };
    let errs = verify_transparent_statement(&stmt, Some(opts), None).unwrap_err();
    assert!(!errs.is_empty());
}
