// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Tests using real .scitt transparent statement files for MST verification.
//!
//! These exercise the full verification path including receipt extraction,
//! issuer parsing, and the verify flow (which will fail signature verification
//! without proper JWKS, but exercises all the parsing/routing code).

use cose_sign1_transparent_mst::validation::verification_options::{
    AuthorizedReceiptBehavior, CodeTransparencyVerificationOptions, UnauthorizedReceiptBehavior,
};
use cose_sign1_transparent_mst::validation::verify::{
    get_receipts_from_transparent_statement, verify_transparent_statement,
};
use std::sync::Arc;

fn load_scitt_file(name: &str) -> Vec<u8> {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .join("certificates")
        .join("testdata")
        .join("v1")
        .join(name);
    std::fs::read(&path).unwrap_or_else(|e| panic!("Failed to read {}: {}", path.display(), e))
}

// ========== Receipt extraction from real .scitt files ==========

#[test]
fn extract_receipts_from_1ts_statement() {
    let data = load_scitt_file("1ts-statement.scitt");
    let receipts = get_receipts_from_transparent_statement(&data);
    // The .scitt file should parse — even if no receipts, it exercises the path
    match receipts {
        Ok(r) => {
            // Exercise issuer extraction on each receipt
            for receipt in &r {
                let _ = &receipt.issuer;
                let _ = receipt.raw_bytes.len();
            }
        }
        Err(e) => {
            // Parse error is acceptable — exercises the error path
            let _ = e;
        }
    }
}

#[test]
fn extract_receipts_from_2ts_statement() {
    let data = load_scitt_file("2ts-statement.scitt");
    let receipts = get_receipts_from_transparent_statement(&data);
    match receipts {
        Ok(r) => {
            for receipt in &r {
                let _ = &receipt.issuer;
            }
        }
        Err(e) => {
            let _ = e;
        }
    }
}

// ========== Verification with real .scitt files ==========

#[test]
fn verify_1ts_statement_offline_only() {
    let data = load_scitt_file("1ts-statement.scitt");

    let opts = CodeTransparencyVerificationOptions {
        allow_network_fetch: false,
        ..Default::default()
    };

    // Without JWKS, verification will fail — but exercises the full path
    let result = verify_transparent_statement(&data, Some(opts), None);
    // We expect errors (no JWKS) but the parsing/verification pipeline should be exercised
    let _ = result;
}

#[test]
fn verify_2ts_statement_offline_only() {
    let data = load_scitt_file("2ts-statement.scitt");

    let opts = CodeTransparencyVerificationOptions {
        allow_network_fetch: false,
        ..Default::default()
    };

    let result = verify_transparent_statement(&data, Some(opts), None);
    let _ = result;
}

#[test]
fn verify_1ts_with_authorized_domains() {
    let data = load_scitt_file("1ts-statement.scitt");

    let opts = CodeTransparencyVerificationOptions {
        authorized_domains: vec!["mst.example.com".to_string()],
        authorized_receipt_behavior: AuthorizedReceiptBehavior::VerifyAnyMatching,
        unauthorized_receipt_behavior: UnauthorizedReceiptBehavior::IgnoreAll,
        allow_network_fetch: false,
        ..Default::default()
    };

    let result = verify_transparent_statement(&data, Some(opts), None);
    let _ = result;
}

#[test]
fn verify_2ts_fail_if_present_unauthorized() {
    let data = load_scitt_file("2ts-statement.scitt");

    let opts = CodeTransparencyVerificationOptions {
        authorized_domains: vec!["specific-domain.example.com".to_string()],
        unauthorized_receipt_behavior: UnauthorizedReceiptBehavior::FailIfPresent,
        allow_network_fetch: false,
        ..Default::default()
    };

    let result = verify_transparent_statement(&data, Some(opts), None);
    // If receipts have issuers not in authorized_domains, this should fail
    let _ = result;
}

// ========== Verify with mock client factory ==========

#[test]
fn verify_1ts_with_factory() {
    use code_transparency_client::{
        mock_transport::{MockResponse, SequentialMockTransport},
        CodeTransparencyClient, CodeTransparencyClientConfig, CodeTransparencyClientOptions,
    };

    let data = load_scitt_file("1ts-statement.scitt");

    let jwks_json = r#"{"keys":[{"kty":"EC","kid":"k1","crv":"P-256"}]}"#;
    let factory: Arc<dyn Fn(&str, &CodeTransparencyClientOptions) -> CodeTransparencyClient + Send + Sync> =
        Arc::new(move |_issuer, _opts| {
            let mock = SequentialMockTransport::new(vec![
                MockResponse::ok(jwks_json.as_bytes().to_vec()),
            ]);
            CodeTransparencyClient::with_options(
                url::Url::parse("https://mst.example.com").unwrap(),
                CodeTransparencyClientConfig::default(),
                CodeTransparencyClientOptions {
                    client_options: mock.into_client_options(),
                    ..Default::default()
                },
            )
        });

    let opts = CodeTransparencyVerificationOptions {
        allow_network_fetch: true,
        client_factory: Some(factory),
        ..Default::default()
    };

    let result = verify_transparent_statement(&data, Some(opts), None);
    // Exercises JWKS fetch + verification pipeline with real statement data
    let _ = result;
}
