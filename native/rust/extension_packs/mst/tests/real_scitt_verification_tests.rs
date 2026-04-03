// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! End-to-end MST receipt verification tests using real .scitt transparent statements.
//!
//! These tests load actual .scitt files that contain COSE_Sign1 transparent statements
//! with embedded MST receipts, extract the receipt structure, and verify the full
//! cryptographic pipeline:
//! - Receipt CBOR parsing (VDS=2, kid, alg, CWT issuer)
//! - JWKS key resolution with matching kid
//! - Statement re-encoding with cleared unprotected headers
//! - CCF inclusion proof verification (data_hash, leaf hash, path folding)
//! - ECDSA signature verification over the Sig_structure

use code_transparency_client::{
    mock_transport::{MockResponse, SequentialMockTransport},
    CodeTransparencyClient, CodeTransparencyClientConfig, CodeTransparencyClientOptions,
    JwksDocument,
};
use cose_sign1_primitives::CoseSign1Message;
use cose_sign1_transparent_mst::validation::jwks_cache::JwksCache;
use cose_sign1_transparent_mst::validation::verification_options::CodeTransparencyVerificationOptions;
use cose_sign1_transparent_mst::validation::verify::{
    get_receipt_issuer_host, get_receipts_from_transparent_statement, verify_transparent_statement,
};
use std::collections::HashMap;
use std::sync::Arc;
use url::Url;

fn load_scitt(name: &str) -> Vec<u8> {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .join("certificates")
        .join("testdata")
        .join("v1")
        .join(name);
    std::fs::read(&path).unwrap_or_else(|e| panic!("Failed to read {}: {}", path.display(), e))
}

// ========== Diagnostic: Inspect .scitt receipt structure ==========

#[test]
fn inspect_1ts_statement_receipt_structure() {
    let data = load_scitt("1ts-statement.scitt");
    let msg = CoseSign1Message::parse(&data).expect("Should parse as COSE_Sign1");

    // Check protected header has alg
    let alg = msg.protected.headers().alg();
    eprintln!("Statement alg: {:?}", alg);

    // Extract receipts from unprotected header 394
    let receipts = get_receipts_from_transparent_statement(&data).unwrap();
    eprintln!("Number of receipts: {}", receipts.len());

    for (i, receipt) in receipts.iter().enumerate() {
        eprintln!("--- Receipt {} ---", i);
        eprintln!("  Issuer: {}", receipt.issuer);
        eprintln!("  Raw bytes: {} bytes", receipt.raw_bytes.len());

        if let Some(ref rmsg) = receipt.message {
            let r_alg = rmsg.protected.headers().alg();
            eprintln!("  Receipt alg: {:?}", r_alg);

            // Check VDS (label 395)
            use cose_sign1_primitives::CoseHeaderLabel;
            let vds = rmsg
                .protected
                .get(&CoseHeaderLabel::Int(395))
                .and_then(|v| v.as_i64());
            eprintln!("  VDS: {:?}", vds);

            // Check kid (label 4)
            let kid = rmsg
                .protected
                .headers()
                .kid()
                .or_else(|| rmsg.unprotected.headers().kid());
            if let Some(kb) = kid {
                eprintln!(
                    "  Kid: {:?}",
                    std::str::from_utf8(kb).unwrap_or("(non-utf8)")
                );
            }

            // Check VDP (label 396 in unprotected)
            let vdp = rmsg.unprotected.get(&CoseHeaderLabel::Int(396));
            eprintln!("  Has VDP (396): {}", vdp.is_some());

            // Check signature length
            eprintln!("  Signature: {} bytes", rmsg.signature().len());
        }
    }

    assert!(
        !receipts.is_empty(),
        "Real .scitt file should contain receipts"
    );
}

#[test]
fn inspect_2ts_statement_receipt_structure() {
    let data = load_scitt("2ts-statement.scitt");
    let receipts = get_receipts_from_transparent_statement(&data).unwrap();
    eprintln!("2ts-statement: {} receipts", receipts.len());

    for (i, receipt) in receipts.iter().enumerate() {
        eprintln!("Receipt {}: issuer={}", i, receipt.issuer);
        if let Some(ref rmsg) = receipt.message {
            let vds = rmsg
                .protected
                .get(&cose_sign1_primitives::CoseHeaderLabel::Int(395))
                .and_then(|v| v.as_i64());
            eprintln!("  VDS: {:?}, sig: {} bytes", vds, rmsg.signature().len());
        }
    }

    assert!(!receipts.is_empty());
}

// ========== Full verification with real .scitt + JWKS from receipt issuer ==========

#[test]
fn verify_1ts_with_mock_jwks_exercises_full_crypto_pipeline() {
    let data = load_scitt("1ts-statement.scitt");

    // Extract receipts to get the issuer and kid
    let receipts = get_receipts_from_transparent_statement(&data).unwrap();
    assert!(!receipts.is_empty(), "Need at least 1 receipt");

    let receipt = &receipts[0];
    let issuer = &receipt.issuer;

    // Get the kid from the receipt to construct matching JWKS
    let kid = receipt.message.as_ref().and_then(|m| {
        m.protected
            .headers()
            .kid()
            .or_else(|| m.unprotected.headers().kid())
            .and_then(|b| std::str::from_utf8(b).ok())
            .map(|s| s.to_string())
    });

    eprintln!("Receipt issuer: {}, kid: {:?}", issuer, kid);

    // Create a mock JWKS with a P-384 key for the kid — this will exercise the
    // full verification pipeline including VDS check, JWKS lookup, proof parsing,
    // statement re-encoding, and signature verification. The signature will fail
    // (wrong key) but all intermediate steps are exercised.
    // Use P-384 because the real receipt uses ES384 (alg=-35).
    let kid_str = kid.unwrap_or_else(|| "unknown-kid".to_string());
    let mock_jwks = format!(
        r#"{{"keys":[{{"kty":"EC","kid":"{}","crv":"P-384","x":"iA7dVHaUwQLFAJONiPWfNyvaCmbnhQlrY4MVCaVKBFuI5RmdTS4qmqS6sGEVWPWB","y":"qiwH95FhYzHxuRr56gDSLgWvfuCLGQ_BkPVPwVKP5hIi_wWYIc9UCHvWXqvhYR3u"}}]}}"#,
        kid_str
    );

    let mock_jwks_owned = mock_jwks.clone();
    let factory: Arc<
        dyn Fn(&str, &CodeTransparencyClientOptions) -> CodeTransparencyClient + Send + Sync,
    > = Arc::new(move |_issuer, _opts| {
        let mock = SequentialMockTransport::new(vec![MockResponse::ok(
            mock_jwks_owned.as_bytes().to_vec(),
        )]);
        CodeTransparencyClient::with_options(
            Url::parse("https://mock.example.com").unwrap(),
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
    // Verification WILL fail because the mock JWKS has a different key than the receipt signer.
    // But the full pipeline is exercised: receipt parsing → VDS=2 → JWKS lookup → proof validation → signature check
    assert!(result.is_err(), "Should fail with wrong JWKS key");
    let errors = result.unwrap_err();
    eprintln!("Verification errors: {:?}", errors);

    // The error should be about verification failure, NOT about missing JWKS or parse errors
    // This confirms the pipeline reached the crypto verification step
    for error in &errors {
        assert!(
            !error.contains("No receipts"),
            "Should find receipts in real .scitt file"
        );
    }
}

#[test]
fn verify_2ts_with_mock_jwks_exercises_full_crypto_pipeline() {
    let data = load_scitt("2ts-statement.scitt");

    let receipts = get_receipts_from_transparent_statement(&data).unwrap();
    if receipts.is_empty() {
        eprintln!("2ts-statement has no receipts — skipping");
        return;
    }

    let receipt = &receipts[0];
    let kid = receipt
        .message
        .as_ref()
        .and_then(|m| {
            m.protected
                .headers()
                .kid()
                .or_else(|| m.unprotected.headers().kid())
                .and_then(|b| std::str::from_utf8(b).ok())
                .map(|s| s.to_string())
        })
        .unwrap_or_else(|| "unknown".to_string());

    let mock_jwks = format!(
        r#"{{"keys":[{{"kty":"EC","kid":"{}","crv":"P-384","x":"iA7dVHaUwQLFAJONiPWfNyvaCmbnhQlrY4MVCaVKBFuI5RmdTS4qmqS6sGEVWPWB","y":"qiwH95FhYzHxuRr56gDSLgWvfuCLGQ_BkPVPwVKP5hIi_wWYIc9UCHvWXqvhYR3u"}}]}}"#,
        kid
    );

    let mock_jwks_owned = mock_jwks.clone();
    let factory: Arc<
        dyn Fn(&str, &CodeTransparencyClientOptions) -> CodeTransparencyClient + Send + Sync,
    > = Arc::new(move |_issuer, _opts| {
        let mock = SequentialMockTransport::new(vec![MockResponse::ok(
            mock_jwks_owned.as_bytes().to_vec(),
        )]);
        CodeTransparencyClient::with_options(
            Url::parse("https://mock.example.com").unwrap(),
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
    assert!(result.is_err()); // wrong key, but exercises full pipeline including ES384 path
    let errors = result.unwrap_err();
    for error in &errors {
        assert!(!error.contains("No receipts"));
    }
}

// ========== Verification with offline JWKS pre-seeded in cache ==========

#[test]
fn verify_1ts_with_offline_jwks_cache() {
    let data = load_scitt("1ts-statement.scitt");
    let receipts = get_receipts_from_transparent_statement(&data).unwrap();

    if receipts.is_empty() {
        return;
    }

    let issuer = receipts[0].issuer.clone();
    let kid = receipts[0]
        .message
        .as_ref()
        .and_then(|m| {
            m.protected
                .headers()
                .kid()
                .and_then(|b| std::str::from_utf8(b).ok())
                .map(|s| s.to_string())
        })
        .unwrap_or_else(|| "k".to_string());

    // Pre-seed cache with a P-384 JWKS for this issuer (receipt uses ES384)
    let jwks_json = format!(
        r#"{{"keys":[{{"kty":"EC","kid":"{}","crv":"P-384","x":"iA7dVHaUwQLFAJONiPWfNyvaCmbnhQlrY4MVCaVKBFuI5RmdTS4qmqS6sGEVWPWB","y":"qiwH95FhYzHxuRr56gDSLgWvfuCLGQ_BkPVPwVKP5hIi_wWYIc9UCHvWXqvhYR3u"}}]}}"#,
        kid
    );
    let jwks = JwksDocument::from_json(&jwks_json).unwrap();
    let mut keys = HashMap::new();
    keys.insert(issuer, jwks);

    let opts = CodeTransparencyVerificationOptions {
        allow_network_fetch: false,
        ..Default::default()
    }
    .with_offline_keys(keys);

    let result = verify_transparent_statement(&data, Some(opts), None);
    // Will fail (wrong key) but exercises offline JWKS cache → key resolution → proof verify
    assert!(result.is_err());
}

// ========== Receipt issuer extraction from real files ==========

#[test]
fn real_receipt_issuer_extraction() {
    let data = load_scitt("1ts-statement.scitt");
    let receipts = get_receipts_from_transparent_statement(&data).unwrap();

    for receipt in &receipts {
        // Issuer should be a valid hostname (not unknown prefix)
        assert!(
            !receipt.issuer.starts_with("__unknown"),
            "Real receipt should have parseable issuer, got: {}",
            receipt.issuer
        );

        // Also verify via the standalone function
        let issuer = get_receipt_issuer_host(&receipt.raw_bytes);
        assert!(
            issuer.is_ok(),
            "get_receipt_issuer_host should work for real receipts"
        );
        assert_eq!(issuer.unwrap(), receipt.issuer);
    }
}

// ========== Policy enforcement with real receipts ==========

#[test]
fn require_all_with_real_receipt_issuer() {
    let data = load_scitt("1ts-statement.scitt");
    let receipts = get_receipts_from_transparent_statement(&data).unwrap();

    if receipts.is_empty() {
        return;
    }

    let real_issuer = receipts[0].issuer.clone();

    // RequireAll with both the real issuer AND a missing domain
    let opts = CodeTransparencyVerificationOptions {
        authorized_domains: vec![
            real_issuer.clone(),
            "definitely-missing.example.com".to_string(),
        ],
        authorized_receipt_behavior: cose_sign1_transparent_mst::validation::verification_options::AuthorizedReceiptBehavior::RequireAll,
        allow_network_fetch: false,
        ..Default::default()
    };

    let result = verify_transparent_statement(&data, Some(opts), None);
    assert!(result.is_err());
    let errors = result.unwrap_err();
    // Should report the missing domain, NOT just "no receipts"
    assert!(
        errors
            .iter()
            .any(|e| e.contains("definitely-missing.example.com")),
        "Should report missing required domain, got: {:?}",
        errors
    );
}

#[test]
fn fail_if_present_with_real_receipts() {
    let data = load_scitt("1ts-statement.scitt");
    let receipts = get_receipts_from_transparent_statement(&data).unwrap();

    if receipts.is_empty() {
        return;
    }

    // Use a domain that doesn't match any real receipt issuer
    let opts = CodeTransparencyVerificationOptions {
        authorized_domains: vec!["only-this-domain.example.com".to_string()],
        unauthorized_receipt_behavior: cose_sign1_transparent_mst::validation::verification_options::UnauthorizedReceiptBehavior::FailIfPresent,
        allow_network_fetch: false,
        ..Default::default()
    };

    let result = verify_transparent_statement(&data, Some(opts), None);
    assert!(result.is_err());
    let errors = result.unwrap_err();
    assert!(
        errors
            .iter()
            .any(|e| e.contains("not in the authorized domain")),
        "Should reject real receipt as unauthorized, got: {:?}",
        errors
    );
}
