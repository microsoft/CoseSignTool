// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Online verification (JWKS fetch + cache).
//!
//! These tests use small `JwksFetcher` stubs to validate:
//! - When fetching is avoided
//! - How fetched keys populate the cache
//! - That fetch/parse errors don't crash

mod common;

use common::*;
use cosesign1::CoseAlgorithm;
use cosesign1_mst::{
    verify_transparent_statement_online, AuthorizedReceiptBehavior, JwksDocument, JwkEcPublicKey, OfflineEcKeyStore,
    ResolvedKey, UnauthorizedReceiptBehavior, VerificationOptions,
};
use p256::pkcs8::EncodePublicKey;

#[test]
fn online_verification_does_not_fetch_when_not_allowed_or_cache_hits() {
    let sk = p256::ecdsa::SigningKey::from_bytes(&[8u8; 32].into()).expect("sk");
    let vk = sk.verifying_key();

    let kid = "kid-1";
    let issuer = "issuer.example";

    let statement_sig = b"sig";
    let statement_payload = b"payload";
    let statement_without_unprotected = encode_statement_without_unprotected(statement_payload, statement_sig);
    let receipt = build_receipt_es256(kid, issuer, &statement_without_unprotected, &sk);
    let statement = encode_statement_with_receipts(statement_payload, statement_sig, &[receipt]);

    let der = p256::PublicKey::from_sec1_bytes(vk.to_encoded_point(false).as_bytes())
        .unwrap()
        .to_public_key_der()
        .unwrap();

    let mut cache = OfflineEcKeyStore::default();
    cache.insert(
        issuer,
        kid,
        ResolvedKey {
            public_key_bytes: der.as_bytes().to_vec(),
            expected_alg: CoseAlgorithm::ES256,
        },
    );

    let mut opts = VerificationOptions::default();
    opts.authorized_domains = vec![issuer.to_string()];

    // Not allowed => offline path.
    opts.allow_network_key_fetch = false;
    let res = verify_transparent_statement_online("mst", &statement, &mut cache, &PanickingFetcher, &opts);
    assert!(res.is_valid, "{:?}", res.failures);

    // Allowed, but cache already satisfies => no fetch.
    opts.allow_network_key_fetch = true;
    let res2 = verify_transparent_statement_online("mst", &statement, &mut cache, &PanickingFetcher, &opts);
    assert!(res2.is_valid, "{:?}", res2.failures);
}

#[test]
fn online_verification_fetches_and_populates_cache() {
    let sk = p256::ecdsa::SigningKey::from_bytes(&[9u8; 32].into()).expect("sk");
    let vk = sk.verifying_key();

    let kid = "kid-1";
    let issuer = "issuer.example";

    let statement_sig = b"sig";
    let statement_payload = b"payload";
    let statement_without_unprotected = encode_statement_without_unprotected(statement_payload, statement_sig);
    let receipt = build_receipt_es256(kid, issuer, &statement_without_unprotected, &sk);
    let statement = encode_statement_with_receipts(statement_payload, statement_sig, &[receipt]);

    // Include some keys that should be skipped to cover the "continue" branches.
    let mut jwk_good = build_jwk_from_p256(kid, vk);
    let jwk_wrong_kty = JwkEcPublicKey {
        kty: "RSA".to_string(),
        crv: "P-256".to_string(),
        x: jwk_good.x.clone(),
        y: jwk_good.y.clone(),
        kid: "skip-kty".to_string(),
    };
    let jwk_bad_coords = JwkEcPublicKey {
        kty: "EC".to_string(),
        crv: "P-256".to_string(),
        x: "AA".to_string(),
        y: "AA".to_string(),
        kid: "skip-coords".to_string(),
    };
    let jwk_unsupported_curve = JwkEcPublicKey {
        kty: "EC".to_string(),
        crv: "P-999".to_string(),
        x: jwk_good.x.clone(),
        y: jwk_good.y.clone(),
        kid: "skip-crv".to_string(),
    };
    jwk_good.kid = kid.to_string();
    let jwks_json = serde_json::to_vec(&JwksDocument {
        keys: vec![jwk_wrong_kty, jwk_bad_coords, jwk_unsupported_curve, jwk_good],
    })
    .unwrap();
    let fetcher = StaticFetcher { bytes: jwks_json };

    let mut cache = OfflineEcKeyStore::default();
    let mut opts = VerificationOptions::default();
    opts.allow_network_key_fetch = true;
    opts.authorized_domains = vec![issuer.to_string()];
    opts.unauthorized_receipt_behavior = UnauthorizedReceiptBehavior::IgnoreAll;
    opts.authorized_receipt_behavior = AuthorizedReceiptBehavior::RequireAll;

    let res = verify_transparent_statement_online("mst", &statement, &mut cache, &fetcher, &opts);
    assert!(res.is_valid, "{:?}", res.failures);
    assert!(cache.resolve(issuer, kid).is_some());
}

#[test]
fn online_verification_fetch_failures_do_not_crash() {
    let sk = p256::ecdsa::SigningKey::from_bytes(&[10u8; 32].into()).expect("sk");

    let kid = "kid-1";
    let issuer = "issuer.example";

    let statement_sig = b"sig";
    let statement_payload = b"payload";
    let statement_without_unprotected = encode_statement_without_unprotected(statement_payload, statement_sig);
    let receipt = build_receipt_es256(kid, issuer, &statement_without_unprotected, &sk);
    let statement = encode_statement_with_receipts(statement_payload, statement_sig, &[receipt]);

    let mut cache = OfflineEcKeyStore::default();
    let mut opts = VerificationOptions::default();
    opts.allow_network_key_fetch = true;
    opts.authorized_domains = vec![issuer.to_string()];
    opts.unauthorized_receipt_behavior = UnauthorizedReceiptBehavior::IgnoreAll;
    opts.authorized_receipt_behavior = AuthorizedReceiptBehavior::RequireAll;

    let res = verify_transparent_statement_online("mst", &statement, &mut cache, &ErrorFetcher, &opts);
    assert!(!res.is_valid);
    assert!(cache.resolve(issuer, kid).is_none());

    let fetcher_bad_json = StaticFetcher {
        bytes: b"not-json".to_vec(),
    };
    let res2 = verify_transparent_statement_online("mst", &statement, &mut cache, &fetcher_bad_json, &opts);
    assert!(!res2.is_valid);
}
