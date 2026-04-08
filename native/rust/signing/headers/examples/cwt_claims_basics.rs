// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! CWT (CBOR Web Token) claims builder — construct, serialize, and
//! deserialize CWT claims for COSE protected headers.
//!
//! Run with:
//!   cargo run --example cwt_claims_basics -p cose_sign1_headers

use cose_sign1_headers::{CwtClaimValue, CwtClaims, CWTClaimsHeaderLabels};

fn main() {
    // ── 1. Build CWT claims using the fluent API ─────────────────────
    println!("=== Step 1: Build CWT claims ===\n");

    let claims = CwtClaims::new()
        .with_issuer("https://example.com/issuer")
        .with_subject("software-artifact-v2.1")
        .with_audience("https://transparency.example.com")
        .with_issued_at(1_700_000_000)      // 2023-11-14T22:13:20Z
        .with_not_before(1_700_000_000)
        .with_expiration_time(1_731_536_000) // ~1 year later
        .with_cwt_id(b"unique-claim-id-001".to_vec())
        .with_custom_claim(100, CwtClaimValue::Text("build-pipeline-A".into()))
        .with_custom_claim(101, CwtClaimValue::Integer(42))
        .with_custom_claim(102, CwtClaimValue::Bool(true));

    println!("  Issuer:     {:?}", claims.issuer);
    println!("  Subject:    {:?}", claims.subject);
    println!("  Audience:   {:?}", claims.audience);
    println!("  Issued At:  {:?}", claims.issued_at);
    println!("  Not Before: {:?}", claims.not_before);
    println!("  Expires:    {:?}", claims.expiration_time);
    println!("  CWT ID:     {:?}", claims.cwt_id.as_ref().map(|b| String::from_utf8_lossy(b)));
    println!("  Custom:     {} claim(s)", claims.custom_claims.len());

    // ── 2. Serialize to CBOR bytes ───────────────────────────────────
    println!("\n=== Step 2: Serialize to CBOR ===\n");

    let cbor_bytes = claims.to_cbor_bytes().expect("CBOR serialization");
    println!("  CBOR size: {} bytes", cbor_bytes.len());
    println!("  CBOR hex:  {}", to_hex(&cbor_bytes));

    // ── 3. Deserialize back from CBOR ────────────────────────────────
    println!("\n=== Step 3: Deserialize from CBOR ===\n");

    let decoded = CwtClaims::from_cbor_bytes(&cbor_bytes).expect("CBOR deserialization");
    assert_eq!(decoded.issuer, claims.issuer);
    assert_eq!(decoded.subject, claims.subject);
    assert_eq!(decoded.audience, claims.audience);
    assert_eq!(decoded.expiration_time, claims.expiration_time);
    assert_eq!(decoded.not_before, claims.not_before);
    assert_eq!(decoded.issued_at, claims.issued_at);
    assert_eq!(decoded.cwt_id, claims.cwt_id);
    assert_eq!(decoded.custom_claims.len(), claims.custom_claims.len());

    println!("  Round-trip: all fields match ✓");
    println!("  Decoded issuer:  {:?}", decoded.issuer);
    println!("  Decoded subject: {:?}", decoded.subject);

    // ── 4. Show the CWT Claims header label ──────────────────────────
    println!("\n=== Step 4: Header integration info ===\n");

    println!(
        "  CWT Claims is placed in protected header label {}",
        CWTClaimsHeaderLabels::CWT_CLAIMS_HEADER
    );
    println!("  Standard claim labels:");
    println!("    Issuer (iss):     {}", CWTClaimsHeaderLabels::ISSUER);
    println!("    Subject (sub):    {}", CWTClaimsHeaderLabels::SUBJECT);
    println!("    Audience (aud):   {}", CWTClaimsHeaderLabels::AUDIENCE);
    println!("    Expiration (exp): {}", CWTClaimsHeaderLabels::EXPIRATION_TIME);
    println!("    Not Before (nbf): {}", CWTClaimsHeaderLabels::NOT_BEFORE);
    println!("    Issued At (iat):  {}", CWTClaimsHeaderLabels::ISSUED_AT);
    println!("    CWT ID (cti):     {}", CWTClaimsHeaderLabels::CWT_ID);

    // ── 5. Build minimal claims (SCITT default subject) ──────────────
    println!("\n=== Step 5: Minimal SCITT claims ===\n");

    let minimal = CwtClaims::new()
        .with_subject(CwtClaims::DEFAULT_SUBJECT)
        .with_issuer("did:x509:0:sha256:example::eku:1.3.6.1.5.5.7.3.3");

    let minimal_bytes = minimal.to_cbor_bytes().expect("minimal CBOR");
    println!("  Default subject: {:?}", CwtClaims::DEFAULT_SUBJECT);
    println!("  Minimal CBOR:    {} bytes", minimal_bytes.len());

    let roundtrip = CwtClaims::from_cbor_bytes(&minimal_bytes).expect("minimal decode");
    assert_eq!(roundtrip.subject.as_deref(), Some(CwtClaims::DEFAULT_SUBJECT));
    println!("  Minimal round-trip: ✓");

    println!("\n=== All steps completed successfully! ===");
}

/// Simple hex encoder for display purposes.
fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}
