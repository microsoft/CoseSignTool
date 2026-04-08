// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Certificate-based trust validation — create an ephemeral certificate chain,
//! construct a COSE_Sign1 message with an embedded x5chain header, then validate
//! using the X.509 certificate trust pack.
//!
//! Run with:
//!   cargo run --example certificate_trust_validation -p cose_sign1_certificates

use std::sync::Arc;

use cbor_primitives::{CborEncoder, CborProvider};
use cbor_primitives_everparse::EverParseCborProvider;
use cose_sign1_certificates::validation::pack::{
    CertificateTrustOptions, X509CertificateTrustPack,
};
use cose_sign1_validation::fluent::*;
use cose_sign1_validation_primitives::CoseHeaderLocation;

fn main() {
    // ── 1. Generate an ephemeral self-signed certificate ─────────────
    println!("=== Step 1: Generate ephemeral certificate ===\n");

    let rcgen::CertifiedKey { cert, .. } =
        rcgen::generate_simple_self_signed(vec!["example-leaf".to_string()]).expect("rcgen failed");
    let leaf_der = cert.der().to_vec();
    println!("  Leaf cert DER size: {} bytes", leaf_der.len());

    // ── 2. Build a minimal COSE_Sign1 with x5chain header ───────────
    println!("\n=== Step 2: Build COSE_Sign1 with x5chain ===\n");

    let payload = b"Hello, COSE world!";
    let cose_bytes = build_cose_sign1_with_x5chain(&leaf_der, payload);
    println!("  COSE message size: {} bytes", cose_bytes.len());
    println!("  Payload: {:?}", std::str::from_utf8(payload).unwrap());

    // ── 3. Set up the certificate trust pack ─────────────────────────
    println!("\n=== Step 3: Configure certificate trust pack ===\n");

    // For this example, treat the embedded x5chain as trusted.
    // In production, configure actual trust roots and revocation checks.
    let cert_pack = Arc::new(X509CertificateTrustPack::new(CertificateTrustOptions {
        trust_embedded_chain_as_trusted: true,
        ..Default::default()
    }));
    println!("  Trust pack: embedded x5chain treated as trusted");

    let trust_packs: Vec<Arc<dyn CoseSign1TrustPack>> = vec![cert_pack];

    // ── 4. Build a validator with bypass trust + signature bypass ─────
    //    (We bypass the actual crypto check because the COSE message's
    //     signature is a dummy — in a real scenario the signing service
    //     would produce a valid signature.)
    println!("\n=== Step 4: Validate with trust bypass ===\n");

    let validator = CoseSign1Validator::new(trust_packs.clone()).with_options(|o| {
        o.certificate_header_location = CoseHeaderLocation::Any;
        o.trust_evaluation_options.bypass_trust = true;
    });

    let result = validator
        .validate_bytes(
            EverParseCborProvider,
            Arc::from(cose_bytes.clone().into_boxed_slice()),
        )
        .expect("validation pipeline error");

    println!("  resolution: {:?}", result.resolution.kind);
    println!("  trust:      {:?}", result.trust.kind);
    println!("  signature:  {:?}", result.signature.kind);
    println!("  overall:    {:?}", result.overall.kind);

    // ── 5. Demonstrate custom trust plan ─────────────────────────────
    println!("\n=== Step 5: Custom trust plan (advanced) ===\n");

    use cose_sign1_certificates::validation::fluent_ext::PrimarySigningKeyScopeRulesExt;

    let cert_pack2 = Arc::new(X509CertificateTrustPack::new(CertificateTrustOptions {
        trust_embedded_chain_as_trusted: true,
        ..Default::default()
    }));
    let packs: Vec<Arc<dyn CoseSign1TrustPack>> = vec![cert_pack2];

    let plan = TrustPlanBuilder::new(packs)
        .for_primary_signing_key(|key| {
            key.require_x509_chain_trusted()
                .and()
                .require_signing_certificate_present()
        })
        .compile()
        .expect("plan compile");

    let validator2 = CoseSign1Validator::new(plan).with_options(|o| {
        o.certificate_header_location = CoseHeaderLocation::Any;
    });

    let result2 = validator2
        .validate_bytes(
            EverParseCborProvider,
            Arc::from(cose_bytes.into_boxed_slice()),
        )
        .expect("validation pipeline error");

    println!("  resolution: {:?}", result2.resolution.kind);
    println!("  trust:      {:?}", result2.trust.kind);
    println!("  signature:  {:?}", result2.signature.kind);
    println!("  overall:    {:?}", result2.overall.kind);

    // Print failures if any
    let stages = [
        ("resolution", &result2.resolution),
        ("trust", &result2.trust),
        ("signature", &result2.signature),
        ("overall", &result2.overall),
    ];
    for (name, stage) in stages {
        if !stage.failures.is_empty() {
            println!("\n  {} failures:", name);
            for f in &stage.failures {
                println!("    - {}", f.message);
            }
        }
    }

    println!("\n=== Example completed! ===");
}

/// Build a minimal COSE_Sign1 byte sequence with an embedded x5chain header.
///
/// The message structure is:
///   [protected_headers_bstr, unprotected_headers_map, payload_bstr, signature_bstr]
///
/// Protected headers contain:
///   { 1 (alg): -7 (ES256), 33 (x5chain): bstr(cert_der) }
fn build_cose_sign1_with_x5chain(leaf_der: &[u8], payload: &[u8]) -> Vec<u8> {
    let p = EverParseCborProvider;
    let mut enc = p.encoder();

    // COSE_Sign1 is a 4-element CBOR array
    enc.encode_array(4).unwrap();

    // Protected headers: CBOR bstr wrapping a CBOR map
    let mut hdr_enc = p.encoder();
    hdr_enc.encode_map(2).unwrap();
    hdr_enc.encode_i64(1).unwrap(); // label: alg
    hdr_enc.encode_i64(-7).unwrap(); // value: ES256
    hdr_enc.encode_i64(33).unwrap(); // label: x5chain
    hdr_enc.encode_bstr(leaf_der).unwrap();
    let protected_bytes = hdr_enc.into_bytes();
    enc.encode_bstr(&protected_bytes).unwrap();

    // Unprotected headers: empty map
    enc.encode_map(0).unwrap();

    // Payload: embedded byte string
    enc.encode_bstr(payload).unwrap();

    // Signature: dummy (not cryptographically valid)
    enc.encode_bstr(b"example-signature-placeholder").unwrap();

    enc.into_bytes()
}
