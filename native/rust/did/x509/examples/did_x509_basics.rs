// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! DID:x509 basics — parse, build, validate, and resolve workflows.
//!
//! Run with:
//!   cargo run --example did_x509_basics -p did_x509

use std::borrow::Cow;

use cose_sign1_certificates_local::{
    CertificateFactory, CertificateOptions, EphemeralCertificateFactory, SoftwareKeyProvider,
};
use did_x509::{
    DidX509Builder, DidX509Parser, DidX509Policy, DidX509Resolver, DidX509Validator, SanType,
};
use sha2::{Digest, Sha256};

fn main() {
    // ── 1. Generate an ephemeral CA + leaf certificate chain ──────────
    println!("=== Step 1: Create ephemeral certificate chain ===\n");

    let (ca_der, leaf_der) = create_cert_chain();
    let chain: Vec<&[u8]> = vec![leaf_der.as_slice(), ca_der.as_slice()];

    let ca_thumbprint = hex::encode(Sha256::digest(&ca_der));
    println!("  CA thumbprint (SHA-256): {}", ca_thumbprint);

    // ── 2. Build a DID:x509 identifier from the chain ────────────────
    println!("\n=== Step 2: Build DID:x509 identifiers ===\n");

    // Build with an EKU policy (code-signing OID 1.3.6.1.5.5.7.3.3)
    let eku_policy = DidX509Policy::Eku(vec![Cow::Borrowed("1.3.6.1.5.5.7.3.3")]);
    let did_eku =
        DidX509Builder::build_sha256(&ca_der, &[eku_policy.clone()]).expect("build EKU DID");
    println!("  DID (EKU):     {}", did_eku);

    // Build with a subject policy
    let subject_policy =
        DidX509Policy::Subject(vec![("CN".to_string(), "Example Leaf".to_string())]);
    let did_subject = DidX509Builder::build_sha256(&ca_der, &[subject_policy.clone()])
        .expect("build subject DID");
    println!("  DID (Subject): {}", did_subject);

    // Build with a SAN policy
    let san_policy = DidX509Policy::San(SanType::Dns, "leaf.example.com".to_string());
    let did_san =
        DidX509Builder::build_sha256(&ca_der, &[san_policy.clone()]).expect("build SAN DID");
    println!("  DID (SAN):     {}", did_san);

    // ── 3. Parse DID:x509 identifiers back into components ───────────
    println!("\n=== Step 3: Parse DID:x509 identifiers ===\n");

    let parsed = DidX509Parser::parse(&did_eku).expect("parse DID");
    println!("  Hash algorithm:     {}", parsed.hash_algorithm);
    println!("  CA fingerprint hex: {}", parsed.ca_fingerprint_hex);
    println!("  Has EKU policy:     {}", parsed.has_eku_policy());
    println!("  Has subject policy: {}", parsed.has_subject_policy());

    if let Some(eku_oids) = parsed.get_eku_policy() {
        println!("  EKU OIDs:           {:?}", eku_oids);
    }

    // ── 4. Validate DID against the certificate chain ────────────────
    println!("\n=== Step 4: Validate DID against certificate chain ===\n");

    // Validate the SAN-based DID (leaf cert has SAN: dns:leaf.example.com)
    let result = DidX509Validator::validate(&did_san, &chain).expect("validate DID");
    println!("  DID (SAN) valid:         {}", result.is_valid);
    println!("  Matched CA index:        {:?}", result.matched_ca_index);

    // Validate subject-based DID (leaf cert has CN=Example Leaf)
    let result = DidX509Validator::validate(&did_subject, &chain).expect("validate subject DID");
    println!("  DID (Subject) valid:     {}", result.is_valid);

    // Demonstrate a failing validation with a wrong subject
    let wrong_subject = DidX509Policy::Subject(vec![("CN".to_string(), "Wrong Name".to_string())]);
    let did_wrong =
        DidX509Builder::build_sha256(&ca_der, &[wrong_subject]).expect("build wrong DID");
    let result = DidX509Validator::validate(&did_wrong, &chain).expect("validate wrong DID");
    println!(
        "  DID (wrong CN) valid:    {} (expected false)",
        result.is_valid
    );
    if !result.errors.is_empty() {
        println!("  Validation errors:       {:?}", result.errors);
    }

    // ── 5. Resolve DID to a DID Document ─────────────────────────────
    println!("\n=== Step 5: Resolve DID to DID Document ===\n");

    let doc = DidX509Resolver::resolve(&did_san, &chain).expect("resolve DID");
    let doc_json = doc.to_json(true).expect("serialize DID Document");
    println!("{}", doc_json);

    println!("\n=== All steps completed successfully! ===");
}

/// Create an ephemeral CA and leaf certificate chain using certificates_local.
/// Returns (ca_der, leaf_der) — both DER-encoded.
fn create_cert_chain() -> (Vec<u8>, Vec<u8>) {
    let factory = EphemeralCertificateFactory::new(Box::new(SoftwareKeyProvider::new()));

    // CA certificate
    let ca_cert = factory
        .create_certificate(
            CertificateOptions::new()
                .with_subject_name("CN=Example CA,O=Example Org")
                .as_ca(u32::MAX),
        )
        .unwrap();

    // Leaf certificate signed by CA
    let leaf_cert = factory
        .create_certificate(
            CertificateOptions::new()
                .with_subject_name("CN=Example Leaf,O=Example Org")
                .add_subject_alternative_name("leaf.example.com")
                .with_enhanced_key_usages(vec!["1.3.6.1.5.5.7.3.3".to_string()])
                .signed_by(ca_cert.clone()),
        )
        .unwrap();

    (ca_cert.cert_der, leaf_cert.cert_der)
}
