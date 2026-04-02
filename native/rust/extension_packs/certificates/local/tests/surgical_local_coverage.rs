// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Surgical coverage tests for cose_sign1_certificates_local factory.rs.
//!
//! Targets:
//! - CA cert with bounded path_length_constraint (lines 214-224)
//! - CA cert with unbounded path_length_constraint (u32::MAX, line 214 branch)
//! - Issuer-signed cert (lines 228-256)
//! - Issuer without private key error (lines 245-248)
//! - Subject without "CN=" prefix (line 187)
//! - Generated key lifecycle: get_generated_key / release_key (lines 45-60, 282-303)
//! - Custom validity period and not_before_offset (lines 195-204)

use cose_sign1_certificates_local::traits::CertificateFactory;
use cose_sign1_certificates_local::*;
use std::time::Duration;
use x509_parser::prelude::*;

/// Helper: create factory with SoftwareKeyProvider.
fn make_factory() -> EphemeralCertificateFactory {
    EphemeralCertificateFactory::new(Box::new(SoftwareKeyProvider::new()))
}

/// Helper: parse cert and return the X509Certificate for assertions.
fn parse_cert(der: &[u8]) -> X509Certificate<'_> {
    X509Certificate::from_der(der).unwrap().1
}

// ===========================================================================
// factory.rs — CA cert with bounded path_length_constraint (lines 214-224)
// ===========================================================================

#[test]
fn create_ca_cert_with_bounded_path_length() {
    // Covers: lines 211-224 (is_ca=true, path_length_constraint < u32::MAX)
    //   - BasicConstraints::new().critical().ca() + pathlen(3)
    //   - KeyUsage::new().key_cert_sign().crl_sign()
    let factory = make_factory();
    let opts = CertificateOptions::new()
        .with_subject_name("CN=Bounded CA")
        .as_ca(3); // path_length_constraint = 3

    let cert = factory.create_certificate(opts).unwrap();
    let parsed = parse_cert(&cert.cert_der);

    // Verify CA basic constraints
    let mut found_bc = false;
    for ext in parsed.extensions() {
        if let ParsedExtension::BasicConstraints(bc) = ext.parsed_extension() {
            assert!(bc.ca, "should be a CA");
            assert_eq!(bc.path_len_constraint, Some(3), "path length should be 3");
            found_bc = true;
        }
    }
    assert!(found_bc, "BasicConstraints extension should be present");

    // Verify key usage includes keyCertSign and crlSign
    let mut found_ku = false;
    for ext in parsed.extensions() {
        if let ParsedExtension::KeyUsage(ku) = ext.parsed_extension() {
            assert!(ku.key_cert_sign(), "keyCertSign should be set");
            assert!(ku.crl_sign(), "crlSign should be set");
            found_ku = true;
        }
    }
    assert!(found_ku, "KeyUsage extension should be present for CA");
}

#[test]
fn create_ca_cert_with_unbounded_path_length() {
    // Covers: line 214 branch where path_length_constraint == u32::MAX (no pathlen)
    let factory = make_factory();
    let opts = CertificateOptions::new()
        .with_subject_name("CN=Unbounded CA")
        .as_ca(u32::MAX); // Should skip pathlen() call

    let cert = factory.create_certificate(opts).unwrap();
    let parsed = parse_cert(&cert.cert_der);

    // BasicConstraints should be CA but without path length constraint
    for ext in parsed.extensions() {
        if let ParsedExtension::BasicConstraints(bc) = ext.parsed_extension() {
            assert!(bc.ca, "should be CA");
            assert!(
                bc.path_len_constraint.is_none(),
                "path length should be unbounded (None), got: {:?}",
                bc.path_len_constraint
            );
        }
    }
}

// ===========================================================================
// factory.rs — issuer-signed certificate (lines 228-256)
// ===========================================================================

#[test]
fn create_issuer_signed_leaf_cert() {
    // Covers: lines 228-256 (issuer path)
    //   - PKey::private_key_from_der (line 231)
    //   - X509::from_der (line 237)
    //   - builder.set_issuer_name(issuer_x509.subject_name()) (line 241)
    //   - sign_x509_builder(&mut builder, &issuer_pkey, ...) (line 244)
    let factory = make_factory();

    // Create a CA root first
    let root_opts = CertificateOptions::new()
        .with_subject_name("CN=Root CA For Signing")
        .as_ca(u32::MAX);
    let root_cert = factory.create_certificate(root_opts).unwrap();
    assert!(root_cert.has_private_key(), "root should have private key");

    // Create leaf signed by root
    let leaf_opts = CertificateOptions::new()
        .with_subject_name("CN=Leaf Signed By Root")
        .signed_by(root_cert.clone());
    let leaf_cert = factory.create_certificate(leaf_opts).unwrap();

    let parsed_leaf = parse_cert(&leaf_cert.cert_der);
    let parsed_root = parse_cert(&root_cert.cert_der);

    // Verify: leaf's issuer == root's subject
    assert_eq!(
        parsed_leaf.issuer().to_string(),
        parsed_root.subject().to_string(),
        "leaf issuer should match root subject"
    );
    // Verify: leaf's subject != root's subject
    assert_ne!(
        parsed_leaf.subject().to_string(),
        parsed_root.subject().to_string(),
        "leaf subject should differ from root"
    );
}

#[test]
fn create_three_level_chain() {
    // Deep chain: Root CA → Intermediate CA → Leaf
    let factory = make_factory();

    let root = factory
        .create_certificate(
            CertificateOptions::new()
                .with_subject_name("CN=Root")
                .as_ca(2),
        )
        .unwrap();

    let intermediate = factory
        .create_certificate(
            CertificateOptions::new()
                .with_subject_name("CN=Intermediate")
                .as_ca(1)
                .signed_by(root.clone()),
        )
        .unwrap();

    let leaf = factory
        .create_certificate(
            CertificateOptions::new()
                .with_subject_name("CN=Leaf")
                .signed_by(intermediate.clone()),
        )
        .unwrap();

    let parsed_leaf = parse_cert(&leaf.cert_der);
    let parsed_intermediate = parse_cert(&intermediate.cert_der);

    assert_eq!(
        parsed_leaf.issuer().to_string(),
        parsed_intermediate.subject().to_string(),
        "leaf issuer should match intermediate subject"
    );
}

#[test]
fn create_issuer_signed_without_private_key_fails() {
    // Covers: lines 245-248 (issuer cert without private key → error)
    let factory = make_factory();

    // Create a cert with NO private key as issuer
    let issuer_without_key = Certificate::new(vec![1, 2, 3, 4]); // Dummy DER, no private key

    let opts = CertificateOptions::new()
        .with_subject_name("CN=Bad Leaf")
        .signed_by(issuer_without_key);

    let result = factory.create_certificate(opts);
    assert!(
        result.is_err(),
        "should fail when issuer has no private key"
    );
}

// ===========================================================================
// factory.rs — subject without "CN=" prefix (line 187)
// ===========================================================================

#[test]
fn create_cert_subject_without_cn_prefix() {
    // Covers: line 187 strip_prefix("CN=") falls through to unwrap_or
    let factory = make_factory();
    let opts = CertificateOptions::new().with_subject_name("My Raw Subject Name");

    let cert = factory.create_certificate(opts).unwrap();
    let parsed = parse_cert(&cert.cert_der);
    assert!(
        parsed.subject().to_string().contains("My Raw Subject Name"),
        "subject should contain the raw name"
    );
}

#[test]
fn create_cert_subject_with_cn_prefix() {
    // Covers: line 187 strip_prefix("CN=") succeeds
    let factory = make_factory();
    let opts = CertificateOptions::new().with_subject_name("CN=Prefixed Subject");

    let cert = factory.create_certificate(opts).unwrap();
    let parsed = parse_cert(&cert.cert_der);
    assert!(
        parsed.subject().to_string().contains("Prefixed Subject"),
        "subject should contain name without prefix"
    );
}

// ===========================================================================
// factory.rs — generated key lifecycle (lines 45-60, 282-303)
// ===========================================================================

#[test]
fn generated_key_get_and_release() {
    // Covers: get_generated_key (lines 45-50), release_key (54-60),
    //   key storage (lines 294-303)
    let factory = make_factory();
    let opts = CertificateOptions::new().with_subject_name("CN=Key Lifecycle");
    let cert = factory.create_certificate(opts).unwrap();

    // Extract serial from cert to look up the generated key
    let parsed = parse_cert(&cert.cert_der);
    let serial_hex: String = parsed
        .serial
        .to_bytes_be()
        .iter()
        .map(|b| format!("{:02X}", b))
        .collect();

    // Should be able to get the key
    let key = factory.get_generated_key(&serial_hex);
    assert!(key.is_some(), "generated key should be retrievable");
    let key = key.unwrap();
    assert!(
        !key.private_key_der.is_empty(),
        "private key should not be empty"
    );
    assert!(
        !key.public_key_der.is_empty(),
        "public key should not be empty"
    );
    assert_eq!(key.algorithm, KeyAlgorithm::Ecdsa);

    // Release the key
    let released = factory.release_key(&serial_hex);
    assert!(released, "key should be released");

    // Should no longer be available
    let key_again = factory.get_generated_key(&serial_hex);
    assert!(key_again.is_none(), "key should be gone after release");

    // Double release returns false
    let released_again = factory.release_key(&serial_hex);
    assert!(!released_again, "second release should return false");
}

#[test]
fn get_generated_key_for_unknown_serial() {
    let factory = make_factory();
    let key = factory.get_generated_key("NONEXISTENT_SERIAL");
    assert!(key.is_none(), "should return None for unknown serial");
}

// ===========================================================================
// factory.rs — custom validity period and not_before_offset (lines 195-204)
// ===========================================================================

#[test]
fn create_cert_with_custom_validity() {
    // Covers: lines 195-204 (not_before_offset and validity)
    let factory = make_factory();
    let opts = CertificateOptions::new()
        .with_subject_name("CN=Custom Validity")
        .with_validity(Duration::from_secs(86400 * 365)) // 1 year
        .with_not_before_offset(Duration::from_secs(60)); // 1 minute

    let cert = factory.create_certificate(opts).unwrap();
    let parsed = parse_cert(&cert.cert_der);
    let validity = parsed.validity();

    // Verify validity period is approximately 1 year
    let duration_secs = validity.not_after.timestamp() - validity.not_before.timestamp();
    assert!(
        duration_secs > 86400 * 364 && duration_secs < 86400 * 366,
        "validity should be approximately 1 year, got {} seconds",
        duration_secs
    );
}

#[test]
fn create_cert_with_zero_not_before_offset() {
    let factory = make_factory();
    let opts = CertificateOptions::new()
        .with_subject_name("CN=Zero Offset")
        .with_not_before_offset(Duration::from_secs(0));

    let cert = factory.create_certificate(opts).unwrap();
    assert!(!cert.cert_der.is_empty());
}

// ===========================================================================
// factory.rs — RSA unsupported path (lines 156-160) — verify error message
// ===========================================================================

#[test]
fn create_cert_rsa_unsupported_error_message() {
    let factory = make_factory();
    let opts = CertificateOptions::new().with_key_algorithm(KeyAlgorithm::Rsa);

    let err = factory.create_certificate(opts).unwrap_err();
    let msg = format!("{}", err);
    assert!(
        msg.to_lowercase().contains("not yet implemented")
            || msg.to_lowercase().contains("unsupported"),
        "error should mention unsupported: got '{}'",
        msg
    );
}

// ===========================================================================
// factory.rs — key_size default when None (line 298)
// ===========================================================================

#[test]
fn create_cert_default_key_size() {
    // Covers: line 298 — key_size.unwrap_or_else(|| key_algorithm.default_key_size())
    let factory = make_factory();
    let opts = CertificateOptions::new().with_subject_name("CN=Default Key Size");
    // key_size is None by default, should use Ecdsa.default_key_size() = 256

    let cert = factory.create_certificate(opts).unwrap();
    let parsed = parse_cert(&cert.cert_der);
    let serial_hex: String = parsed
        .serial
        .to_bytes_be()
        .iter()
        .map(|b| format!("{:02X}", b))
        .collect();

    let key = factory.get_generated_key(&serial_hex).unwrap();
    assert_eq!(
        key.key_size, 256,
        "default key size for ECDSA should be 256"
    );
}

#[test]
fn create_cert_explicit_key_size() {
    // key_size is explicitly set
    let factory = make_factory();
    let opts = CertificateOptions::new()
        .with_subject_name("CN=Explicit Key Size")
        .with_key_size(256);

    let cert = factory.create_certificate(opts).unwrap();
    let parsed = parse_cert(&cert.cert_der);
    let serial_hex: String = parsed
        .serial
        .to_bytes_be()
        .iter()
        .map(|b| format!("{:02X}", b))
        .collect();

    let key = factory.get_generated_key(&serial_hex).unwrap();
    assert_eq!(key.key_size, 256);
}
