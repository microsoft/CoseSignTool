// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Targeted tests for EphemeralCertificateFactory covering uncovered lines in factory.rs.
//!
//! Targets:
//! - factory.rs lines 66-74: generate_ec_p256_key helper
//! - factory.rs lines 112, 155, 167, 171, 175-192: create_certificate internals
//! - factory.rs lines 198-208: validity and pubkey setting
//! - factory.rs lines 218-244: CA cert creation, issuer-signed certs
//! - factory.rs lines 253-254: self-signed issuer name setting
//! - factory.rs lines 280, 286, 303: cert DER output, serial parsing, key store

use cose_sign1_certificates_local::*;
use std::time::Duration;

// ---------------------------------------------------------------------------
// Factory: self-signed certificate (exercises lines 155, 166-208, 253-254, 279-305)
// ---------------------------------------------------------------------------

/// Verify self-signed certificate creation exercises the full builder path.
/// Covers: generate_ec_p256_key (66-74), X509Builder setup (166-208),
/// self-signed issuer name (253-254), cert DER output (280), serial parsing (286),
/// key storage (303).
#[test]
fn factory_create_self_signed_exercises_full_path() {
    let provider = Box::new(SoftwareKeyProvider::new());
    let factory = EphemeralCertificateFactory::new(provider);

    let options = CertificateOptions::new()
        .with_subject_name("CN=Full Path Test")
        .with_key_algorithm(KeyAlgorithm::Ecdsa)
        .with_key_size(256)
        .with_validity(Duration::from_secs(7200))
        .with_not_before_offset(Duration::from_secs(60));

    let cert = factory.create_certificate(options).unwrap();

    assert!(cert.has_private_key());
    assert!(!cert.cert_der.is_empty());

    // Parse and verify
    use x509_parser::prelude::*;
    let (_, parsed) = X509Certificate::from_der(&cert.cert_der).unwrap();
    assert!(parsed.subject().to_string().contains("Full Path Test"));
    // Self-signed: subject == issuer
    assert_eq!(parsed.subject().to_string(), parsed.issuer().to_string());
}

// ---------------------------------------------------------------------------
// Factory: issuer-signed certificate (exercises lines 228-244)
// ---------------------------------------------------------------------------

/// Create a CA cert then sign a leaf cert with it.
/// Covers: issuer branch (228-244), issuer key loading (231-234),
/// issuer cert parsing (237-240), set_issuer_name (241-242),
/// sign_x509_builder with issuer key (244).
#[test]
fn factory_create_issuer_signed_certificate() {
    let provider = Box::new(SoftwareKeyProvider::new());
    let factory = EphemeralCertificateFactory::new(provider);

    // Create CA certificate
    let ca_options = CertificateOptions::new()
        .with_subject_name("CN=Test CA")
        .with_key_algorithm(KeyAlgorithm::Ecdsa)
        .as_ca(1);

    let ca_cert = factory.create_certificate(ca_options).unwrap();
    assert!(ca_cert.has_private_key());

    // Create leaf signed by CA
    let leaf_options = CertificateOptions::new()
        .with_subject_name("CN=Test Leaf Signed")
        .with_key_algorithm(KeyAlgorithm::Ecdsa)
        .signed_by(ca_cert.clone());

    let leaf_cert = factory.create_certificate(leaf_options).unwrap();
    assert!(leaf_cert.has_private_key());
    assert!(!leaf_cert.cert_der.is_empty());

    // Verify issuer name matches CA subject
    use x509_parser::prelude::*;
    let (_, parsed_leaf) = X509Certificate::from_der(&leaf_cert.cert_der).unwrap();
    let (_, parsed_ca) = X509Certificate::from_der(&ca_cert.cert_der).unwrap();
    assert_eq!(
        parsed_leaf.issuer().to_string(),
        parsed_ca.subject().to_string()
    );
    assert!(parsed_leaf
        .subject()
        .to_string()
        .contains("Test Leaf Signed"));
}

// ---------------------------------------------------------------------------
// Factory: CA with basic constraints (exercises lines 211-224)
// ---------------------------------------------------------------------------

/// Create a CA certificate with path length constraint and key usage.
/// Covers: lines 211-224 (BasicConstraints + KeyUsage extensions).
#[test]
fn factory_create_ca_with_basic_constraints() {
    let provider = Box::new(SoftwareKeyProvider::new());
    let factory = EphemeralCertificateFactory::new(provider);

    let options = CertificateOptions::new()
        .with_subject_name("CN=Constrained CA")
        .with_key_algorithm(KeyAlgorithm::Ecdsa)
        .as_ca(2); // path length 2

    let cert = factory.create_certificate(options).unwrap();

    use x509_parser::prelude::*;
    let (_, parsed) = X509Certificate::from_der(&cert.cert_der).unwrap();

    // Verify basic constraints
    let mut found_bc = false;
    for ext in parsed.extensions() {
        if let ParsedExtension::BasicConstraints(bc) = ext.parsed_extension() {
            found_bc = true;
            assert!(bc.ca, "should be CA");
            assert_eq!(bc.path_len_constraint, Some(2));
        }
    }
    assert!(found_bc, "BasicConstraints extension should be present");

    // Verify key usage includes key_cert_sign and crl_sign
    let mut found_ku = false;
    for ext in parsed.extensions() {
        if let ParsedExtension::KeyUsage(ku) = ext.parsed_extension() {
            found_ku = true;
            assert!(ku.key_cert_sign(), "should have KeyCertSign");
            assert!(ku.crl_sign(), "should have CrlSign");
        }
    }
    assert!(found_ku, "KeyUsage extension should be present for CA");
}

/// Create a CA with u32::MAX path_length_constraint (unbounded).
/// Covers: line 214 (path_length_constraint < u32::MAX branch skipped).
#[test]
fn factory_create_ca_unbounded_path_length() {
    let provider = Box::new(SoftwareKeyProvider::new());
    let factory = EphemeralCertificateFactory::new(provider);

    let mut options = CertificateOptions::new()
        .with_subject_name("CN=Unbounded CA")
        .with_key_algorithm(KeyAlgorithm::Ecdsa);
    options.is_ca = true;
    options.path_length_constraint = u32::MAX;

    let cert = factory.create_certificate(options).unwrap();

    use x509_parser::prelude::*;
    let (_, parsed) = X509Certificate::from_der(&cert.cert_der).unwrap();

    let mut found_bc = false;
    for ext in parsed.extensions() {
        if let ParsedExtension::BasicConstraints(bc) = ext.parsed_extension() {
            found_bc = true;
            assert!(bc.ca, "should be CA");
            // With u32::MAX, pathlen should NOT be set (unconstrained)
            assert!(
                bc.path_len_constraint.is_none(),
                "path_len_constraint should be None for u32::MAX"
            );
        }
    }
    assert!(found_bc, "BasicConstraints extension should be present");
}

// ---------------------------------------------------------------------------
// Factory: RSA key generation succeeds
// ---------------------------------------------------------------------------

/// RSA key generation is fully supported.
#[test]
fn factory_rsa_key_generation_succeeds() {
    let provider = Box::new(SoftwareKeyProvider::new());
    let factory = EphemeralCertificateFactory::new(provider);

    let options = CertificateOptions::new()
        .with_subject_name("CN=RSA Test")
        .with_key_algorithm(KeyAlgorithm::Rsa);

    let cert = factory.create_certificate(options).unwrap();
    assert!(!cert.cert_der.is_empty());
    assert!(cert.has_private_key());
    let subject = cert.subject().unwrap();
    assert!(subject.contains("RSA Test"), "subject: {subject}");
}

// ---------------------------------------------------------------------------
// Factory: get_generated_key and release_key (lines 45-60)
// ---------------------------------------------------------------------------

/// After creating a certificate, retrieve its generated key by serial number.
/// Covers: lines 45-49 (get_generated_key), 55-60 (release_key),
/// lines 294-303 (key storage after creation).
#[test]
fn factory_get_and_release_generated_key() {
    let provider = Box::new(SoftwareKeyProvider::new());
    let factory = EphemeralCertificateFactory::new(provider);

    let cert = factory.create_certificate_default().unwrap();

    // Extract serial number from the certificate
    use x509_parser::prelude::*;
    let (_, parsed) = X509Certificate::from_der(&cert.cert_der).unwrap();
    let serial_hex: String = parsed
        .serial
        .to_bytes_be()
        .iter()
        .map(|b| format!("{:02X}", b))
        .collect();

    // Retrieve the generated key
    let key = factory.get_generated_key(&serial_hex);
    assert!(key.is_some(), "Generated key should be retrievable");

    let key = key.unwrap();
    assert!(!key.private_key_der.is_empty());
    assert!(!key.public_key_der.is_empty());
    assert!(matches!(key.algorithm, KeyAlgorithm::Ecdsa));

    // Release the key
    let released = factory.release_key(&serial_hex);
    assert!(released, "Key should be releasable");

    // After release, key should be gone
    let key_after = factory.get_generated_key(&serial_hex);
    assert!(key_after.is_none(), "Key should be gone after release");

    // Releasing again should return false
    let released_again = factory.release_key(&serial_hex);
    assert!(!released_again, "Second release should return false");
}

// ---------------------------------------------------------------------------
// Factory: key_provider accessor
// ---------------------------------------------------------------------------

/// Verify key_provider() returns the provider.
/// Covers: line 148-150 (key_provider method).
#[test]
fn factory_key_provider_returns_provider() {
    let provider = Box::new(SoftwareKeyProvider::new());
    let factory = EphemeralCertificateFactory::new(provider);

    let provider = factory.key_provider();
    assert_eq!(provider.name(), "SoftwareKeyProvider");
}

// ---------------------------------------------------------------------------
// Factory: three-tier chain (root -> intermediate -> leaf) exercises the
// issuer-signed path multiple times
// ---------------------------------------------------------------------------

/// Build a three-tier chain to fully exercise issuer-signed path.
/// Covers: lines 228-244 (issuer path) called twice (intermediate, then leaf).
#[test]
fn factory_three_tier_chain() {
    let provider = Box::new(SoftwareKeyProvider::new());
    let factory = EphemeralCertificateFactory::new(provider);

    // Root CA
    let root = factory
        .create_certificate(
            CertificateOptions::new()
                .with_subject_name("CN=Root CA")
                .with_key_algorithm(KeyAlgorithm::Ecdsa)
                .as_ca(2),
        )
        .unwrap();

    // Intermediate CA signed by root
    let intermediate = factory
        .create_certificate(
            CertificateOptions::new()
                .with_subject_name("CN=Intermediate CA")
                .with_key_algorithm(KeyAlgorithm::Ecdsa)
                .as_ca(0)
                .signed_by(root.clone()),
        )
        .unwrap();

    // Leaf signed by intermediate
    let leaf = factory
        .create_certificate(
            CertificateOptions::new()
                .with_subject_name("CN=Leaf Cert")
                .with_key_algorithm(KeyAlgorithm::Ecdsa)
                .signed_by(intermediate.clone()),
        )
        .unwrap();

    // Verify chain
    use x509_parser::prelude::*;
    let (_, parsed_root) = X509Certificate::from_der(&root.cert_der).unwrap();
    let (_, parsed_inter) = X509Certificate::from_der(&intermediate.cert_der).unwrap();
    let (_, parsed_leaf) = X509Certificate::from_der(&leaf.cert_der).unwrap();

    // Root is self-signed
    assert_eq!(
        parsed_root.subject().to_string(),
        parsed_root.issuer().to_string()
    );

    // Intermediate issuer == root subject
    assert_eq!(
        parsed_inter.issuer().to_string(),
        parsed_root.subject().to_string()
    );

    // Leaf issuer == intermediate subject
    assert_eq!(
        parsed_leaf.issuer().to_string(),
        parsed_inter.subject().to_string()
    );
}

// ---------------------------------------------------------------------------
// Factory: subject name with CN= prefix stripping
// ---------------------------------------------------------------------------

/// Subject name that already starts with "CN=" should be handled correctly.
/// Covers: line 187 (strip_prefix("CN=")).
#[test]
fn factory_subject_name_with_cn_prefix() {
    let provider = Box::new(SoftwareKeyProvider::new());
    let factory = EphemeralCertificateFactory::new(provider);

    let options = CertificateOptions::new()
        .with_subject_name("CN=Already Prefixed")
        .with_key_algorithm(KeyAlgorithm::Ecdsa);

    let cert = factory.create_certificate(options).unwrap();

    use x509_parser::prelude::*;
    let (_, parsed) = X509Certificate::from_der(&cert.cert_der).unwrap();
    let subject = parsed.subject().to_string();
    assert!(subject.contains("Already Prefixed"));
    // Should NOT have double CN=
    assert!(!subject.contains("CN=CN="));
}

/// Subject name without CN= prefix.
/// Covers: line 187 (strip_prefix returns None, uses original value).
#[test]
fn factory_subject_name_without_cn_prefix() {
    let provider = Box::new(SoftwareKeyProvider::new());
    let factory = EphemeralCertificateFactory::new(provider);

    let options = CertificateOptions::new()
        .with_subject_name("No Prefix Subject")
        .with_key_algorithm(KeyAlgorithm::Ecdsa);

    let cert = factory.create_certificate(options).unwrap();

    use x509_parser::prelude::*;
    let (_, parsed) = X509Certificate::from_der(&cert.cert_der).unwrap();
    let subject = parsed.subject().to_string();
    assert!(subject.contains("No Prefix Subject"));
}

// ---------------------------------------------------------------------------
// Factory: default certificate options
// ---------------------------------------------------------------------------

/// Verify create_certificate_default uses CertificateOptions::default().
/// Covers: line 67-68 (create_certificate_default trait method).
#[test]
fn factory_create_default_uses_default_options() {
    let provider = Box::new(SoftwareKeyProvider::new());
    let factory = EphemeralCertificateFactory::new(provider);

    let cert = factory.create_certificate_default().unwrap();
    assert!(cert.has_private_key());

    use x509_parser::prelude::*;
    let (_, parsed) = X509Certificate::from_der(&cert.cert_der).unwrap();
    // Default subject name is "CN=Ephemeral Certificate"
    assert!(parsed
        .subject()
        .to_string()
        .contains("Ephemeral Certificate"));
}

// ---------------------------------------------------------------------------
// Factory: custom validity and not_before_offset
// ---------------------------------------------------------------------------

/// Exercise validity and not_before_offset code paths.
/// Covers: lines 195-204 (Asn1Time creation, set_not_before, set_not_after).
#[test]
fn factory_custom_validity_and_offset() {
    let provider = Box::new(SoftwareKeyProvider::new());
    let factory = EphemeralCertificateFactory::new(provider);

    let options = CertificateOptions::new()
        .with_subject_name("CN=Custom Validity")
        .with_key_algorithm(KeyAlgorithm::Ecdsa)
        .with_validity(Duration::from_secs(86400)) // 24 hours
        .with_not_before_offset(Duration::from_secs(600)); // 10 minutes

    let cert = factory.create_certificate(options).unwrap();

    use x509_parser::prelude::*;
    let (_, parsed) = X509Certificate::from_der(&cert.cert_der).unwrap();
    let validity = parsed.validity();
    // not_after should be later than not_before
    assert!(validity.not_after.timestamp() > validity.not_before.timestamp());
    // Validity window should be approximately 24h + 10min = 87000s
    let window = validity.not_after.timestamp() - validity.not_before.timestamp();
    assert!(
        window > 86000 && window < 88000,
        "Expected ~87000s window, got {}",
        window
    );
}
