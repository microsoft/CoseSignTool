// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Enhanced coverage tests targeting ≥90% line coverage for cose_sign1_certificates_local.
//!
//! Each test is self-contained with its own factory instance.
//! All tests are parallel-safe (no shared mutable state).

use cose_sign1_certificates_local::certificate::Certificate;
use cose_sign1_certificates_local::chain_factory::{CertificateChainFactory, CertificateChainOptions};
use cose_sign1_certificates_local::factory::EphemeralCertificateFactory;
use cose_sign1_certificates_local::key_algorithm::KeyAlgorithm;
use cose_sign1_certificates_local::options::{
    CertificateOptions, CustomExtension, HashAlgorithm, SigningPadding,
};
use cose_sign1_certificates_local::software_key::SoftwareKeyProvider;
use cose_sign1_certificates_local::traits::{CertificateFactory, PrivateKeyProvider};
use x509_parser::prelude::*;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn make_factory() -> EphemeralCertificateFactory {
    EphemeralCertificateFactory::new(Box::new(SoftwareKeyProvider::new()))
}

fn make_chain_factory() -> CertificateChainFactory {
    CertificateChainFactory::new(make_factory())
}

/// Parse a DER certificate and return the parsed X509Certificate (owned via bytes).
fn parse_cert(der: &[u8]) -> (Vec<u8>, x509_parser::certificate::X509Certificate<'static>) {
    // We need to own the bytes so the parsed cert can live long enough.
    // Use a trick: leak the bytes so the borrow is 'static.
    let owned = der.to_vec().into_boxed_slice();
    let leaked: &'static [u8] = Box::leak(owned);
    let (_, cert) = X509Certificate::from_der(leaked).expect("failed to parse DER certificate");
    (der.to_vec(), cert)
}

// OIDs for X.509 extensions
const OID_SKI: &[u64] = &[2, 5, 29, 14]; // Subject Key Identifier
const OID_AKI: &[u64] = &[2, 5, 29, 35]; // Authority Key Identifier

fn has_extension(cert: &X509Certificate<'_>, oid_components: &[u64]) -> bool {
    let target = x509_parser::oid_registry::Oid::from(oid_components).unwrap();
    cert.extensions().iter().any(|ext| ext.oid == target)
}

// ===========================================================================
// key_algorithm.rs coverage
// ===========================================================================

#[test]
fn eddsa_is_pure_signature_returns_true() {
    assert!(KeyAlgorithm::EdDsa.is_pure_signature());
}

#[test]
fn ecdsa_is_not_pure_signature() {
    assert!(!KeyAlgorithm::Ecdsa.is_pure_signature());
}

#[test]
fn rsa_is_not_pure_signature() {
    assert!(!KeyAlgorithm::Rsa.is_pure_signature());
}

#[test]
fn eddsa_default_key_size_is_255() {
    assert_eq!(KeyAlgorithm::EdDsa.default_key_size(), 255);
}

// ===========================================================================
// software_key.rs — EdDSA key generation
// ===========================================================================

#[test]
fn software_key_supports_eddsa() {
    let provider = SoftwareKeyProvider::new();
    assert!(provider.supports_algorithm(KeyAlgorithm::EdDsa));
}

#[test]
fn software_key_generate_ed25519() {
    let provider = SoftwareKeyProvider::new();
    let key = provider
        .generate_key(KeyAlgorithm::EdDsa, None)
        .expect("Ed25519 key generation should succeed");
    assert_eq!(key.algorithm, KeyAlgorithm::EdDsa);
    assert_eq!(key.key_size, 255);
    assert!(!key.private_key_der.is_empty());
    assert!(!key.public_key_der.is_empty());
}

#[test]
fn software_key_generate_ed448() {
    let provider = SoftwareKeyProvider::new();
    let key = provider
        .generate_key(KeyAlgorithm::EdDsa, Some(448))
        .expect("Ed448 key generation should succeed");
    assert_eq!(key.algorithm, KeyAlgorithm::EdDsa);
    assert_eq!(key.key_size, 448);
    assert!(!key.private_key_der.is_empty());
    assert!(!key.public_key_der.is_empty());
}

#[test]
fn software_key_generate_ed25519_explicit_size() {
    let provider = SoftwareKeyProvider::new();
    let key = provider
        .generate_key(KeyAlgorithm::EdDsa, Some(255))
        .expect("Ed25519 with explicit size 255 should succeed");
    assert_eq!(key.key_size, 255);
}

// ===========================================================================
// factory.rs — EdDSA certificate creation (self-signed)
// ===========================================================================

#[test]
fn create_self_signed_ed25519_certificate() {
    let factory = make_factory();
    let cert = factory
        .create_certificate(
            CertificateOptions::new()
                .with_subject_name("CN=Ed25519 Test")
                .with_key_algorithm(KeyAlgorithm::EdDsa),
        )
        .expect("Ed25519 self-signed cert should succeed");

    assert!(cert.has_private_key());
    let (_, parsed) = parse_cert(&cert.cert_der);
    assert!(parsed.subject().to_string().contains("Ed25519 Test"));
}

#[test]
fn create_self_signed_ed448_certificate() {
    let factory = make_factory();
    let cert = factory
        .create_certificate(
            CertificateOptions::new()
                .with_subject_name("CN=Ed448 Test")
                .with_key_algorithm(KeyAlgorithm::EdDsa)
                .with_key_size(448),
        )
        .expect("Ed448 self-signed cert should succeed");

    assert!(cert.has_private_key());
    let (_, parsed) = parse_cert(&cert.cert_der);
    assert!(parsed.subject().to_string().contains("Ed448 Test"));
}

// ===========================================================================
// factory.rs — Hash algorithm selection via resolve_digest
// ===========================================================================

#[test]
fn ecdsa_with_sha384() {
    let factory = make_factory();
    let cert = factory
        .create_certificate(
            CertificateOptions::new()
                .with_subject_name("CN=ECDSA SHA384")
                .with_key_algorithm(KeyAlgorithm::Ecdsa)
                .with_key_size(384)
                .with_hash_algorithm(HashAlgorithm::Sha384),
        )
        .expect("ECDSA with SHA-384 should succeed");

    let (_, parsed) = parse_cert(&cert.cert_der);
    let sig_alg = parsed.signature_algorithm.algorithm.to_string();
    // ecdsa-with-SHA384 OID = 1.2.840.10045.4.3.3
    assert!(
        sig_alg.contains("1.2.840.10045.4.3.3"),
        "Expected ecdsa-with-SHA384 OID, got: {}",
        sig_alg
    );
}

#[test]
fn ecdsa_with_sha512() {
    let factory = make_factory();
    let cert = factory
        .create_certificate(
            CertificateOptions::new()
                .with_subject_name("CN=ECDSA SHA512")
                .with_key_algorithm(KeyAlgorithm::Ecdsa)
                .with_key_size(521)
                .with_hash_algorithm(HashAlgorithm::Sha512),
        )
        .expect("ECDSA with SHA-512 should succeed");

    let (_, parsed) = parse_cert(&cert.cert_der);
    let sig_alg = parsed.signature_algorithm.algorithm.to_string();
    // ecdsa-with-SHA512 OID = 1.2.840.10045.4.3.4
    assert!(
        sig_alg.contains("1.2.840.10045.4.3.4"),
        "Expected ecdsa-with-SHA512 OID, got: {}",
        sig_alg
    );
}

#[test]
fn rsa_with_sha384() {
    let factory = make_factory();
    let cert = factory
        .create_certificate(
            CertificateOptions::new()
                .with_subject_name("CN=RSA SHA384")
                .with_key_algorithm(KeyAlgorithm::Rsa)
                .with_key_size(2048)
                .with_hash_algorithm(HashAlgorithm::Sha384),
        )
        .expect("RSA with SHA-384 should succeed");

    let (_, parsed) = parse_cert(&cert.cert_der);
    let sig_alg = parsed.signature_algorithm.algorithm.to_string();
    // sha384WithRSAEncryption OID = 1.2.840.113549.1.1.12
    assert!(
        sig_alg.contains("1.2.840.113549.1.1.12"),
        "Expected sha384WithRSAEncryption OID, got: {}",
        sig_alg
    );
}

#[test]
fn rsa_with_sha512() {
    let factory = make_factory();
    let cert = factory
        .create_certificate(
            CertificateOptions::new()
                .with_subject_name("CN=RSA SHA512")
                .with_key_algorithm(KeyAlgorithm::Rsa)
                .with_key_size(2048)
                .with_hash_algorithm(HashAlgorithm::Sha512),
        )
        .expect("RSA with SHA-512 should succeed");

    let (_, parsed) = parse_cert(&cert.cert_der);
    let sig_alg = parsed.signature_algorithm.algorithm.to_string();
    // sha512WithRSAEncryption OID = 1.2.840.113549.1.1.13
    assert!(
        sig_alg.contains("1.2.840.113549.1.1.13"),
        "Expected sha512WithRSAEncryption OID, got: {}",
        sig_alg
    );
}

// ===========================================================================
// factory.rs — RSA-PSS signing
// ===========================================================================

#[test]
fn rsa_pss_self_signed_sha256() {
    let factory = make_factory();
    let cert = factory
        .create_certificate(
            CertificateOptions::new()
                .with_subject_name("CN=RSA-PSS SHA256")
                .with_key_algorithm(KeyAlgorithm::Rsa)
                .with_key_size(2048)
                .with_signing_padding(SigningPadding::Pss)
                .with_hash_algorithm(HashAlgorithm::Sha256),
        )
        .expect("RSA-PSS with SHA-256 should succeed");

    assert!(cert.has_private_key());
    let (_, parsed) = parse_cert(&cert.cert_der);
    let sig_alg = parsed.signature_algorithm.algorithm.to_string();
    // RSASSA-PSS OID = 1.2.840.113549.1.1.10
    assert!(
        sig_alg.contains("1.2.840.113549.1.1.10"),
        "Expected RSASSA-PSS OID, got: {}",
        sig_alg
    );
}

#[test]
fn rsa_pss_self_signed_sha384() {
    let factory = make_factory();
    let cert = factory
        .create_certificate(
            CertificateOptions::new()
                .with_subject_name("CN=RSA-PSS SHA384")
                .with_key_algorithm(KeyAlgorithm::Rsa)
                .with_key_size(2048)
                .with_signing_padding(SigningPadding::Pss)
                .with_hash_algorithm(HashAlgorithm::Sha384),
        )
        .expect("RSA-PSS with SHA-384 should succeed");

    let (_, parsed) = parse_cert(&cert.cert_der);
    let sig_alg = parsed.signature_algorithm.algorithm.to_string();
    assert!(
        sig_alg.contains("1.2.840.113549.1.1.10"),
        "Expected RSASSA-PSS OID, got: {}",
        sig_alg
    );
}

#[test]
fn rsa_pss_self_signed_sha512() {
    let factory = make_factory();
    let cert = factory
        .create_certificate(
            CertificateOptions::new()
                .with_subject_name("CN=RSA-PSS SHA512")
                .with_key_algorithm(KeyAlgorithm::Rsa)
                .with_key_size(2048)
                .with_signing_padding(SigningPadding::Pss)
                .with_hash_algorithm(HashAlgorithm::Sha512),
        )
        .expect("RSA-PSS with SHA-512 should succeed");

    let (_, parsed) = parse_cert(&cert.cert_der);
    let sig_alg = parsed.signature_algorithm.algorithm.to_string();
    assert!(
        sig_alg.contains("1.2.840.113549.1.1.10"),
        "Expected RSASSA-PSS OID, got: {}",
        sig_alg
    );
}

// ===========================================================================
// factory.rs — Subject Key Identifier (SKI) emitted on all certs
// ===========================================================================

#[test]
fn self_signed_ecdsa_has_ski() {
    let factory = make_factory();
    let cert = factory
        .create_certificate(
            CertificateOptions::new()
                .with_subject_name("CN=SKI Test ECDSA")
                .with_key_algorithm(KeyAlgorithm::Ecdsa),
        )
        .expect("ECDSA cert should succeed");

    let (_, parsed) = parse_cert(&cert.cert_der);
    assert!(
        has_extension(&parsed, OID_SKI),
        "Self-signed ECDSA cert should have Subject Key Identifier"
    );
}

#[test]
fn self_signed_eddsa_has_ski() {
    let factory = make_factory();
    let cert = factory
        .create_certificate(
            CertificateOptions::new()
                .with_subject_name("CN=SKI Test EdDSA")
                .with_key_algorithm(KeyAlgorithm::EdDsa),
        )
        .expect("EdDSA cert should succeed");

    let (_, parsed) = parse_cert(&cert.cert_der);
    assert!(
        has_extension(&parsed, OID_SKI),
        "Self-signed EdDSA cert should have Subject Key Identifier"
    );
}

#[test]
fn self_signed_rsa_has_ski() {
    let factory = make_factory();
    let cert = factory
        .create_certificate(
            CertificateOptions::new()
                .with_subject_name("CN=SKI Test RSA")
                .with_key_algorithm(KeyAlgorithm::Rsa)
                .with_key_size(2048),
        )
        .expect("RSA cert should succeed");

    let (_, parsed) = parse_cert(&cert.cert_der);
    assert!(
        has_extension(&parsed, OID_SKI),
        "Self-signed RSA cert should have Subject Key Identifier"
    );
}

// ===========================================================================
// factory.rs — Authority Key Identifier (AKI) on issuer-signed certs
// ===========================================================================

#[test]
fn issuer_signed_ecdsa_has_aki() {
    let factory = make_factory();

    // Create issuer (CA)
    let issuer = factory
        .create_certificate(
            CertificateOptions::new()
                .with_subject_name("CN=AKI Test CA")
                .with_key_algorithm(KeyAlgorithm::Ecdsa)
                .as_ca(1),
        )
        .expect("CA cert should succeed");

    // Create leaf signed by issuer
    let leaf = factory
        .create_certificate(
            CertificateOptions::new()
                .with_subject_name("CN=AKI Test Leaf")
                .with_key_algorithm(KeyAlgorithm::Ecdsa)
                .signed_by(issuer),
        )
        .expect("Leaf cert signed by issuer should succeed");

    let (_, parsed) = parse_cert(&leaf.cert_der);
    assert!(
        has_extension(&parsed, OID_AKI),
        "Issuer-signed cert must have Authority Key Identifier"
    );
    assert!(
        has_extension(&parsed, OID_SKI),
        "Issuer-signed cert must also have Subject Key Identifier"
    );
}

// ===========================================================================
// factory.rs — Custom extensions
// ===========================================================================

#[test]
fn custom_extension_via_add_custom_extension() {
    let factory = make_factory();
    let custom_oid = "1.2.3.4.5.6.7.8.9";
    let custom_value = vec![0x01, 0x02, 0x03];

    let cert = factory
        .create_certificate(
            CertificateOptions::new()
                .with_subject_name("CN=Custom Ext Test")
                .with_key_algorithm(KeyAlgorithm::Ecdsa)
                .add_custom_extension(CustomExtension::new(
                    custom_oid,
                    false,
                    custom_value.clone(),
                )),
        )
        .expect("Cert with custom extension should succeed");

    let (_, parsed) = parse_cert(&cert.cert_der);
    let found = parsed.extensions().iter().any(|ext| {
        ext.oid.to_string() == custom_oid
    });
    assert!(found, "Custom extension with OID {} should be present", custom_oid);
}

#[test]
fn custom_extension_via_add_custom_extension_der() {
    let factory = make_factory();
    let custom_oid = "1.2.3.4.5.6.7.8.10";
    let custom_value = vec![0xDE, 0xAD, 0xBE, 0xEF];

    let cert = factory
        .create_certificate(
            CertificateOptions::new()
                .with_subject_name("CN=Custom DER Ext Test")
                .with_key_algorithm(KeyAlgorithm::Ecdsa)
                .add_custom_extension_der(custom_oid, true, custom_value),
        )
        .expect("Cert with custom DER extension should succeed");

    let (_, parsed) = parse_cert(&cert.cert_der);
    let ext = parsed.extensions().iter().find(|ext| {
        ext.oid.to_string() == custom_oid
    });
    assert!(ext.is_some(), "Custom DER extension should be present");
    assert!(ext.unwrap().critical, "Custom DER extension should be critical");
}

#[test]
fn multiple_custom_extensions() {
    let factory = make_factory();

    let cert = factory
        .create_certificate(
            CertificateOptions::new()
                .with_subject_name("CN=Multi Ext Test")
                .with_key_algorithm(KeyAlgorithm::Ecdsa)
                .add_custom_extension(CustomExtension::new("1.2.3.4.5.100", false, vec![0x01]))
                .add_custom_extension_der("1.2.3.4.5.101", true, vec![0x02]),
        )
        .expect("Cert with multiple custom extensions should succeed");

    let (_, parsed) = parse_cert(&cert.cert_der);
    let oids: Vec<String> = parsed.extensions().iter().map(|e| e.oid.to_string()).collect();
    assert!(oids.contains(&"1.2.3.4.5.100".to_string()));
    assert!(oids.contains(&"1.2.3.4.5.101".to_string()));
}

// ===========================================================================
// factory.rs — Issuer-signed EdDSA certs (hybrid scenario)
// ===========================================================================

#[test]
fn eddsa_leaf_signed_by_ecdsa_issuer() {
    let factory = make_factory();

    // ECDSA CA
    let ca = factory
        .create_certificate(
            CertificateOptions::new()
                .with_subject_name("CN=Hybrid CA ECDSA")
                .with_key_algorithm(KeyAlgorithm::Ecdsa)
                .as_ca(1),
        )
        .expect("ECDSA CA should succeed");

    // EdDSA leaf signed by ECDSA CA
    let leaf = factory
        .create_certificate(
            CertificateOptions::new()
                .with_subject_name("CN=Hybrid Leaf EdDSA")
                .with_key_algorithm(KeyAlgorithm::EdDsa)
                .signed_by(ca),
        )
        .expect("EdDSA leaf signed by ECDSA issuer should succeed");

    assert!(leaf.has_private_key());
    let (_, parsed) = parse_cert(&leaf.cert_der);
    assert!(parsed.subject().to_string().contains("Hybrid Leaf EdDSA"));
    assert!(has_extension(&parsed, OID_AKI));
    assert!(has_extension(&parsed, OID_SKI));
}

#[test]
fn eddsa_leaf_signed_by_rsa_issuer() {
    let factory = make_factory();

    let ca = factory
        .create_certificate(
            CertificateOptions::new()
                .with_subject_name("CN=Hybrid CA RSA")
                .with_key_algorithm(KeyAlgorithm::Rsa)
                .with_key_size(2048)
                .as_ca(1),
        )
        .expect("RSA CA should succeed");

    let leaf = factory
        .create_certificate(
            CertificateOptions::new()
                .with_subject_name("CN=Hybrid Leaf EdDSA from RSA")
                .with_key_algorithm(KeyAlgorithm::EdDsa)
                .signed_by(ca),
        )
        .expect("EdDSA leaf signed by RSA issuer should succeed");

    assert!(leaf.has_private_key());
    let (_, parsed) = parse_cert(&leaf.cert_der);
    assert!(has_extension(&parsed, OID_AKI));
}

// ===========================================================================
// factory.rs — RSA-PSS issuer-signed
// ===========================================================================

#[test]
fn rsa_pss_leaf_signed_by_rsa_pss_ca() {
    let factory = make_factory();

    let ca = factory
        .create_certificate(
            CertificateOptions::new()
                .with_subject_name("CN=RSA-PSS CA")
                .with_key_algorithm(KeyAlgorithm::Rsa)
                .with_key_size(2048)
                .with_signing_padding(SigningPadding::Pss)
                .as_ca(1),
        )
        .expect("RSA-PSS CA should succeed");

    let leaf = factory
        .create_certificate(
            CertificateOptions::new()
                .with_subject_name("CN=RSA-PSS Leaf")
                .with_key_algorithm(KeyAlgorithm::Rsa)
                .with_key_size(2048)
                .with_signing_padding(SigningPadding::Pss)
                .signed_by(ca),
        )
        .expect("RSA-PSS leaf signed by RSA-PSS CA should succeed");

    let (_, parsed) = parse_cert(&leaf.cert_der);
    let sig_alg = parsed.signature_algorithm.algorithm.to_string();
    assert!(
        sig_alg.contains("1.2.840.113549.1.1.10"),
        "Leaf should use RSASSA-PSS, got: {}",
        sig_alg
    );
    assert!(has_extension(&parsed, OID_AKI));
}

// ===========================================================================
// factory.rs — EdDSA CA self-signed (CA mode)
// ===========================================================================

#[test]
fn eddsa_ca_self_signed() {
    let factory = make_factory();
    let cert = factory
        .create_certificate(
            CertificateOptions::new()
                .with_subject_name("CN=EdDSA CA")
                .with_key_algorithm(KeyAlgorithm::EdDsa)
                .as_ca(2),
        )
        .expect("EdDSA CA should succeed");

    let (_, parsed) = parse_cert(&cert.cert_der);
    assert!(parsed.is_ca());
}

// ===========================================================================
// factory.rs — get_generated_key and release_key
// ===========================================================================

#[test]
fn get_and_release_generated_key() {
    let factory = make_factory();
    let cert = factory
        .create_certificate(
            CertificateOptions::new()
                .with_subject_name("CN=Key Retrieval Test")
                .with_key_algorithm(KeyAlgorithm::Ecdsa),
        )
        .expect("cert creation should succeed");

    // Extract serial hex from the cert
    let (_, parsed) = parse_cert(&cert.cert_der);
    let serial_hex: String = parsed
        .serial
        .to_bytes_be()
        .iter()
        .map(|b| format!("{:02X}", b))
        .collect();

    // Should be able to retrieve the generated key
    let key = factory.get_generated_key(&serial_hex);
    assert!(key.is_some(), "Generated key should be retrievable by serial hex");
    let key = key.unwrap();
    assert_eq!(key.algorithm, KeyAlgorithm::Ecdsa);

    // Release the key
    assert!(factory.release_key(&serial_hex), "Release should return true for existing key");
    assert!(!factory.release_key(&serial_hex), "Second release should return false");
    assert!(factory.get_generated_key(&serial_hex).is_none(), "Key should be gone after release");
}

// ===========================================================================
// factory.rs — EdDSA with default key_size (None)
// ===========================================================================

#[test]
fn eddsa_default_key_size_resolves_to_ed25519() {
    let factory = make_factory();
    let cert = factory
        .create_certificate(
            CertificateOptions::new()
                .with_subject_name("CN=EdDSA Default")
                .with_key_algorithm(KeyAlgorithm::EdDsa),
            // key_size is None → defaults to Ed25519
        )
        .expect("EdDSA with default size should produce Ed25519");

    // Extract stored key and verify size
    let (_, parsed) = parse_cert(&cert.cert_der);
    let serial_hex: String = parsed
        .serial
        .to_bytes_be()
        .iter()
        .map(|b| format!("{:02X}", b))
        .collect();

    let key = factory.get_generated_key(&serial_hex);
    assert!(key.is_some());
    assert_eq!(key.unwrap().key_size, 255); // Ed25519 default
}

// ===========================================================================
// factory.rs — Issuer without private key should fail
// ===========================================================================

#[test]
fn issuer_without_private_key_fails() {
    let factory = make_factory();

    // Create an issuer cert then strip its private key
    let ca = factory
        .create_certificate(
            CertificateOptions::new()
                .with_subject_name("CN=No Key CA")
                .with_key_algorithm(KeyAlgorithm::Ecdsa)
                .as_ca(1),
        )
        .expect("CA should succeed");

    let stripped_ca = Certificate::new(ca.cert_der); // no private key

    let result = factory.create_certificate(
        CertificateOptions::new()
            .with_subject_name("CN=Should Fail Leaf")
            .with_key_algorithm(KeyAlgorithm::Ecdsa)
            .signed_by(stripped_ca),
    );

    assert!(result.is_err(), "Signing with issuer that has no private key should fail");
}

// ===========================================================================
// factory.rs — ECDSA with SHA-256 (default) — ensure resolve_digest Sha256 path
// ===========================================================================

#[test]
fn ecdsa_sha256_default_digest() {
    let factory = make_factory();
    let cert = factory
        .create_certificate(
            CertificateOptions::new()
                .with_subject_name("CN=ECDSA SHA256 Default")
                .with_key_algorithm(KeyAlgorithm::Ecdsa)
                .with_hash_algorithm(HashAlgorithm::Sha256),
        )
        .expect("ECDSA with SHA-256 should succeed");

    let (_, parsed) = parse_cert(&cert.cert_der);
    let sig_alg = parsed.signature_algorithm.algorithm.to_string();
    // ecdsa-with-SHA256 OID = 1.2.840.10045.4.3.2
    assert!(
        sig_alg.contains("1.2.840.10045.4.3.2"),
        "Expected ecdsa-with-SHA256, got: {}",
        sig_alg
    );
}

// ===========================================================================
// factory.rs — RSA with PKCS1v15 (default padding, explicit)
// ===========================================================================

#[test]
fn rsa_pkcs1v15_explicit_padding() {
    let factory = make_factory();
    let cert = factory
        .create_certificate(
            CertificateOptions::new()
                .with_subject_name("CN=RSA PKCS1v15")
                .with_key_algorithm(KeyAlgorithm::Rsa)
                .with_key_size(2048)
                .with_signing_padding(SigningPadding::Pkcs1v15)
                .with_hash_algorithm(HashAlgorithm::Sha256),
        )
        .expect("RSA PKCS1v15 should succeed");

    let (_, parsed) = parse_cert(&cert.cert_der);
    let sig_alg = parsed.signature_algorithm.algorithm.to_string();
    // sha256WithRSAEncryption OID = 1.2.840.113549.1.1.11
    assert!(
        sig_alg.contains("1.2.840.113549.1.1.11"),
        "Expected sha256WithRSAEncryption, got: {}",
        sig_alg
    );
}

// ===========================================================================
// factory.rs — RSA key sizes
// ===========================================================================

#[test]
fn rsa_3072_key_size() {
    let factory = make_factory();
    let cert = factory
        .create_certificate(
            CertificateOptions::new()
                .with_subject_name("CN=RSA 3072")
                .with_key_algorithm(KeyAlgorithm::Rsa)
                .with_key_size(3072),
        )
        .expect("RSA-3072 should succeed");
    assert!(cert.has_private_key());
}

#[test]
fn rsa_4096_key_size() {
    let factory = make_factory();
    let cert = factory
        .create_certificate(
            CertificateOptions::new()
                .with_subject_name("CN=RSA 4096")
                .with_key_algorithm(KeyAlgorithm::Rsa)
                .with_key_size(4096),
        )
        .expect("RSA-4096 should succeed");
    assert!(cert.has_private_key());
}

// ===========================================================================
// factory.rs — ECDSA key sizes (P-384, P-521)
// ===========================================================================

#[test]
fn ecdsa_p384() {
    let factory = make_factory();
    let cert = factory
        .create_certificate(
            CertificateOptions::new()
                .with_subject_name("CN=ECDSA P384")
                .with_key_algorithm(KeyAlgorithm::Ecdsa)
                .with_key_size(384),
        )
        .expect("ECDSA P-384 should succeed");
    assert!(cert.has_private_key());
}

#[test]
fn ecdsa_p521() {
    let factory = make_factory();
    let cert = factory
        .create_certificate(
            CertificateOptions::new()
                .with_subject_name("CN=ECDSA P521")
                .with_key_algorithm(KeyAlgorithm::Ecdsa)
                .with_key_size(521),
        )
        .expect("ECDSA P-521 should succeed");
    assert!(cert.has_private_key());
}

// ===========================================================================
// factory.rs — CA with pathlen constraint and unlimited
// ===========================================================================

#[test]
fn ca_with_unlimited_path_length() {
    let factory = make_factory();
    let cert = factory
        .create_certificate(
            CertificateOptions::new()
                .with_subject_name("CN=Unlimited CA")
                .with_key_algorithm(KeyAlgorithm::Ecdsa)
                .as_ca(u32::MAX), // unlimited path length
        )
        .expect("CA with unlimited path length should succeed");

    let (_, parsed) = parse_cert(&cert.cert_der);
    assert!(parsed.is_ca());
}

// ===========================================================================
// factory.rs — EKU variants
// ===========================================================================

#[test]
fn cert_with_server_auth_eku() {
    let factory = make_factory();
    let cert = factory
        .create_certificate(
            CertificateOptions::new()
                .with_subject_name("CN=Server Auth")
                .with_key_algorithm(KeyAlgorithm::Ecdsa)
                .with_enhanced_key_usages(vec!["1.3.6.1.5.5.7.3.1".to_string()]),
        )
        .expect("Server auth EKU cert should succeed");
    assert!(cert.has_private_key());
}

#[test]
fn cert_with_client_auth_eku() {
    let factory = make_factory();
    let cert = factory
        .create_certificate(
            CertificateOptions::new()
                .with_subject_name("CN=Client Auth")
                .with_key_algorithm(KeyAlgorithm::Ecdsa)
                .with_enhanced_key_usages(vec!["1.3.6.1.5.5.7.3.2".to_string()]),
        )
        .expect("Client auth EKU cert should succeed");
    assert!(cert.has_private_key());
}

#[test]
fn cert_with_email_protection_eku() {
    let factory = make_factory();
    let cert = factory
        .create_certificate(
            CertificateOptions::new()
                .with_subject_name("CN=Email Protection")
                .with_key_algorithm(KeyAlgorithm::Ecdsa)
                .with_enhanced_key_usages(vec!["1.3.6.1.5.5.7.3.4".to_string()]),
        )
        .expect("Email protection EKU cert should succeed");
    assert!(cert.has_private_key());
}

#[test]
fn cert_with_time_stamping_eku() {
    let factory = make_factory();
    let cert = factory
        .create_certificate(
            CertificateOptions::new()
                .with_subject_name("CN=Time Stamping")
                .with_key_algorithm(KeyAlgorithm::Ecdsa)
                .with_enhanced_key_usages(vec!["1.3.6.1.5.5.7.3.8".to_string()]),
        )
        .expect("Time stamping EKU cert should succeed");
    assert!(cert.has_private_key());
}

#[test]
fn cert_with_custom_eku_oid() {
    let factory = make_factory();
    let cert = factory
        .create_certificate(
            CertificateOptions::new()
                .with_subject_name("CN=Custom EKU")
                .with_key_algorithm(KeyAlgorithm::Ecdsa)
                .with_enhanced_key_usages(vec!["1.2.3.4.5.99".to_string()]),
        )
        .expect("Custom EKU OID cert should succeed");
    assert!(cert.has_private_key());
}

#[test]
fn cert_with_multiple_ekus() {
    let factory = make_factory();
    let cert = factory
        .create_certificate(
            CertificateOptions::new()
                .with_subject_name("CN=Multi EKU")
                .with_key_algorithm(KeyAlgorithm::Ecdsa)
                .with_enhanced_key_usages(vec![
                    "1.3.6.1.5.5.7.3.1".to_string(), // server auth
                    "1.3.6.1.5.5.7.3.2".to_string(), // client auth
                    "1.3.6.1.5.5.7.3.3".to_string(), // code signing
                ]),
        )
        .expect("Multiple EKU cert should succeed");
    assert!(cert.has_private_key());
}

#[test]
fn cert_with_empty_ekus() {
    let factory = make_factory();
    let cert = factory
        .create_certificate(
            CertificateOptions::new()
                .with_subject_name("CN=No EKU")
                .with_key_algorithm(KeyAlgorithm::Ecdsa)
                .with_enhanced_key_usages(vec![]),
        )
        .expect("Empty EKU cert should succeed");
    assert!(cert.has_private_key());
}

// ===========================================================================
// factory.rs — SAN variants
// ===========================================================================

#[test]
fn cert_with_dns_san() {
    let factory = make_factory();
    let cert = factory
        .create_certificate(
            CertificateOptions::new()
                .with_subject_name("CN=DNS SAN Test")
                .with_key_algorithm(KeyAlgorithm::Ecdsa)
                .add_subject_alternative_name("example.com"),
        )
        .expect("DNS SAN cert should succeed");
    assert!(cert.has_private_key());
}

#[test]
fn cert_with_email_san() {
    let factory = make_factory();
    let cert = factory
        .create_certificate(
            CertificateOptions::new()
                .with_subject_name("CN=Email SAN Test")
                .with_key_algorithm(KeyAlgorithm::Ecdsa)
                .add_subject_alternative_name("email:test@example.com"),
        )
        .expect("Email SAN cert should succeed");
    assert!(cert.has_private_key());
}

#[test]
fn cert_with_uri_san() {
    let factory = make_factory();
    let cert = factory
        .create_certificate(
            CertificateOptions::new()
                .with_subject_name("CN=URI SAN Test")
                .with_key_algorithm(KeyAlgorithm::Ecdsa)
                .add_subject_alternative_name("URI:https://example.com"),
        )
        .expect("URI SAN cert should succeed");
    assert!(cert.has_private_key());
}

#[test]
fn cert_with_ip_san() {
    let factory = make_factory();
    let cert = factory
        .create_certificate(
            CertificateOptions::new()
                .with_subject_name("CN=IP SAN Test")
                .with_key_algorithm(KeyAlgorithm::Ecdsa)
                .add_subject_alternative_name("IP:192.168.1.1"),
        )
        .expect("IP SAN cert should succeed");
    assert!(cert.has_private_key());
}

// ===========================================================================
// factory.rs — Issuer-signed with various algorithm combos
// ===========================================================================

#[test]
fn rsa_leaf_signed_by_ecdsa_ca() {
    let factory = make_factory();
    let ca = factory
        .create_certificate(
            CertificateOptions::new()
                .with_subject_name("CN=ECDSA CA for RSA")
                .with_key_algorithm(KeyAlgorithm::Ecdsa)
                .as_ca(0),
        )
        .expect("ECDSA CA should succeed");

    let leaf = factory
        .create_certificate(
            CertificateOptions::new()
                .with_subject_name("CN=RSA Leaf from ECDSA")
                .with_key_algorithm(KeyAlgorithm::Rsa)
                .with_key_size(2048)
                .signed_by(ca),
        )
        .expect("RSA leaf signed by ECDSA CA should succeed");

    let (_, parsed) = parse_cert(&leaf.cert_der);
    assert!(has_extension(&parsed, OID_AKI));
}

#[test]
fn ecdsa_leaf_signed_by_ecdsa_ca_sha384() {
    let factory = make_factory();
    let ca = factory
        .create_certificate(
            CertificateOptions::new()
                .with_subject_name("CN=ECDSA CA SHA384")
                .with_key_algorithm(KeyAlgorithm::Ecdsa)
                .with_key_size(384)
                .with_hash_algorithm(HashAlgorithm::Sha384)
                .as_ca(0),
        )
        .expect("ECDSA P384 CA should succeed");

    let leaf = factory
        .create_certificate(
            CertificateOptions::new()
                .with_subject_name("CN=ECDSA Leaf SHA384")
                .with_key_algorithm(KeyAlgorithm::Ecdsa)
                .with_key_size(384)
                .with_hash_algorithm(HashAlgorithm::Sha384)
                .signed_by(ca),
        )
        .expect("ECDSA leaf with SHA384 should succeed");

    let (_, parsed) = parse_cert(&leaf.cert_der);
    assert!(has_extension(&parsed, OID_AKI));
}

// ===========================================================================
// factory.rs — EdDSA issuer-signed by EdDSA (EdDSA CA → EdDSA leaf)
// ===========================================================================

#[test]
fn eddsa_leaf_signed_by_eddsa_ca() {
    let factory = make_factory();
    let ca = factory
        .create_certificate(
            CertificateOptions::new()
                .with_subject_name("CN=EdDSA CA for EdDSA")
                .with_key_algorithm(KeyAlgorithm::EdDsa)
                .as_ca(0),
        )
        .expect("EdDSA CA should succeed");

    let leaf = factory
        .create_certificate(
            CertificateOptions::new()
                .with_subject_name("CN=EdDSA Leaf from EdDSA")
                .with_key_algorithm(KeyAlgorithm::EdDsa)
                .signed_by(ca),
        )
        .expect("EdDSA leaf signed by EdDSA CA should succeed");

    let (_, parsed) = parse_cert(&leaf.cert_der);
    assert!(has_extension(&parsed, OID_AKI));
    assert!(has_extension(&parsed, OID_SKI));
}

// ===========================================================================
// chain_factory.rs — Hybrid chain (ECDSA root + EdDSA leaf)
// ===========================================================================

#[test]
fn hybrid_chain_ecdsa_root_eddsa_leaf() {
    let chain_factory = make_chain_factory();
    let options = CertificateChainOptions::new()
        .with_root_key_algorithm(KeyAlgorithm::Ecdsa)
        .with_leaf_key_algorithm(KeyAlgorithm::EdDsa);

    let chain = chain_factory
        .create_chain_with_options(options)
        .expect("Hybrid ECDSA root + EdDSA leaf chain should succeed");

    assert!(chain.len() >= 2, "Chain should have at least root + leaf");
}

#[test]
fn hybrid_chain_ecdsa_root_eddsa_leaf_with_intermediate() {
    let chain_factory = make_chain_factory();
    let options = CertificateChainOptions::new()
        .with_root_key_algorithm(KeyAlgorithm::Ecdsa)
        .with_intermediate_key_algorithm(KeyAlgorithm::Ecdsa)
        .with_leaf_key_algorithm(KeyAlgorithm::EdDsa);

    let chain = chain_factory
        .create_chain_with_options(options)
        .expect("3-tier hybrid chain should succeed");

    assert_eq!(chain.len(), 3, "Chain should have root + intermediate + leaf");
}

// ===========================================================================
// chain_factory.rs — Per-tier key sizes
// ===========================================================================

#[test]
fn chain_with_per_tier_key_sizes() {
    let chain_factory = make_chain_factory();
    let options = CertificateChainOptions::new()
        .with_key_algorithm(KeyAlgorithm::Ecdsa)
        .with_root_key_size(384)
        .with_intermediate_key_size(384)
        .with_leaf_key_size(256);

    let chain = chain_factory
        .create_chain_with_options(options)
        .expect("Chain with per-tier key sizes should succeed");

    assert_eq!(chain.len(), 3);
}

#[test]
fn chain_with_root_and_leaf_key_sizes_no_intermediate() {
    let chain_factory = make_chain_factory();
    let options = CertificateChainOptions::new()
        .with_intermediate_name(None::<String>)
        .with_key_algorithm(KeyAlgorithm::Ecdsa)
        .with_root_key_size(384)
        .with_leaf_key_size(256);

    let chain = chain_factory
        .create_chain_with_options(options)
        .expect("2-tier chain with per-tier sizes should succeed");

    assert_eq!(chain.len(), 2);
}

// ===========================================================================
// chain_factory.rs — resolve_algorithm and resolve_key_size helpers
// ===========================================================================

#[test]
fn chain_default_algorithm_used_when_no_override() {
    let chain_factory = make_chain_factory();
    let options = CertificateChainOptions::new()
        .with_key_algorithm(KeyAlgorithm::Ecdsa);
    // No per-tier overrides → all use Ecdsa

    let chain = chain_factory
        .create_chain_with_options(options)
        .expect("Default algorithm chain should succeed");

    assert_eq!(chain.len(), 3);
}

#[test]
fn chain_global_key_size_applied_when_no_tier_override() {
    let chain_factory = make_chain_factory();
    let options = CertificateChainOptions::new()
        .with_key_algorithm(KeyAlgorithm::Ecdsa)
        .with_key_size(384); // global size, no per-tier overrides

    let chain = chain_factory
        .create_chain_with_options(options)
        .expect("Chain with global key size should succeed");

    assert_eq!(chain.len(), 3);
}

// ===========================================================================
// chain_factory.rs — leaf_first ordering
// ===========================================================================

#[test]
fn chain_leaf_first_ordering() {
    let chain_factory = make_chain_factory();
    let options = CertificateChainOptions::new()
        .with_root_name("CN=Root for Order Test")
        .with_leaf_name("CN=Leaf for Order Test")
        .with_leaf_first(true);

    let chain = chain_factory
        .create_chain_with_options(options)
        .expect("Leaf-first chain should succeed");

    // First cert should be the leaf
    let (_, first) = parse_cert(&chain[0].cert_der);
    assert!(
        first.subject().to_string().contains("Leaf for Order Test"),
        "First cert in leaf-first order should be the leaf"
    );
}

#[test]
fn chain_root_first_ordering() {
    let chain_factory = make_chain_factory();
    let options = CertificateChainOptions::new()
        .with_root_name("CN=Root for Root-First Test")
        .with_leaf_name("CN=Leaf for Root-First Test")
        .with_leaf_first(false);

    let chain = chain_factory
        .create_chain_with_options(options)
        .expect("Root-first chain should succeed");

    let (_, first) = parse_cert(&chain[0].cert_der);
    assert!(
        first.subject().to_string().contains("Root for Root-First Test"),
        "First cert in root-first order should be the root"
    );
}

// ===========================================================================
// chain_factory.rs — leaf_only_private_key
// ===========================================================================

#[test]
fn chain_leaf_only_private_key() {
    let chain_factory = make_chain_factory();
    let options = CertificateChainOptions::new()
        .with_leaf_only_private_key(true);

    let chain = chain_factory
        .create_chain_with_options(options)
        .expect("Leaf-only private key chain should succeed");

    // root-first order: root, intermediate, leaf
    assert!(!chain[0].has_private_key(), "Root should not have private key");
    assert!(!chain[1].has_private_key(), "Intermediate should not have private key");
    assert!(chain[2].has_private_key(), "Leaf should have private key");
}

// ===========================================================================
// chain_factory.rs — leaf_enhanced_key_usages
// ===========================================================================

#[test]
fn chain_with_custom_leaf_ekus() {
    let chain_factory = make_chain_factory();
    let options = CertificateChainOptions::new()
        .with_leaf_enhanced_key_usages(vec![
            "1.3.6.1.5.5.7.3.1".to_string(), // server auth
        ]);

    let chain = chain_factory
        .create_chain_with_options(options)
        .expect("Chain with custom leaf EKUs should succeed");

    assert_eq!(chain.len(), 3);
}

// ===========================================================================
// chain_factory.rs — 2-tier chain (no intermediate)
// ===========================================================================

#[test]
fn two_tier_chain() {
    let chain_factory = make_chain_factory();
    let options = CertificateChainOptions::new()
        .with_intermediate_name(None::<String>);

    let chain = chain_factory
        .create_chain_with_options(options)
        .expect("2-tier chain should succeed");

    assert_eq!(chain.len(), 2, "Should have root + leaf only");
}

// ===========================================================================
// chain_factory.rs — create_chain (default)
// ===========================================================================

#[test]
fn default_chain_creation() {
    let chain_factory = make_chain_factory();
    let chain = chain_factory
        .create_chain()
        .expect("Default chain should succeed");

    assert_eq!(chain.len(), 3, "Default chain should have root + intermediate + leaf");
}

// ===========================================================================
// chain_factory.rs — custom validity durations
// ===========================================================================

#[test]
fn chain_with_custom_validities() {
    let chain_factory = make_chain_factory();
    let options = CertificateChainOptions::new()
        .with_root_validity(std::time::Duration::from_secs(365 * 24 * 3600))
        .with_intermediate_validity(std::time::Duration::from_secs(180 * 24 * 3600))
        .with_leaf_validity(std::time::Duration::from_secs(30 * 24 * 3600));

    let chain = chain_factory
        .create_chain_with_options(options)
        .expect("Chain with custom validities should succeed");

    assert_eq!(chain.len(), 3);
}

// ===========================================================================
// chain_factory.rs — leaf_first + leaf_only_private_key combined
// ===========================================================================

#[test]
fn chain_leaf_first_with_leaf_only_key() {
    let chain_factory = make_chain_factory();
    let options = CertificateChainOptions::new()
        .with_leaf_first(true)
        .with_leaf_only_private_key(true);

    let chain = chain_factory
        .create_chain_with_options(options)
        .expect("Leaf-first + leaf-only-key chain should succeed");

    // leaf-first: [leaf, intermediate, root]
    assert!(chain[0].has_private_key(), "First (leaf) should have private key");
    assert!(!chain[1].has_private_key(), "Second (intermediate) should not have private key");
    assert!(!chain[2].has_private_key(), "Third (root) should not have private key");
}

// ===========================================================================
// chain_factory.rs — 2-tier leaf-first + leaf-only
// ===========================================================================

#[test]
fn two_tier_leaf_first_leaf_only_key() {
    let chain_factory = make_chain_factory();
    let options = CertificateChainOptions::new()
        .with_intermediate_name(None::<String>)
        .with_leaf_first(true)
        .with_leaf_only_private_key(true);

    let chain = chain_factory
        .create_chain_with_options(options)
        .expect("2-tier leaf-first leaf-only chain should succeed");

    assert_eq!(chain.len(), 2);
    assert!(chain[0].has_private_key(), "First (leaf) should have key");
    assert!(!chain[1].has_private_key(), "Second (root) should not have key");
}

// ===========================================================================
// factory.rs — RSA-PSS issuer signs ECDSA leaf
// ===========================================================================

#[test]
fn rsa_pss_ca_signs_ecdsa_leaf() {
    let factory = make_factory();
    let ca = factory
        .create_certificate(
            CertificateOptions::new()
                .with_subject_name("CN=RSA-PSS CA for ECDSA Leaf")
                .with_key_algorithm(KeyAlgorithm::Rsa)
                .with_key_size(2048)
                .with_signing_padding(SigningPadding::Pss)
                .as_ca(0),
        )
        .expect("RSA-PSS CA should succeed");

    let leaf = factory
        .create_certificate(
            CertificateOptions::new()
                .with_subject_name("CN=ECDSA Leaf from RSA-PSS")
                .with_key_algorithm(KeyAlgorithm::Ecdsa)
                .signed_by(ca),
        )
        .expect("ECDSA leaf signed by RSA-PSS CA should succeed");

    let (_, parsed) = parse_cert(&leaf.cert_der);
    assert!(has_extension(&parsed, OID_AKI));
}

// ===========================================================================
// factory.rs — create_certificate_default (trait method)
// ===========================================================================

#[test]
fn create_certificate_default_trait_method() {
    let factory = make_factory();
    let cert = factory
        .create_certificate_default()
        .expect("Default certificate creation should succeed");
    assert!(cert.has_private_key());
}

// ===========================================================================
// factory.rs — Subject name without CN= prefix
// ===========================================================================

#[test]
fn subject_name_without_cn_prefix() {
    let factory = make_factory();
    let cert = factory
        .create_certificate(
            CertificateOptions::new()
                .with_subject_name("Test No Prefix")
                .with_key_algorithm(KeyAlgorithm::Ecdsa),
        )
        .expect("Subject name without CN= prefix should succeed");

    let (_, parsed) = parse_cert(&cert.cert_der);
    assert!(parsed.subject().to_string().contains("Test No Prefix"));
}

// ===========================================================================
// software_key.rs — RSA default key size via generate_key
// ===========================================================================

#[test]
fn software_key_rsa_default_size() {
    let provider = SoftwareKeyProvider::new();
    let key = provider
        .generate_key(KeyAlgorithm::Rsa, None)
        .expect("RSA with default size should succeed");
    assert_eq!(key.key_size, 2048);
}

#[test]
fn software_key_ecdsa_default_size() {
    let provider = SoftwareKeyProvider::new();
    let key = provider
        .generate_key(KeyAlgorithm::Ecdsa, None)
        .expect("ECDSA with default size should succeed");
    assert_eq!(key.key_size, 256);
}

// ===========================================================================
// software_key.rs — ECDSA P-384 and P-521
// ===========================================================================

#[test]
fn software_key_ecdsa_p384() {
    let provider = SoftwareKeyProvider::new();
    let key = provider
        .generate_key(KeyAlgorithm::Ecdsa, Some(384))
        .expect("ECDSA P-384 should succeed");
    assert_eq!(key.key_size, 384);
}

#[test]
fn software_key_ecdsa_p521() {
    let provider = SoftwareKeyProvider::new();
    let key = provider
        .generate_key(KeyAlgorithm::Ecdsa, Some(521))
        .expect("ECDSA P-521 should succeed");
    assert_eq!(key.key_size, 521);
}

// ===========================================================================
// factory.rs — key_provider accessor
// ===========================================================================

#[test]
fn factory_key_provider_returns_software_provider() {
    let factory = make_factory();
    let provider = factory.key_provider();
    assert_eq!(provider.name(), "SoftwareKeyProvider");
}

// ===========================================================================
// factory.rs — not_before_offset
// ===========================================================================

#[test]
fn cert_with_custom_not_before_offset() {
    let factory = make_factory();
    let cert = factory
        .create_certificate(
            CertificateOptions::new()
                .with_subject_name("CN=Not Before Offset")
                .with_key_algorithm(KeyAlgorithm::Ecdsa)
                .with_not_before_offset(std::time::Duration::from_secs(60)),
        )
        .expect("Cert with custom not_before_offset should succeed");
    assert!(cert.has_private_key());
}

// ===========================================================================
// chain_factory.rs — Hybrid chain with EdDSA root + ECDSA leaf
// ===========================================================================

// NOTE: EdDSA root → ECDSA leaf is not supported because the builder signs
// with the *leaf's* algorithm+digest, but the issuer's EdDSA key cannot use
// an explicit digest. Only ECDSA/RSA roots can sign EdDSA leaves (not vice versa).

#[test]
fn hybrid_chain_rsa_root_eddsa_leaf() {
    let chain_factory = make_chain_factory();
    let options = CertificateChainOptions::new()
        .with_root_key_algorithm(KeyAlgorithm::Rsa)
        .with_intermediate_key_algorithm(KeyAlgorithm::Rsa)
        .with_leaf_key_algorithm(KeyAlgorithm::EdDsa)
        .with_intermediate_name(None::<String>); // 2-tier to simplify

    let chain = chain_factory
        .create_chain_with_options(options)
        .expect("RSA root + EdDSA leaf hybrid chain should succeed");

    assert_eq!(chain.len(), 2);
}

// ===========================================================================
// chain_factory.rs — EdDSA-only chain
// ===========================================================================

#[test]
fn eddsa_only_chain() {
    let chain_factory = make_chain_factory();
    let options = CertificateChainOptions::new()
        .with_key_algorithm(KeyAlgorithm::EdDsa)
        .with_intermediate_name(None::<String>);

    let chain = chain_factory
        .create_chain_with_options(options)
        .expect("EdDSA-only chain should succeed");

    assert_eq!(chain.len(), 2);
}

// ===========================================================================
// chain_factory.rs — RSA-PSS chain
// ===========================================================================

#[test]
fn chain_with_rsa_algorithm() {
    let chain_factory = make_chain_factory();
    let options = CertificateChainOptions::new()
        .with_key_algorithm(KeyAlgorithm::Rsa)
        .with_key_size(2048)
        .with_intermediate_name(None::<String>);

    let chain = chain_factory
        .create_chain_with_options(options)
        .expect("RSA chain should succeed");

    assert_eq!(chain.len(), 2);
}

// ===========================================================================
// chain_factory.rs — Custom names
// ===========================================================================

#[test]
fn chain_with_custom_names() {
    let chain_factory = make_chain_factory();
    let options = CertificateChainOptions::new()
        .with_root_name("CN=My Custom Root")
        .with_intermediate_name(Some("CN=My Custom Intermediate"))
        .with_leaf_name("CN=My Custom Leaf");

    let chain = chain_factory
        .create_chain_with_options(options)
        .expect("Chain with custom names should succeed");

    assert_eq!(chain.len(), 3);
    let (_, root) = parse_cert(&chain[0].cert_der);
    assert!(root.subject().to_string().contains("My Custom Root"));
}

// ===========================================================================
// software_key.rs — SoftwareKeyProvider::default()
// ===========================================================================

#[test]
fn software_key_provider_default_impl() {
    let provider = SoftwareKeyProvider::default();
    assert_eq!(provider.name(), "SoftwareKeyProvider");
}
