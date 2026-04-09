// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Tests for EphemeralCertificateFactory.

use cose_sign1_certificates_local::*;
use std::time::Duration;

#[test]
fn test_create_default_certificate() {
    let provider = Box::new(SoftwareKeyProvider::new());
    let factory = EphemeralCertificateFactory::new(provider);

    let cert = factory.create_certificate_default().unwrap();

    assert!(cert.has_private_key());
    assert!(!cert.cert_der.is_empty());
}

#[test]
fn test_create_self_signed_certificate() {
    let provider = Box::new(SoftwareKeyProvider::new());
    let factory = EphemeralCertificateFactory::new(provider);

    let options = CertificateOptions::new()
        .with_subject_name("CN=Test Self-Signed")
        .with_key_algorithm(KeyAlgorithm::Ecdsa)
        .with_key_size(256);

    let cert = factory.create_certificate(options).unwrap();

    assert!(cert.has_private_key());
    assert!(!cert.cert_der.is_empty());

    // Verify DER can be parsed
    use x509_parser::prelude::*;
    let parsed = X509Certificate::from_der(&cert.cert_der).unwrap().1;
    assert!(parsed.subject().to_string().contains("Test Self-Signed"));
}

#[test]
fn test_create_certificate_custom_subject() {
    let provider = Box::new(SoftwareKeyProvider::new());
    let factory = EphemeralCertificateFactory::new(provider);

    let options = CertificateOptions::new()
        .with_subject_name("CN=Custom Subject Certificate")
        .with_validity(Duration::from_secs(7200));

    let cert = factory.create_certificate(options).unwrap();

    // Verify subject
    use x509_parser::prelude::*;
    let parsed = X509Certificate::from_der(&cert.cert_der).unwrap().1;
    assert!(parsed
        .subject()
        .to_string()
        .contains("Custom Subject Certificate"));
}

#[test]
fn test_create_certificate_ecdsa_p256() {
    let provider = Box::new(SoftwareKeyProvider::new());
    let factory = EphemeralCertificateFactory::new(provider);

    let options = CertificateOptions::new()
        .with_subject_name("CN=ECDSA Certificate")
        .with_key_algorithm(KeyAlgorithm::Ecdsa)
        .with_key_size(256);

    let cert = factory.create_certificate(options).unwrap();

    assert!(cert.has_private_key());
    assert!(!cert.cert_der.is_empty());

    // Verify it's an ECDSA certificate
    use x509_parser::prelude::*;
    let parsed = X509Certificate::from_der(&cert.cert_der).unwrap().1;
    let spki = &parsed.public_key();
    assert!(spki
        .algorithm
        .algorithm
        .to_string()
        .contains("1.2.840.10045"));
}

#[test]
fn test_create_certificate_rsa_4096() {
    let provider = Box::new(SoftwareKeyProvider::new());
    let factory = EphemeralCertificateFactory::new(provider);

    let options = CertificateOptions::new()
        .with_subject_name("CN=RSA 4096 Certificate")
        .with_key_algorithm(KeyAlgorithm::Rsa)
        .with_key_size(4096);

    let cert = factory.create_certificate(options).unwrap();
    assert!(!cert.cert_der.is_empty());
    assert!(cert.has_private_key());
    let subject = cert.subject().unwrap();
    assert!(subject.contains("RSA 4096 Certificate"), "subject: {subject}");
}

#[test]
fn test_certificate_validity_period() {
    let provider = Box::new(SoftwareKeyProvider::new());
    let factory = EphemeralCertificateFactory::new(provider);

    let validity_duration = Duration::from_secs(86400); // 1 day
    let options = CertificateOptions::new()
        .with_subject_name("CN=Validity Test")
        .with_validity(validity_duration);

    let cert = factory.create_certificate(options).unwrap();

    // Verify validity period
    use x509_parser::prelude::*;
    let parsed = X509Certificate::from_der(&cert.cert_der).unwrap().1;
    let validity = parsed.validity();

    let not_before = validity.not_before.timestamp();
    let not_after = validity.not_after.timestamp();

    // Verify roughly 1 day validity (allowing for clock skew)
    let diff = not_after - not_before;
    assert!(diff >= 86400 - 600 && diff <= 86400 + 600);
}

#[test]
fn test_certificate_has_private_key() {
    let provider = Box::new(SoftwareKeyProvider::new());
    let factory = EphemeralCertificateFactory::new(provider);

    let cert = factory.create_certificate_default().unwrap();

    assert!(cert.has_private_key());
    assert!(cert.private_key_der.is_some());
    assert!(!cert.private_key_der.unwrap().is_empty());
}

#[test]
fn test_certificate_ca_constraints() {
    let provider = Box::new(SoftwareKeyProvider::new());
    let factory = EphemeralCertificateFactory::new(provider);

    let options = CertificateOptions::new()
        .with_subject_name("CN=Test CA")
        .as_ca(2);

    let cert = factory.create_certificate(options).unwrap();

    // Verify basic constraints
    use x509_parser::prelude::*;
    let parsed = X509Certificate::from_der(&cert.cert_der).unwrap().1;

    let basic_constraints = parsed.basic_constraints().unwrap().unwrap().value;

    assert!(basic_constraints.ca);
}

#[test]
fn test_get_generated_key() {
    let provider = Box::new(SoftwareKeyProvider::new());
    let factory = EphemeralCertificateFactory::new(provider);

    let cert = factory.create_certificate_default().unwrap();

    // Get serial number
    use x509_parser::prelude::*;
    let parsed = X509Certificate::from_der(&cert.cert_der).unwrap().1;
    let serial_hex = parsed
        .serial
        .to_bytes_be()
        .iter()
        .map(|b| format!("{:02X}", b))
        .collect::<String>();

    // Retrieve generated key
    let key = factory.get_generated_key(&serial_hex);
    assert!(key.is_some());
}

#[test]
fn test_release_key() {
    let provider = Box::new(SoftwareKeyProvider::new());
    let factory = EphemeralCertificateFactory::new(provider);

    let cert = factory.create_certificate_default().unwrap();

    // Get serial number
    use x509_parser::prelude::*;
    let parsed = X509Certificate::from_der(&cert.cert_der).unwrap().1;
    let serial_hex = parsed
        .serial
        .to_bytes_be()
        .iter()
        .map(|b| format!("{:02X}", b))
        .collect::<String>();

    // Release key
    assert!(factory.release_key(&serial_hex));

    // Verify key is gone
    assert!(factory.get_generated_key(&serial_hex).is_none());
}

#[test]
fn test_unsupported_algorithm() {
    let provider = Box::new(SoftwareKeyProvider::new());
    let factory = EphemeralCertificateFactory::new(provider);

    #[cfg(feature = "pqc")]
    {
        let options = CertificateOptions::new()
            .with_subject_name("CN=ML-DSA Test")
            .with_key_algorithm(KeyAlgorithm::MlDsa);

        let result = factory.create_certificate(options);
        assert!(result.is_err());
    }
}
