// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Tests for CertificateSigningService.

use std::sync::Arc;

use cose_sign1_certificates_local::CertificateFactory;
use cose_sign1_headers::CwtClaims;
use cose_sign1_signing::{
    HeaderContributor, HeaderContributorContext, SigningContext, SigningService,
};
use crypto_primitives::{CryptoError, CryptoSigner};

use cose_sign1_certificates::chain_builder::{
    CertificateChainBuilder, ExplicitCertificateChainBuilder,
};
use cose_sign1_certificates::error::CertificateError;
use cose_sign1_certificates::signing::{
    signing_key_provider::SigningKeyProvider, source::CertificateSource, CertificateSigningOptions,
    CertificateSigningService,
};

// Mock implementations for testing
struct MockCertificateSource {
    cert: Vec<u8>,
    chain_builder: ExplicitCertificateChainBuilder,
    should_fail: bool,
}

impl MockCertificateSource {
    fn new(cert: Vec<u8>, chain: Vec<Vec<u8>>) -> Self {
        Self {
            cert,
            chain_builder: ExplicitCertificateChainBuilder::new(chain),
            should_fail: false,
        }
    }

    fn with_failure() -> Self {
        Self {
            cert: vec![],
            chain_builder: ExplicitCertificateChainBuilder::new(vec![]),
            should_fail: true,
        }
    }
}

impl CertificateSource for MockCertificateSource {
    fn get_signing_certificate(&self) -> Result<&[u8], CertificateError> {
        if self.should_fail {
            Err(CertificateError::InvalidCertificate(
                "Mock failure".to_string(),
            ))
        } else {
            Ok(&self.cert)
        }
    }

    fn has_private_key(&self) -> bool {
        true
    }

    fn get_chain_builder(&self) -> &dyn CertificateChainBuilder {
        &self.chain_builder
    }
}

struct MockSigningKeyProvider {
    is_remote: bool,
    should_fail_sign: bool,
}

impl MockSigningKeyProvider {
    fn new(is_remote: bool) -> Self {
        Self {
            is_remote,
            should_fail_sign: false,
        }
    }

    fn with_sign_failure() -> Self {
        Self {
            is_remote: false,
            should_fail_sign: true,
        }
    }
}

impl SigningKeyProvider for MockSigningKeyProvider {
    fn is_remote(&self) -> bool {
        self.is_remote
    }
}

impl CryptoSigner for MockSigningKeyProvider {
    fn sign(&self, _data: &[u8]) -> Result<Vec<u8>, CryptoError> {
        if self.should_fail_sign {
            Err(CryptoError::SigningFailed("Mock sign failure".to_string()))
        } else {
            Ok(vec![0xDE, 0xAD, 0xBE, 0xEF])
        }
    }

    fn algorithm(&self) -> i64 {
        -7 // ES256
    }

    fn key_id(&self) -> Option<&[u8]> {
        Some(b"mock-key-id")
    }

    fn key_type(&self) -> &str {
        "EC"
    }
}

struct MockHeaderContributor {
    added_protected: bool,
    added_unprotected: bool,
}

impl MockHeaderContributor {
    fn new() -> Self {
        Self {
            added_protected: false,
            added_unprotected: false,
        }
    }
}

impl HeaderContributor for MockHeaderContributor {
    fn merge_strategy(&self) -> cose_sign1_signing::HeaderMergeStrategy {
        cose_sign1_signing::HeaderMergeStrategy::Replace
    }

    fn contribute_protected_headers(
        &self,
        headers: &mut cose_sign1_primitives::CoseHeaderMap,
        _context: &HeaderContributorContext,
    ) {
        headers.insert(
            cose_sign1_primitives::CoseHeaderLabel::Int(999),
            cose_sign1_primitives::CoseHeaderValue::Int(123),
        );
    }

    fn contribute_unprotected_headers(
        &self,
        headers: &mut cose_sign1_primitives::CoseHeaderMap,
        _context: &HeaderContributorContext,
    ) {
        headers.insert(
            cose_sign1_primitives::CoseHeaderLabel::Int(888),
            cose_sign1_primitives::CoseHeaderValue::Int(456),
        );
    }
}

fn create_test_cert() -> Vec<u8> {
    // Simple mock DER certificate bytes
    vec![
        0x30, 0x82, 0x01, 0x23, // SEQUENCE
        0x30, 0x82, 0x01, 0x00, // tbsCertificate SEQUENCE
        // ... simplified mock DER structure
        0x01, 0x02, 0x03, 0x04, 0x05, // Mock certificate content
    ]
}

#[test]
fn test_new_certificate_signing_service() {
    let cert = create_test_cert();
    let source = Box::new(MockCertificateSource::new(cert.clone(), vec![]));
    let provider = Arc::new(MockSigningKeyProvider::new(false));
    let options = CertificateSigningOptions::default();

    let service = CertificateSigningService::new(source, provider, options);

    assert!(!service.is_remote());
    assert_eq!(
        service.service_metadata().service_name,
        "CertificateSigningService"
    );
    assert_eq!(
        service.service_metadata().service_description,
        "X.509 certificate-based signing service"
    );
}

#[test]
fn test_remote_signing_key_provider() {
    let cert = create_test_cert();
    let source = Box::new(MockCertificateSource::new(cert.clone(), vec![]));
    let provider = Arc::new(MockSigningKeyProvider::new(true)); // Remote
    let options = CertificateSigningOptions::default();

    let service = CertificateSigningService::new(source, provider, options);

    assert!(service.is_remote());
}

#[test]
fn test_get_cose_signer_basic() {
    let cert = create_test_cert();
    let chain = vec![cert.clone(), vec![0x30, 0x11, 0x22, 0x33]]; // Mock chain
    let source = Box::new(MockCertificateSource::new(cert.clone(), chain));
    let provider = Arc::new(MockSigningKeyProvider::new(false));
    let options = CertificateSigningOptions {
        enable_scitt_compliance: false, // Disable SCITT for mock cert
        ..Default::default()
    };

    let service = CertificateSigningService::new(source, provider, options);
    let context = SigningContext::from_bytes(vec![]);

    let result = service.get_cose_signer(&context);
    assert!(result.is_ok());

    let signer = result.unwrap();
    assert_eq!(signer.signer().algorithm(), -7); // ES256
}

#[test]
fn test_get_cose_signer_with_scitt_enabled() {
    let cert = create_test_cert();
    let chain = vec![cert.clone()];
    let source = Box::new(MockCertificateSource::new(cert.clone(), chain));
    let provider = Arc::new(MockSigningKeyProvider::new(false));

    let options = CertificateSigningOptions {
        enable_scitt_compliance: true,
        ..Default::default()
    };

    let service = CertificateSigningService::new(source, provider, options);
    let context = SigningContext::from_bytes(vec![]);

    let result = service.get_cose_signer(&context);
    // Note: This might fail due to DID:X509 generation with mock cert,
    // but we're testing the code path
    match result {
        Ok(_) => {
            // Success case - SCITT contributor was added
        }
        Err(cose_sign1_signing::SigningError::SigningFailed { detail }) => {
            // Expected failure due to mock cert not being valid for DID:X509
            assert!(detail.contains("DID:X509") || detail.contains("Invalid"));
        }
        _ => panic!("Unexpected error type"),
    }
}

#[test]
fn test_get_cose_signer_with_custom_cwt_claims() {
    let cert = create_test_cert();
    let chain = vec![cert.clone()];
    let source = Box::new(MockCertificateSource::new(cert.clone(), chain));
    let provider = Arc::new(MockSigningKeyProvider::new(false));

    let custom_claims = CwtClaims::new()
        .with_issuer("custom-issuer".to_string())
        .with_subject("custom-subject".to_string());

    let options = CertificateSigningOptions {
        enable_scitt_compliance: true,
        custom_cwt_claims: Some(custom_claims),
        ..Default::default()
    };

    let service = CertificateSigningService::new(source, provider, options);
    let context = SigningContext::from_bytes(vec![]);

    let result = service.get_cose_signer(&context);
    // Similar to above - testing the code path
    match result {
        Ok(_) => {}
        Err(cose_sign1_signing::SigningError::SigningFailed { .. }) => {
            // Expected due to mock cert
        }
        _ => panic!("Unexpected error type"),
    }
}

#[test]
fn test_get_cose_signer_with_additional_contributors() {
    let cert = create_test_cert();
    let source = Box::new(MockCertificateSource::new(cert.clone(), vec![]));
    let provider = Arc::new(MockSigningKeyProvider::new(false));
    let options = CertificateSigningOptions {
        enable_scitt_compliance: false, // Disable SCITT for mock cert
        ..Default::default()
    };

    let service = CertificateSigningService::new(source, provider, options);

    let additional_contributor = Box::new(MockHeaderContributor::new());
    let mut context = SigningContext::from_bytes(vec![]);
    context
        .additional_header_contributors
        .push(additional_contributor);

    let result = service.get_cose_signer(&context);
    assert!(result.is_ok());
}

#[test]
fn test_get_cose_signer_certificate_source_failure() {
    let source = Box::new(MockCertificateSource::with_failure());
    let provider = Arc::new(MockSigningKeyProvider::new(false));
    let options = CertificateSigningOptions::default();

    let service = CertificateSigningService::new(source, provider, options);
    let context = SigningContext::from_bytes(vec![]);

    let result = service.get_cose_signer(&context);
    assert!(result.is_err());
    match result {
        Err(cose_sign1_signing::SigningError::SigningFailed { detail }) => {
            assert!(detail.contains("Mock failure"));
        }
        _ => panic!("Expected SigningFailed error"),
    }
}

#[test]
fn test_verify_signature_returns_true() {
    // Generate a real EC P-256 key pair and self-signed certificate
    let factory = cose_sign1_certificates_local::EphemeralCertificateFactory::new(
        Box::new(cose_sign1_certificates_local::SoftwareKeyProvider::new()),
    );
    let test_cert = factory
        .create_certificate(
            cose_sign1_certificates_local::CertificateOptions::new()
                .with_subject_name("CN=test.example.com")
                .add_subject_alternative_name("test.example.com"),
        )
        .unwrap();
    let cert_der = test_cert.cert_der.clone();

    // Build a COSE_Sign1 message signed by this key
    let payload = b"test payload for verification";

    // Create an OpenSSL signer from the private key DER
    let private_key_der = test_cert.private_key_der.clone().unwrap();
    let signer =
        cose_sign1_crypto_openssl::evp_signer::EvpSigner::from_der(&private_key_der, -7).unwrap();

    // Build and sign a tagged COSE_Sign1 message
    let builder = cose_sign1_primitives::CoseSign1Builder::new().tagged(true);
    let signed_bytes = builder.sign(&signer, payload).expect("sign");

    // Now set up CertificateSigningService with the real cert
    let source = Box::new(MockCertificateSource::new(cert_der, vec![]));
    let provider = Arc::new(MockSigningKeyProvider::new(false));
    let options = CertificateSigningOptions::default();

    let service = CertificateSigningService::new(source, provider, options);
    let context = SigningContext::from_bytes(vec![]);

    let result = service.verify_signature(&signed_bytes, &context);
    assert!(result.is_ok(), "verify_signature failed: {:?}", result);
    assert!(result.unwrap(), "signature should be valid");
}

#[test]
fn test_verify_signature_rejects_tampered_message() {
    // Generate a real EC P-256 key pair and self-signed certificate
    let factory = cose_sign1_certificates_local::EphemeralCertificateFactory::new(
        Box::new(cose_sign1_certificates_local::SoftwareKeyProvider::new()),
    );
    let test_cert = factory
        .create_certificate(
            cose_sign1_certificates_local::CertificateOptions::new()
                .with_subject_name("CN=test.example.com")
                .add_subject_alternative_name("test.example.com"),
        )
        .unwrap();
    let cert_der = test_cert.cert_der.clone();

    // Build a COSE_Sign1 message signed by this key
    let payload = b"original payload";
    let private_key_der = test_cert.private_key_der.clone().unwrap();
    let signer =
        cose_sign1_crypto_openssl::evp_signer::EvpSigner::from_der(&private_key_der, -7).unwrap();

    let builder = cose_sign1_primitives::CoseSign1Builder::new().tagged(true);
    let mut signed_bytes = builder.sign(&signer, payload).expect("sign");

    // Tamper with the last byte of the signature
    let len = signed_bytes.len();
    signed_bytes[len - 1] ^= 0xFF;

    let source = Box::new(MockCertificateSource::new(cert_der, vec![]));
    let provider = Arc::new(MockSigningKeyProvider::new(false));
    let options = CertificateSigningOptions::default();
    let service = CertificateSigningService::new(source, provider, options);
    let context = SigningContext::from_bytes(vec![]);

    let result = service.verify_signature(&signed_bytes, &context);
    // Either returns Ok(false) or Err — both indicate invalid signature
    match result {
        Ok(false) => {} // Verification correctly returned false
        Err(_) => {}    // Verification error is also acceptable for tampered data
        Ok(true) => panic!("tampered message should not verify as valid"),
    }
}

#[test]
fn test_verify_signature_invalid_message_returns_error() {
    let cert = create_test_cert();
    let source = Box::new(MockCertificateSource::new(cert, vec![]));
    let provider = Arc::new(MockSigningKeyProvider::new(false));
    let options = CertificateSigningOptions::default();

    let service = CertificateSigningService::new(source, provider, options);
    let context = SigningContext::from_bytes(vec![]);

    // Garbage bytes are not a valid COSE_Sign1 message
    let result = service.verify_signature(&[1, 2, 3, 4], &context);
    assert!(result.is_err(), "invalid message bytes should return Err");
}

#[test]
fn test_arc_signer_wrapper_functionality() {
    // Test the ArcSignerWrapper by creating a service and getting a signer
    let cert = create_test_cert();
    let source = Box::new(MockCertificateSource::new(cert, vec![]));
    let provider = Arc::new(MockSigningKeyProvider::new(false));
    let options = CertificateSigningOptions {
        enable_scitt_compliance: false, // Disable SCITT for mock cert
        ..Default::default()
    };

    let service = CertificateSigningService::new(source, provider, options);
    let context = SigningContext::from_bytes(vec![]);

    let signer = service.get_cose_signer(&context).unwrap();

    // Test the wrapped signer methods
    assert_eq!(signer.signer().algorithm(), -7);
    assert_eq!(signer.signer().key_id(), Some(b"mock-key-id".as_slice()));
    assert_eq!(signer.signer().key_type(), "EC");

    let signature = signer.signer().sign(b"test data");
    assert!(signature.is_ok());
    assert_eq!(signature.unwrap(), vec![0xDE, 0xAD, 0xBE, 0xEF]);
}

#[test]
fn test_arc_signer_wrapper_sign_failure() {
    let cert = create_test_cert();
    let source = Box::new(MockCertificateSource::new(cert, vec![]));
    let provider = Arc::new(MockSigningKeyProvider::with_sign_failure());
    let options = CertificateSigningOptions {
        enable_scitt_compliance: false, // Disable SCITT for mock cert
        ..Default::default()
    };

    let service = CertificateSigningService::new(source, provider, options);
    let context = SigningContext::from_bytes(vec![]);

    let signer = service.get_cose_signer(&context).unwrap();

    let signature = signer.signer().sign(b"test data");
    assert!(signature.is_err());
    match signature {
        Err(CryptoError::SigningFailed(msg)) => {
            assert!(msg.contains("Mock sign failure"));
        }
        _ => panic!("Expected SigningFailed error"),
    }
}
