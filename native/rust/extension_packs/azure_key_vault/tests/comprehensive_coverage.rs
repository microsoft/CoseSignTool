// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Comprehensive coverage tests for the AKV signing layer.
//! Uses MockCryptoClient to exercise all code paths in:
//! - AzureKeyVaultSigningService (get_cose_signer, verify_signature, initialize)
//! - AzureKeyVaultSigningKey (sign, hash_sig_structure, build_cose_key_cbor, get_cose_key_bytes)
//! - AzureKeyVaultCertificateSource (initialize, CertificateSource, RemoteCertificateSource)
//! - Header contributors (KeyIdHeaderContributor, CoseKeyHeaderContributor)

use cose_sign1_azure_key_vault::common::{AkvError, KeyVaultCryptoClient};
use cose_sign1_azure_key_vault::signing::akv_certificate_source::AzureKeyVaultCertificateSource;
use cose_sign1_azure_key_vault::signing::{
    AzureKeyVaultSigningKey, AzureKeyVaultSigningService, CoseKeyHeaderContributor,
    CoseKeyHeaderLocation, KeyIdHeaderContributor,
};
use cose_sign1_signing::{SigningContext, SigningService};
use crypto_primitives::CryptoSigner;

// ==================== Mock ====================

struct MockCryptoClient {
    key_id: String,
    key_type: String,
    curve: Option<String>,
    name: String,
    version: String,
    hsm: bool,
    sign_result: Result<Vec<u8>, String>,
    public_key_result: Result<Vec<u8>, String>,
}

impl MockCryptoClient {
    fn ec_p256() -> Self {
        Self {
            key_id: "https://vault.azure.net/keys/k/v1".into(),
            key_type: "EC".into(),
            curve: Some("P-256".into()),
            name: "k".into(),
            version: "v1".into(),
            hsm: false,
            sign_result: Ok(vec![0xDE; 32]),
            public_key_result: Ok(vec![0x04; 65]),
        }
    }

    fn ec_p384() -> Self {
        Self {
            key_id: "https://vault.azure.net/keys/k384/v2".into(),
            key_type: "EC".into(),
            curve: Some("P-384".into()),
            name: "k384".into(),
            version: "v2".into(),
            hsm: true,
            sign_result: Ok(vec![0xCA; 48]),
            public_key_result: Ok(vec![0x04; 97]),
        }
    }

    fn ec_p521() -> Self {
        Self {
            key_id: "https://vault.azure.net/keys/k521/v3".into(),
            key_type: "EC".into(),
            curve: Some("P-521".into()),
            name: "k521".into(),
            version: "v3".into(),
            hsm: false,
            sign_result: Ok(vec![0xAB; 66]),
            public_key_result: Ok(vec![0x04; 133]),
        }
    }

    fn rsa() -> Self {
        Self {
            key_id: "https://vault.azure.net/keys/rsa/v4".into(),
            key_type: "RSA".into(),
            curve: None,
            name: "rsa".into(),
            version: "v4".into(),
            hsm: true,
            sign_result: Ok(vec![0x01; 256]),
            public_key_result: Ok(vec![0x30; 294]),
        }
    }

    fn failing() -> Self {
        Self {
            key_id: "https://vault.azure.net/keys/fail/v0".into(),
            key_type: "EC".into(),
            curve: Some("P-256".into()),
            name: "fail".into(),
            version: "v0".into(),
            hsm: false,
            sign_result: Err("mock sign failure".into()),
            public_key_result: Err("mock public key failure".into()),
        }
    }
}

impl KeyVaultCryptoClient for MockCryptoClient {
    fn sign(&self, _alg: &str, _digest: &[u8]) -> Result<Vec<u8>, AkvError> {
        self.sign_result
            .clone()
            .map_err(|e| AkvError::CryptoOperationFailed(e))
    }
    fn key_id(&self) -> &str {
        &self.key_id
    }
    fn key_type(&self) -> &str {
        &self.key_type
    }
    fn key_size(&self) -> Option<usize> {
        None
    }
    fn curve_name(&self) -> Option<&str> {
        self.curve.as_deref()
    }
    fn public_key_bytes(&self) -> Result<Vec<u8>, AkvError> {
        self.public_key_result
            .clone()
            .map_err(|e| AkvError::General(e))
    }
    fn name(&self) -> &str {
        &self.name
    }
    fn version(&self) -> &str {
        &self.version
    }
    fn is_hsm_protected(&self) -> bool {
        self.hsm
    }
}

// ==================== AzureKeyVaultSigningKey tests ====================

#[test]
fn signing_key_sign_es256() {
    let key = AzureKeyVaultSigningKey::new(Box::new(MockCryptoClient::ec_p256())).unwrap();
    let result = key.sign(b"test sig_structure data");
    assert!(result.is_ok(), "ES256 sign: {:?}", result.err());
    assert!(!result.unwrap().is_empty());
}

#[test]
fn signing_key_sign_es384() {
    let key = AzureKeyVaultSigningKey::new(Box::new(MockCryptoClient::ec_p384())).unwrap();
    let result = key.sign(b"test data for p384");
    assert!(result.is_ok(), "ES384 sign: {:?}", result.err());
}

#[test]
fn signing_key_sign_es512() {
    let key = AzureKeyVaultSigningKey::new(Box::new(MockCryptoClient::ec_p521())).unwrap();
    let result = key.sign(b"test data for p521");
    assert!(result.is_ok(), "ES512 sign: {:?}", result.err());
}

#[test]
fn signing_key_sign_rsa_pss() {
    let key = AzureKeyVaultSigningKey::new(Box::new(MockCryptoClient::rsa())).unwrap();
    let result = key.sign(b"test data for rsa");
    assert!(result.is_ok(), "PS256 sign: {:?}", result.err());
}

#[test]
fn signing_key_sign_failure_propagates() {
    let key = AzureKeyVaultSigningKey::new(Box::new(MockCryptoClient::failing())).unwrap();
    let result = key.sign(b"data");
    assert!(result.is_err());
    let err = format!("{}", result.unwrap_err());
    assert!(err.contains("mock sign failure"));
}

#[test]
fn signing_key_algorithm_accessor() {
    let key = AzureKeyVaultSigningKey::new(Box::new(MockCryptoClient::ec_p256())).unwrap();
    assert_eq!(key.algorithm(), -7); // ES256
}

#[test]
fn signing_key_key_id_accessor() {
    let key = AzureKeyVaultSigningKey::new(Box::new(MockCryptoClient::ec_p256())).unwrap();
    assert!(key.key_id().is_some());
}

#[test]
fn signing_key_key_type_accessor() {
    let key = AzureKeyVaultSigningKey::new(Box::new(MockCryptoClient::ec_p256())).unwrap();
    assert_eq!(key.key_type(), "EC");
}

#[test]
fn signing_key_supports_streaming_false() {
    let key = AzureKeyVaultSigningKey::new(Box::new(MockCryptoClient::ec_p256())).unwrap();
    assert!(!key.supports_streaming());
}

#[test]
fn signing_key_clone() {
    let key = AzureKeyVaultSigningKey::new(Box::new(MockCryptoClient::ec_p256())).unwrap();
    let cloned = key.clone();
    assert_eq!(cloned.algorithm(), key.algorithm());
}

#[test]
fn signing_key_get_cose_key_bytes() {
    let key = AzureKeyVaultSigningKey::new(Box::new(MockCryptoClient::ec_p256())).unwrap();
    let result = key.get_cose_key_bytes();
    assert!(result.is_ok());
    // Call again to exercise cache path
    let cached = key.get_cose_key_bytes();
    assert!(cached.is_ok());
    assert_eq!(result.unwrap(), cached.unwrap());
}

#[test]
fn signing_key_get_cose_key_bytes_failure() {
    let key = AzureKeyVaultSigningKey::new(Box::new(MockCryptoClient::failing())).unwrap();
    let result = key.get_cose_key_bytes();
    assert!(result.is_err());
}

#[test]
fn signing_key_metadata() {
    use cose_sign1_signing::SigningServiceKey;
    let key = AzureKeyVaultSigningKey::new(Box::new(MockCryptoClient::ec_p256())).unwrap();
    let meta = key.metadata();
    assert!(meta.is_remote);
}

// ==================== AzureKeyVaultSigningService tests ====================

#[test]
fn service_initialize_idempotent() {
    let mut svc = AzureKeyVaultSigningService::new(Box::new(MockCryptoClient::ec_p256())).unwrap();
    svc.initialize().unwrap();
    svc.initialize().unwrap(); // second call should be no-op
}

#[test]
fn service_get_cose_signer_with_content_type() {
    let mut svc = AzureKeyVaultSigningService::new(Box::new(MockCryptoClient::ec_p256())).unwrap();
    svc.initialize().unwrap();

    let mut ctx = SigningContext::from_bytes(vec![]);
    ctx.content_type = Some("application/cose".to_string());
    let signer = svc.get_cose_signer(&ctx).unwrap();
    let _ = signer; // exercises content-type header addition
}

#[test]
fn service_get_cose_signer_protected_key_embedding() {
    let mut svc = AzureKeyVaultSigningService::new(Box::new(MockCryptoClient::ec_p256())).unwrap();
    svc.initialize().unwrap();
    svc.enable_public_key_embedding(CoseKeyHeaderLocation::Protected)
        .unwrap();

    let ctx = SigningContext::from_bytes(vec![]);
    let signer = svc.get_cose_signer(&ctx).unwrap();
    let _ = signer; // exercises protected key embedding path
}

#[test]
fn service_get_cose_signer_unprotected_key_embedding() {
    let mut svc = AzureKeyVaultSigningService::new(Box::new(MockCryptoClient::ec_p256())).unwrap();
    svc.initialize().unwrap();
    svc.enable_public_key_embedding(CoseKeyHeaderLocation::Unprotected)
        .unwrap();

    let ctx = SigningContext::from_bytes(vec![]);
    let signer = svc.get_cose_signer(&ctx).unwrap();
    let _ = signer;
}

#[test]
fn service_is_remote() {
    let svc = AzureKeyVaultSigningService::new(Box::new(MockCryptoClient::ec_p256())).unwrap();
    assert!(svc.is_remote());
}

#[test]
fn service_metadata() {
    let svc = AzureKeyVaultSigningService::new(Box::new(MockCryptoClient::ec_p256())).unwrap();
    let meta = svc.service_metadata();
    assert!(!meta.service_name.is_empty());
}

#[test]
fn service_verify_signature_invalid_message() {
    let mut svc = AzureKeyVaultSigningService::new(Box::new(MockCryptoClient::ec_p256())).unwrap();
    svc.initialize().unwrap();
    let ctx = SigningContext::from_bytes(vec![]);
    let result = svc.verify_signature(b"not a cose message", &ctx);
    assert!(result.is_err());
}

#[test]
fn service_verify_signature_not_initialized() {
    let svc = AzureKeyVaultSigningService::new(Box::new(MockCryptoClient::ec_p256())).unwrap();
    let ctx = SigningContext::from_bytes(vec![]);
    let result = svc.verify_signature(b"data", &ctx);
    assert!(result.is_err());
}

#[test]
fn service_not_initialized_error() {
    let svc = AzureKeyVaultSigningService::new(Box::new(MockCryptoClient::ec_p256())).unwrap();
    let ctx = SigningContext::from_bytes(vec![]);
    assert!(svc.get_cose_signer(&ctx).is_err());
}

#[test]
fn service_enable_public_key_failure() {
    let mut svc = AzureKeyVaultSigningService::new(Box::new(MockCryptoClient::failing())).unwrap();
    let result = svc.enable_public_key_embedding(CoseKeyHeaderLocation::Protected);
    assert!(result.is_err());
}

#[test]
fn service_rsa_signing() {
    let mut svc = AzureKeyVaultSigningService::new(Box::new(MockCryptoClient::rsa())).unwrap();
    svc.initialize().unwrap();
    let ctx = SigningContext::from_bytes(vec![]);
    let signer = svc.get_cose_signer(&ctx).unwrap();
    let _ = signer;
}

#[test]
fn service_p384_signing() {
    let mut svc = AzureKeyVaultSigningService::new(Box::new(MockCryptoClient::ec_p384())).unwrap();
    svc.initialize().unwrap();
    let ctx = SigningContext::from_bytes(vec![]);
    let signer = svc.get_cose_signer(&ctx).unwrap();
    let _ = signer;
}

// ==================== AzureKeyVaultCertificateSource tests ====================

#[test]
fn cert_source_not_initialized() {
    use cose_sign1_certificates::signing::source::CertificateSource;
    let src = AzureKeyVaultCertificateSource::new(Box::new(MockCryptoClient::ec_p256()));
    let result = src.get_signing_certificate();
    assert!(result.is_err());
}

#[test]
fn cert_source_initialize_and_get_cert() {
    use cose_sign1_certificates::signing::source::CertificateSource;
    let mut src = AzureKeyVaultCertificateSource::new(Box::new(MockCryptoClient::ec_p256()));
    let cert_der = vec![0x30, 0x82, 0x01, 0x22]; // fake DER
    src.initialize(cert_der.clone(), vec![]).unwrap();
    let result = src.get_signing_certificate().unwrap();
    assert_eq!(result, cert_der.as_slice());
}

#[test]
fn cert_source_has_private_key() {
    use cose_sign1_certificates::signing::source::CertificateSource;
    let src = AzureKeyVaultCertificateSource::new(Box::new(MockCryptoClient::ec_p256()));
    assert!(src.has_private_key());
}

#[test]
fn cert_source_chain_builder() {
    use cose_sign1_certificates::signing::source::CertificateSource;
    let mut src = AzureKeyVaultCertificateSource::new(Box::new(MockCryptoClient::ec_p256()));
    let cert = vec![0x30, 0x82];
    let chain_cert = vec![0x30, 0x83];
    src.initialize(cert, vec![chain_cert]).unwrap();
    let _ = src.get_chain_builder();
}

#[test]
fn cert_source_sign_rsa() {
    use cose_sign1_certificates::signing::remote::RemoteCertificateSource;
    let src = AzureKeyVaultCertificateSource::new(Box::new(MockCryptoClient::rsa()));
    let result = src.sign_data_rsa(b"data to sign", "SHA-256");
    assert!(result.is_ok());
}

#[test]
fn cert_source_sign_rsa_sha384() {
    use cose_sign1_certificates::signing::remote::RemoteCertificateSource;
    let src = AzureKeyVaultCertificateSource::new(Box::new(MockCryptoClient::rsa()));
    let result = src.sign_data_rsa(b"data", "SHA-384");
    assert!(result.is_ok());
}

#[test]
fn cert_source_sign_rsa_sha512() {
    use cose_sign1_certificates::signing::remote::RemoteCertificateSource;
    let src = AzureKeyVaultCertificateSource::new(Box::new(MockCryptoClient::rsa()));
    let result = src.sign_data_rsa(b"data", "SHA-512");
    assert!(result.is_ok());
}

#[test]
fn cert_source_sign_rsa_unknown_hash() {
    use cose_sign1_certificates::signing::remote::RemoteCertificateSource;
    let src = AzureKeyVaultCertificateSource::new(Box::new(MockCryptoClient::rsa()));
    let result = src.sign_data_rsa(b"data", "MD5");
    assert!(result.is_err());
}

#[test]
fn cert_source_sign_ecdsa() {
    use cose_sign1_certificates::signing::remote::RemoteCertificateSource;
    let src = AzureKeyVaultCertificateSource::new(Box::new(MockCryptoClient::ec_p256()));
    let result = src.sign_data_ecdsa(b"data to sign", "SHA-256");
    assert!(result.is_ok());
}

#[test]
fn cert_source_sign_ecdsa_sha384() {
    use cose_sign1_certificates::signing::remote::RemoteCertificateSource;
    let src = AzureKeyVaultCertificateSource::new(Box::new(MockCryptoClient::ec_p256()));
    let result = src.sign_data_ecdsa(b"data", "SHA-384");
    assert!(result.is_ok());
}

#[test]
fn cert_source_sign_ecdsa_unknown_hash() {
    use cose_sign1_certificates::signing::remote::RemoteCertificateSource;
    let src = AzureKeyVaultCertificateSource::new(Box::new(MockCryptoClient::ec_p256()));
    let result = src.sign_data_ecdsa(b"data", "BLAKE3");
    assert!(result.is_err());
}

#[test]
fn cert_source_sign_failure() {
    use cose_sign1_certificates::signing::remote::RemoteCertificateSource;
    let src = AzureKeyVaultCertificateSource::new(Box::new(MockCryptoClient::failing()));
    let result = src.sign_data_rsa(b"data", "SHA-256");
    assert!(result.is_err());
}

// ==================== Header contributors ====================

#[test]
fn key_id_contributor_new() {
    let c = KeyIdHeaderContributor::new("https://vault/keys/k/v".to_string());
    let _ = c;
}

#[test]
fn cose_key_contributor_protected() {
    let c = CoseKeyHeaderContributor::new(vec![0x04; 65], CoseKeyHeaderLocation::Protected);
    let _ = c;
}

#[test]
fn cose_key_contributor_unprotected() {
    let c = CoseKeyHeaderContributor::new(vec![0x04; 65], CoseKeyHeaderLocation::Unprotected);
    let _ = c;
}

// ==================== Unsupported key type ====================

#[test]
fn signing_key_unsupported_key_type() {
    let mock = MockCryptoClient {
        key_id: "https://vault/keys/bad/v1".into(),
        key_type: "CHACHA".into(),
        curve: None,
        name: "bad".into(),
        version: "v1".into(),
        hsm: false,
        sign_result: Ok(vec![]),
        public_key_result: Ok(vec![]),
    };
    let result = AzureKeyVaultSigningKey::new(Box::new(mock));
    assert!(result.is_err());
}

#[test]
fn signing_key_ec_missing_curve() {
    let mock = MockCryptoClient {
        key_id: "https://vault/keys/nocrv/v1".into(),
        key_type: "EC".into(),
        curve: None, // missing!
        name: "nocrv".into(),
        version: "v1".into(),
        hsm: false,
        sign_result: Ok(vec![]),
        public_key_result: Ok(vec![]),
    };
    let result = AzureKeyVaultSigningKey::new(Box::new(mock));
    assert!(result.is_err());
}

#[test]
fn signing_key_ec_unsupported_curve() {
    let mock = MockCryptoClient {
        key_id: "https://vault/keys/badcrv/v1".into(),
        key_type: "EC".into(),
        curve: Some("secp256k1".into()), // not supported
        name: "badcrv".into(),
        version: "v1".into(),
        hsm: false,
        sign_result: Ok(vec![]),
        public_key_result: Ok(vec![]),
    };
    let result = AzureKeyVaultSigningKey::new(Box::new(mock));
    assert!(result.is_err());
}

// ==================== COSE_Key CBOR encoding ====================

#[test]
fn cose_key_cbor_ec_p256() {
    let key = AzureKeyVaultSigningKey::new(Box::new(MockCryptoClient::ec_p256())).unwrap();
    let cose_key = key.get_cose_key_bytes().unwrap();
    assert!(!cose_key.is_empty());
    assert_eq!(cose_key[0] & 0xF0, 0xA0, "Should be a CBOR map");
}

#[test]
fn cose_key_cbor_ec_p384() {
    let key = AzureKeyVaultSigningKey::new(Box::new(MockCryptoClient::ec_p384())).unwrap();
    let cose_key = key.get_cose_key_bytes().unwrap();
    assert!(!cose_key.is_empty());
}

#[test]
fn cose_key_cbor_ec_p521() {
    let key = AzureKeyVaultSigningKey::new(Box::new(MockCryptoClient::ec_p521())).unwrap();
    let cose_key = key.get_cose_key_bytes().unwrap();
    assert!(!cose_key.is_empty());
}

#[test]
fn cose_key_cbor_rsa() {
    let key = AzureKeyVaultSigningKey::new(Box::new(MockCryptoClient::rsa())).unwrap();
    let cose_key = key.get_cose_key_bytes().unwrap();
    assert!(!cose_key.is_empty());
    assert_eq!(cose_key[0] & 0xF0, 0xA0, "Should be a CBOR map");
}

#[test]
fn cose_key_cbor_invalid_ec_format() {
    let mock = MockCryptoClient {
        key_id: "https://vault/keys/badec/v1".into(),
        key_type: "EC".into(),
        curve: Some("P-256".into()),
        name: "badec".into(),
        version: "v1".into(),
        hsm: false,
        sign_result: Ok(vec![0xDE; 32]),
        public_key_result: Ok(vec![0x00; 64]), // no 0x04 prefix
    };
    let key = AzureKeyVaultSigningKey::new(Box::new(mock)).unwrap();
    let result = key.get_cose_key_bytes();
    assert!(result.is_err(), "Invalid EC format should fail");
}

#[test]
fn cose_key_cbor_empty_public_key() {
    let mock = MockCryptoClient {
        key_id: "https://vault/keys/empty/v1".into(),
        key_type: "EC".into(),
        curve: Some("P-256".into()),
        name: "empty".into(),
        version: "v1".into(),
        hsm: false,
        sign_result: Ok(vec![]),
        public_key_result: Ok(vec![]),
    };
    let key = AzureKeyVaultSigningKey::new(Box::new(mock)).unwrap();
    let result = key.get_cose_key_bytes();
    assert!(result.is_err());
}

#[test]
fn cose_key_cbor_rsa_too_short() {
    let mock = MockCryptoClient {
        key_id: "https://vault/keys/shortrsa/v1".into(),
        key_type: "RSA".into(),
        curve: None,
        name: "shortrsa".into(),
        version: "v1".into(),
        hsm: false,
        sign_result: Ok(vec![0x01; 256]),
        public_key_result: Ok(vec![0x01, 0x02]), // too short
    };
    let key = AzureKeyVaultSigningKey::new(Box::new(mock)).unwrap();
    let result = key.get_cose_key_bytes();
    assert!(result.is_err(), "RSA key too short should fail");
}

// ==================== verify_signature ====================

#[test]
fn verify_signature_with_malformed_bytes() {
    let mut svc = AzureKeyVaultSigningService::new(Box::new(MockCryptoClient::ec_p256())).unwrap();
    svc.initialize().unwrap();
    let ctx = SigningContext::from_bytes(vec![]);
    let result = svc.verify_signature(b"not-a-valid-cose-message", &ctx);
    assert!(result.is_err());
}

#[test]
fn verify_signature_with_crafted_cose_message() {
    use cbor_primitives::{CborEncoder, CborProvider};
    use cbor_primitives_everparse::EverParseCborProvider;

    let mut svc = AzureKeyVaultSigningService::new(Box::new(MockCryptoClient::ec_p256())).unwrap();
    svc.initialize().unwrap();

    let p = EverParseCborProvider;
    let mut phdr = p.encoder();
    phdr.encode_map(1).unwrap();
    phdr.encode_i64(1).unwrap();
    phdr.encode_i64(-7).unwrap();
    let phdr_bytes = phdr.into_bytes();

    let mut enc = p.encoder();
    enc.encode_array(4).unwrap();
    enc.encode_bstr(&phdr_bytes).unwrap();
    enc.encode_map(0).unwrap();
    enc.encode_bstr(b"test payload").unwrap();
    enc.encode_bstr(&vec![0xDE; 64]).unwrap();
    let cose_bytes = enc.into_bytes();

    let ctx = SigningContext::from_bytes(vec![]);
    let result = svc.verify_signature(&cose_bytes, &ctx);
    match result {
        Ok(false) => {}
        Err(_) => {}
        Ok(true) => panic!("Fake signature should not verify"),
    }
}

#[test]
fn service_get_cose_signer_with_extra_contributor() {
    use cose_sign1_primitives::CoseHeaderMap;
    use cose_sign1_signing::HeaderContributor;

    struct NoopContributor;
    impl HeaderContributor for NoopContributor {
        fn contribute_protected_headers(
            &self,
            _headers: &mut CoseHeaderMap,
            _ctx: &cose_sign1_signing::HeaderContributorContext,
        ) {
        }
        fn contribute_unprotected_headers(
            &self,
            _headers: &mut CoseHeaderMap,
            _ctx: &cose_sign1_signing::HeaderContributorContext,
        ) {
        }
        fn merge_strategy(&self) -> cose_sign1_signing::HeaderMergeStrategy {
            cose_sign1_signing::HeaderMergeStrategy::Replace
        }
    }

    let mut svc = AzureKeyVaultSigningService::new(Box::new(MockCryptoClient::ec_p256())).unwrap();
    svc.initialize().unwrap();

    let mut ctx = SigningContext::from_bytes(b"payload".to_vec());
    ctx.additional_header_contributors
        .push(Box::new(NoopContributor));
    assert!(svc.get_cose_signer(&ctx).is_ok());
}

#[test]
fn service_get_cose_signer_with_fail_merge_strategy() {
    use cose_sign1_primitives::CoseHeaderMap;
    use cose_sign1_signing::HeaderContributor;

    struct FailStrategyContributor;
    impl HeaderContributor for FailStrategyContributor {
        fn contribute_protected_headers(
            &self,
            _headers: &mut CoseHeaderMap,
            _ctx: &cose_sign1_signing::HeaderContributorContext,
        ) {
        }
        fn contribute_unprotected_headers(
            &self,
            _headers: &mut CoseHeaderMap,
            _ctx: &cose_sign1_signing::HeaderContributorContext,
        ) {
        }
        fn merge_strategy(&self) -> cose_sign1_signing::HeaderMergeStrategy {
            cose_sign1_signing::HeaderMergeStrategy::Fail
        }
    }

    let mut svc = AzureKeyVaultSigningService::new(Box::new(MockCryptoClient::ec_p256())).unwrap();
    svc.initialize().unwrap();

    let mut ctx = SigningContext::from_bytes(b"payload".to_vec());
    ctx.additional_header_contributors
        .push(Box::new(FailStrategyContributor));
    // The Fail strategy does conflict detection — exercises lines 133-140
    let result = svc.get_cose_signer(&ctx);
    assert!(result.is_ok());
}

#[test]
fn service_get_cose_signer_with_content_type_already_set() {
    let mut svc = AzureKeyVaultSigningService::new(Box::new(MockCryptoClient::ec_p256())).unwrap();
    svc.initialize().unwrap();

    // Create context with content_type — exercises lines 152-157
    let mut ctx = SigningContext::from_bytes(b"payload".to_vec());
    ctx.content_type = Some("application/cose".to_string());
    let result = svc.get_cose_signer(&ctx);
    assert!(result.is_ok());
}
