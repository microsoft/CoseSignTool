// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Tests for Azure Key Vault signing components using a mock KeyVaultCryptoClient.
//! No Azure service access required — the trait seam enables full offline testing.

use cose_sign1_azure_key_vault::common::{AkvError, KeyVaultCryptoClient};
use cose_sign1_azure_key_vault::signing::{
    AzureKeyVaultSigningKey, AzureKeyVaultSigningService, CoseKeyHeaderContributor,
    CoseKeyHeaderLocation, KeyIdHeaderContributor,
};
use cose_sign1_primitives::{CoseHeaderLabel, CoseHeaderMap};
use cose_sign1_signing::{
    HeaderContributor, HeaderContributorContext, SigningContext, SigningService,
};
use crypto_primitives::CryptoSigner;

// ========================================================================
// Mock KeyVaultCryptoClient
// ========================================================================

struct MockCryptoClient {
    key_id: String,
    key_type: String,
    curve: Option<String>,
    name: String,
    version: String,
    hsm: bool,
    sign_ok: Option<Vec<u8>>,
    sign_err: Option<String>,
    public_key_ok: Option<Vec<u8>>,
    public_key_err: Option<String>,
}

impl MockCryptoClient {
    fn ec_p256() -> Self {
        Self {
            key_id: "https://test-vault.vault.azure.net/keys/test-key/abc123".into(),
            key_type: "EC".into(),
            curve: Some("P-256".into()),
            name: "test-key".into(),
            version: "abc123".into(),
            hsm: false,
            sign_ok: Some(vec![
                0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A,
                0x0B, 0x0C,
            ]),
            sign_err: None,
            public_key_ok: Some(vec![0x04; 65]),
            public_key_err: None,
        }
    }

    fn ec_p384() -> Self {
        Self {
            key_id: "https://test-vault.vault.azure.net/keys/p384-key/def456".into(),
            key_type: "EC".into(),
            curve: Some("P-384".into()),
            name: "p384-key".into(),
            version: "def456".into(),
            hsm: true,
            sign_ok: Some(vec![0xCA; 48]),
            sign_err: None,
            public_key_ok: Some(vec![0x04; 97]),
            public_key_err: None,
        }
    }

    fn ec_p521() -> Self {
        Self {
            key_id: "https://test-vault.vault.azure.net/keys/p521-key/ghi789".into(),
            key_type: "EC".into(),
            curve: Some("P-521".into()),
            name: "p521-key".into(),
            version: "ghi789".into(),
            hsm: false,
            sign_ok: Some(vec![0xAB; 32]),
            sign_err: None,
            public_key_ok: Some(vec![0x04; 133]),
            public_key_err: None,
        }
    }

    fn rsa() -> Self {
        Self {
            key_id: "https://test-vault.vault.azure.net/keys/rsa-key/jkl012".into(),
            key_type: "RSA".into(),
            curve: None,
            name: "rsa-key".into(),
            version: "jkl012".into(),
            hsm: true,
            sign_ok: Some(vec![0x01; 256]),
            sign_err: None,
            public_key_ok: Some(vec![0x30; 294]),
            public_key_err: None,
        }
    }

    fn failing() -> Self {
        Self {
            key_id: "https://test-vault.vault.azure.net/keys/fail-key/bad".into(),
            key_type: "EC".into(),
            curve: Some("P-256".into()),
            name: "fail-key".into(),
            version: "bad".into(),
            hsm: false,
            sign_ok: None,
            sign_err: Some("mock signing failure".into()),
            public_key_ok: None,
            public_key_err: Some("mock network failure".into()),
        }
    }
}

impl KeyVaultCryptoClient for MockCryptoClient {
    fn sign(&self, _algorithm: &str, _digest: &[u8]) -> Result<Vec<u8>, AkvError> {
        if let Some(ref sig) = self.sign_ok {
            Ok(sig.clone())
        } else {
            Err(AkvError::CryptoOperationFailed(
                self.sign_err.clone().unwrap_or_default(),
            ))
        }
    }

    fn key_id(&self) -> &str {
        &self.key_id
    }
    fn key_type(&self) -> &str {
        &self.key_type
    }
    fn key_size(&self) -> Option<usize> {
        if self.key_type == "RSA" {
            Some(2048)
        } else {
            None
        }
    }
    fn curve_name(&self) -> Option<&str> {
        self.curve.as_deref()
    }
    fn public_key_bytes(&self) -> Result<Vec<u8>, AkvError> {
        if let Some(ref pk) = self.public_key_ok {
            Ok(pk.clone())
        } else {
            Err(AkvError::NetworkError(
                self.public_key_err.clone().unwrap_or_default(),
            ))
        }
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

// ========================================================================
// AkvError — Display for all variants
// ========================================================================

#[test]
fn error_display_all_variants() {
    let errors: Vec<AkvError> = vec![
        AkvError::CryptoOperationFailed("op failed".into()),
        AkvError::KeyNotFound("missing".into()),
        AkvError::InvalidKeyType("bad type".into()),
        AkvError::AuthenticationFailed("no creds".into()),
        AkvError::NetworkError("timeout".into()),
        AkvError::InvalidConfiguration("bad config".into()),
        AkvError::CertificateSourceError("cert error".into()),
        AkvError::General("general".into()),
    ];
    for e in &errors {
        let s = e.to_string();
        assert!(!s.is_empty());
        let _d = format!("{:?}", e);
    }
    let boxed: Box<dyn std::error::Error> = Box::new(AkvError::General("test".into()));
    assert!(!boxed.to_string().is_empty());
}

// ========================================================================
// AzureKeyVaultSigningKey — creation, algorithm mapping
// ========================================================================

#[test]
fn signing_key_ec_p256() {
    let key = AzureKeyVaultSigningKey::new(Box::new(MockCryptoClient::ec_p256())).unwrap();
    assert_eq!(key.algorithm(), -7);
    assert_eq!(key.key_type(), "EC");
    assert!(key.key_id().is_some());
    assert!(!key.supports_streaming());
    assert_eq!(
        key.crypto_client().key_id(),
        "https://test-vault.vault.azure.net/keys/test-key/abc123"
    );
}

#[test]
fn signing_key_ec_p384() {
    let key = AzureKeyVaultSigningKey::new(Box::new(MockCryptoClient::ec_p384())).unwrap();
    assert_eq!(key.algorithm(), -35);
    assert!(key.crypto_client().is_hsm_protected());
}

#[test]
fn signing_key_ec_p521() {
    let key = AzureKeyVaultSigningKey::new(Box::new(MockCryptoClient::ec_p521())).unwrap();
    assert_eq!(key.algorithm(), -36);
}

#[test]
fn signing_key_rsa() {
    let key = AzureKeyVaultSigningKey::new(Box::new(MockCryptoClient::rsa())).unwrap();
    assert_eq!(key.algorithm(), -37);
    assert_eq!(key.key_type(), "RSA");
}

#[test]
fn signing_key_unsupported_key_type() {
    let mut mock = MockCryptoClient::ec_p256();
    mock.key_type = "OKP".into();
    mock.curve = Some("Ed25519".into());
    let result = AzureKeyVaultSigningKey::new(Box::new(mock));
    assert!(result.is_err());
}

#[test]
fn signing_key_unsupported_curve() {
    let mut mock = MockCryptoClient::ec_p256();
    mock.curve = Some("secp256k1".into());
    let result = AzureKeyVaultSigningKey::new(Box::new(mock));
    assert!(result.is_err());
}

#[test]
fn signing_key_ec_missing_curve() {
    let mut mock = MockCryptoClient::ec_p256();
    mock.curve = None;
    let result = AzureKeyVaultSigningKey::new(Box::new(mock));
    assert!(result.is_err());
}

// ========================================================================
// AzureKeyVaultSigningKey — CryptoSigner::sign
// ========================================================================

#[test]
fn signing_key_sign_ec_p256() {
    let key = AzureKeyVaultSigningKey::new(Box::new(MockCryptoClient::ec_p256())).unwrap();
    let sig = key.sign(b"test sig_structure data").unwrap();
    assert!(!sig.is_empty());
}

#[test]
fn signing_key_sign_ec_p384() {
    let key = AzureKeyVaultSigningKey::new(Box::new(MockCryptoClient::ec_p384())).unwrap();
    let sig = key.sign(b"test data for p384").unwrap();
    assert!(!sig.is_empty());
}

#[test]
fn signing_key_sign_ec_p521() {
    let key = AzureKeyVaultSigningKey::new(Box::new(MockCryptoClient::ec_p521())).unwrap();
    let sig = key.sign(b"test data for p521").unwrap();
    assert!(!sig.is_empty());
}

#[test]
fn signing_key_sign_rsa() {
    let key = AzureKeyVaultSigningKey::new(Box::new(MockCryptoClient::rsa())).unwrap();
    let sig = key.sign(b"test data for RSA").unwrap();
    assert!(!sig.is_empty());
}

#[test]
fn signing_key_sign_failure() {
    let key = AzureKeyVaultSigningKey::new(Box::new(MockCryptoClient::failing())).unwrap();
    let err = key.sign(b"test data").unwrap_err();
    assert!(!err.to_string().is_empty());
}

// ========================================================================
// AzureKeyVaultSigningKey — COSE_Key caching
// ========================================================================

#[test]
fn signing_key_cose_key_bytes() {
    let key = AzureKeyVaultSigningKey::new(Box::new(MockCryptoClient::ec_p256())).unwrap();
    let bytes1 = key.get_cose_key_bytes().unwrap();
    assert!(!bytes1.is_empty());
    let bytes2 = key.get_cose_key_bytes().unwrap();
    assert_eq!(bytes1, bytes2);
}

#[test]
fn signing_key_cose_key_bytes_failure() {
    let key = AzureKeyVaultSigningKey::new(Box::new(MockCryptoClient::failing())).unwrap();
    assert!(key.get_cose_key_bytes().is_err());
}

// ========================================================================
// AzureKeyVaultSigningKey — metadata
// ========================================================================

#[test]
fn signing_key_metadata() {
    use cose_sign1_signing::SigningServiceKey;
    let key = AzureKeyVaultSigningKey::new(Box::new(MockCryptoClient::ec_p256())).unwrap();
    let meta = key.metadata();
    assert_eq!(meta.algorithm, -7);
    assert!(meta.is_remote);
}

// ========================================================================
// KeyIdHeaderContributor
// ========================================================================

#[test]
fn kid_header_contributor_adds_to_protected() {
    let contributor = KeyIdHeaderContributor::new("https://vault.azure.net/keys/k/v".to_string());
    let mut headers = CoseHeaderMap::new();
    let ctx = SigningContext::from_bytes(vec![]);
    let mock = MockCryptoClient::ec_p256();
    let key = AzureKeyVaultSigningKey::new(Box::new(mock)).unwrap();
    let signer: &dyn CryptoSigner = &key;
    let hcc = HeaderContributorContext::new(&ctx, signer);

    contributor.contribute_protected_headers(&mut headers, &hcc);
    assert!(headers.get(&CoseHeaderLabel::Int(4)).is_some());
}

#[test]
fn kid_header_contributor_keeps_existing() {
    use cose_sign1_primitives::CoseHeaderValue;
    let contributor = KeyIdHeaderContributor::new("new-kid".to_string());
    let mut headers = CoseHeaderMap::new();
    headers.insert(
        CoseHeaderLabel::Int(4),
        CoseHeaderValue::Bytes(b"existing-kid".to_vec().into()),
    );
    let ctx = SigningContext::from_bytes(vec![]);
    let mock = MockCryptoClient::ec_p256();
    let key = AzureKeyVaultSigningKey::new(Box::new(mock)).unwrap();
    let hcc = HeaderContributorContext::new(&ctx, &key as &dyn CryptoSigner);

    contributor.contribute_protected_headers(&mut headers, &hcc);
    match headers.get(&CoseHeaderLabel::Int(4)) {
        Some(CoseHeaderValue::Bytes(b)) => assert_eq!(b.as_bytes(), b"existing-kid"),
        _ => panic!("Expected existing kid preserved"),
    }
}

#[test]
fn kid_header_contributor_unprotected_noop() {
    let contributor = KeyIdHeaderContributor::new("kid".to_string());
    let mut headers = CoseHeaderMap::new();
    let ctx = SigningContext::from_bytes(vec![]);
    let mock = MockCryptoClient::ec_p256();
    let key = AzureKeyVaultSigningKey::new(Box::new(mock)).unwrap();
    let hcc = HeaderContributorContext::new(&ctx, &key as &dyn CryptoSigner);
    contributor.contribute_unprotected_headers(&mut headers, &hcc);
    assert!(headers.is_empty());
}

// ========================================================================
// CoseKeyHeaderContributor
// ========================================================================

#[test]
fn cose_key_contributor_unprotected() {
    let contributor = CoseKeyHeaderContributor::unprotected(vec![0x01, 0x02]);
    let mut protected = CoseHeaderMap::new();
    let mut unprotected = CoseHeaderMap::new();
    let ctx = SigningContext::from_bytes(vec![]);
    let mock = MockCryptoClient::ec_p256();
    let key = AzureKeyVaultSigningKey::new(Box::new(mock)).unwrap();
    let hcc = HeaderContributorContext::new(&ctx, &key as &dyn CryptoSigner);

    contributor.contribute_protected_headers(&mut protected, &hcc);
    contributor.contribute_unprotected_headers(&mut unprotected, &hcc);

    let label = CoseHeaderLabel::Int(-65537);
    assert!(protected.get(&label).is_none());
    assert!(unprotected.get(&label).is_some());
}

#[test]
fn cose_key_contributor_protected() {
    let contributor = CoseKeyHeaderContributor::protected(vec![0xAA, 0xBB]);
    let mut protected = CoseHeaderMap::new();
    let mut unprotected = CoseHeaderMap::new();
    let ctx = SigningContext::from_bytes(vec![]);
    let mock = MockCryptoClient::ec_p256();
    let key = AzureKeyVaultSigningKey::new(Box::new(mock)).unwrap();
    let hcc = HeaderContributorContext::new(&ctx, &key as &dyn CryptoSigner);

    contributor.contribute_protected_headers(&mut protected, &hcc);
    contributor.contribute_unprotected_headers(&mut unprotected, &hcc);

    let label = CoseHeaderLabel::Int(-65537);
    assert!(protected.get(&label).is_some());
    assert!(unprotected.get(&label).is_none());
}

#[test]
fn cose_key_header_location_debug() {
    assert!(format!("{:?}", CoseKeyHeaderLocation::Protected).contains("Protected"));
    assert!(format!("{:?}", CoseKeyHeaderLocation::Unprotected).contains("Unprotected"));
}

// ========================================================================
// AzureKeyVaultSigningService
// ========================================================================

#[test]
fn signing_service_new() {
    let svc = AzureKeyVaultSigningService::new(Box::new(MockCryptoClient::ec_p256())).unwrap();
    assert!(svc.is_remote());
    assert!(!svc.service_metadata().service_name.is_empty());
}

#[test]
fn signing_service_not_initialized_error() {
    let svc = AzureKeyVaultSigningService::new(Box::new(MockCryptoClient::ec_p256())).unwrap();
    let ctx = SigningContext::from_bytes(vec![]);
    assert!(svc.get_cose_signer(&ctx).is_err());
}

#[test]
fn signing_service_initialize_and_sign() {
    let mut svc = AzureKeyVaultSigningService::new(Box::new(MockCryptoClient::ec_p256())).unwrap();
    svc.initialize().unwrap();
    svc.initialize().unwrap(); // double init is no-op

    let ctx = SigningContext::from_bytes(vec![]);
    let cose_signer = svc.get_cose_signer(&ctx).unwrap();
    assert!(!cose_signer.protected_headers().is_empty());
}

#[test]
fn signing_service_with_content_type() {
    let mut svc = AzureKeyVaultSigningService::new(Box::new(MockCryptoClient::ec_p256())).unwrap();
    svc.initialize().unwrap();
    let mut ctx = SigningContext::from_bytes(vec![]);
    ctx.content_type = Some("application/cose".to_string());
    let cose_signer = svc.get_cose_signer(&ctx).unwrap();
    assert!(cose_signer
        .protected_headers()
        .get(&CoseHeaderLabel::Int(3))
        .is_some());
}

#[test]
fn signing_service_enable_public_key_unprotected() {
    let mut svc = AzureKeyVaultSigningService::new(Box::new(MockCryptoClient::ec_p256())).unwrap();
    svc.enable_public_key_embedding(CoseKeyHeaderLocation::Unprotected)
        .unwrap();
    svc.initialize().unwrap();

    let ctx = SigningContext::from_bytes(vec![]);
    let cose_signer = svc.get_cose_signer(&ctx).unwrap();
    assert!(cose_signer
        .unprotected_headers()
        .get(&CoseHeaderLabel::Int(-65537))
        .is_some());
}

#[test]
fn signing_service_enable_public_key_protected() {
    let mut svc = AzureKeyVaultSigningService::new(Box::new(MockCryptoClient::ec_p256())).unwrap();
    svc.enable_public_key_embedding(CoseKeyHeaderLocation::Protected)
        .unwrap();
    svc.initialize().unwrap();

    let ctx = SigningContext::from_bytes(vec![]);
    let cose_signer = svc.get_cose_signer(&ctx).unwrap();
    assert!(cose_signer
        .protected_headers()
        .get(&CoseHeaderLabel::Int(-65537))
        .is_some());
}

#[test]
fn signing_service_enable_public_key_failure() {
    let mut svc = AzureKeyVaultSigningService::new(Box::new(MockCryptoClient::failing())).unwrap();
    assert!(svc
        .enable_public_key_embedding(CoseKeyHeaderLocation::Unprotected)
        .is_err());
}

#[test]
fn signing_service_verify_not_implemented() {
    let mut svc = AzureKeyVaultSigningService::new(Box::new(MockCryptoClient::ec_p256())).unwrap();
    svc.initialize().unwrap();
    let ctx = SigningContext::from_bytes(vec![]);
    assert!(svc.verify_signature(b"msg", &ctx).is_err());
}

#[test]
fn signing_service_rsa() {
    let mut svc = AzureKeyVaultSigningService::new(Box::new(MockCryptoClient::rsa())).unwrap();
    svc.initialize().unwrap();
    let ctx = SigningContext::from_bytes(vec![]);
    let cose_signer = svc.get_cose_signer(&ctx).unwrap();
    assert!(!cose_signer.protected_headers().is_empty());
}

#[test]
fn signing_service_metadata() {
    let svc = AzureKeyVaultSigningService::new(Box::new(MockCryptoClient::ec_p256())).unwrap();
    assert!(svc
        .service_metadata()
        .service_name
        .contains("AzureKeyVault"));
}
