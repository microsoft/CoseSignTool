// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Comprehensive tests for crypto_primitives: JWK types, trait defaults,
//! JwkVerifierFactory dispatch, CryptoError Display/Debug.

use crypto_primitives::{
    CryptoError, CryptoSigner, CryptoVerifier, EcJwk, Jwk, JwkVerifierFactory, PqcJwk, RsaJwk,
};

// ============================================================================
// JWK type construction and accessors
// ============================================================================

#[test]
fn ec_jwk_creation_and_debug() {
    let jwk = EcJwk {
        kty: "EC".into(),
        crv: "P-256".into(),
        x: "base64url_x".into(),
        y: "base64url_y".into(),
        kid: Some("key-1".into()),
    };
    assert_eq!(jwk.kty, "EC");
    assert_eq!(jwk.crv, "P-256");
    assert_eq!(jwk.x, "base64url_x");
    assert_eq!(jwk.y, "base64url_y");
    assert_eq!(jwk.kid.as_deref(), Some("key-1"));
    let dbg = format!("{:?}", jwk);
    assert!(dbg.contains("EC"));
}

#[test]
fn ec_jwk_without_kid() {
    let jwk = EcJwk {
        kty: "EC".into(),
        crv: "P-384".into(),
        x: "x384".into(),
        y: "y384".into(),
        kid: None,
    };
    assert!(jwk.kid.is_none());
}

#[test]
fn ec_jwk_clone() {
    let jwk = EcJwk {
        kty: "EC".into(),
        crv: "P-521".into(),
        x: "x521".into(),
        y: "y521".into(),
        kid: Some("cloned-key".into()),
    };
    let cloned = jwk.clone();
    assert_eq!(cloned.crv, "P-521");
    assert_eq!(cloned.kid.as_deref(), Some("cloned-key"));
}

#[test]
fn rsa_jwk_creation_and_debug() {
    let jwk = RsaJwk {
        kty: "RSA".into(),
        n: "modulus".to_string(),
        e: "AQAB".to_string(),
        kid: Some("rsa-key".into()),
    };
    assert_eq!(jwk.kty, "RSA");
    assert_eq!(jwk.n, "modulus");
    assert_eq!(jwk.e, "AQAB");
    let dbg = format!("{:?}", jwk);
    assert!(dbg.contains("RSA"));
}

#[test]
fn rsa_jwk_without_kid() {
    let jwk = RsaJwk {
        kty: "RSA".into(),
        n: "n".to_string(),
        e: "e".to_string(),
        kid: None,
    };
    assert!(jwk.kid.is_none());
}

#[test]
fn rsa_jwk_clone() {
    let jwk = RsaJwk {
        kty: "RSA".into(),
        n: "big-modulus".to_string(),
        e: "AQAB".to_string(),
        kid: None,
    };
    let cloned = jwk.clone();
    assert_eq!(cloned.n, "big-modulus");
}

#[test]
fn pqc_jwk_creation_and_debug() {
    let jwk = PqcJwk {
        kty: "ML-DSA".into(),
        alg: "ML-DSA-44".to_string(),
        pub_key: "base64_pub".into(),
        kid: Some("pqc-1".into()),
    };
    assert_eq!(jwk.kty, "ML-DSA");
    assert_eq!(jwk.alg, "ML-DSA-44");
    let dbg = format!("{:?}", jwk);
    assert!(dbg.contains("ML-DSA"));
}

#[test]
fn pqc_jwk_clone() {
    let jwk = PqcJwk {
        kty: "ML-DSA".into(),
        alg: "ML-DSA-87".to_string(),
        pub_key: "key".into(),
        kid: None,
    };
    let cloned = jwk.clone();
    assert_eq!(cloned.alg, "ML-DSA-87");
}

// ============================================================================
// Jwk enum
// ============================================================================

#[test]
fn jwk_ec_variant() {
    let ec = EcJwk {
        kty: "EC".into(),
        crv: "P-256".into(),
        x: "x".into(),
        y: "y".into(),
        kid: None,
    };
    let jwk = Jwk::Ec(ec);
    let dbg = format!("{:?}", jwk);
    assert!(dbg.contains("Ec"));
}

#[test]
fn jwk_rsa_variant() {
    let rsa = RsaJwk {
        kty: "RSA".into(),
        n: "n".to_string(),
        e: "e".to_string(),
        kid: None,
    };
    let jwk = Jwk::Rsa(rsa);
    let dbg = format!("{:?}", jwk);
    assert!(dbg.contains("Rsa"));
}

#[test]
fn jwk_pqc_variant() {
    let pqc = PqcJwk {
        kty: "ML-DSA".into(),
        alg: "ML-DSA-65".to_string(),
        pub_key: "key".into(),
        kid: None,
    };
    let jwk = Jwk::Pqc(pqc);
    let dbg = format!("{:?}", jwk);
    assert!(dbg.contains("Pqc"));
}

#[test]
fn jwk_clone() {
    let ec = EcJwk {
        kty: "EC".into(),
        crv: "P-256".into(),
        x: "x".into(),
        y: "y".into(),
        kid: None,
    };
    let jwk = Jwk::Ec(ec);
    let cloned = jwk.clone();
    match cloned {
        Jwk::Ec(e) => assert_eq!(e.crv, "P-256"),
        _ => panic!("expected Ec variant"),
    }
}

// ============================================================================
// JwkVerifierFactory default implementations
// ============================================================================

/// Minimal implementation only providing EC JWK.
struct MinimalJwkFactory;

impl JwkVerifierFactory for MinimalJwkFactory {
    fn verifier_from_ec_jwk(
        &self,
        _jwk: &EcJwk<'_>,
        _cose_algorithm: i64,
    ) -> Result<Box<dyn CryptoVerifier>, CryptoError> {
        Err(CryptoError::UnsupportedOperation("test: not real".into()))
    }
}

#[test]
fn jwk_factory_rsa_default_returns_unsupported() {
    let factory = MinimalJwkFactory;
    let rsa = RsaJwk {
        kty: "RSA".into(),
        n: "n".to_string(),
        e: "e".to_string(),
        kid: None,
    };
    let result = factory.verifier_from_rsa_jwk(&rsa, -257);
    assert!(result.is_err());
    let err = result.err().unwrap();
    match err {
        CryptoError::UnsupportedOperation(msg) => {
            assert!(msg.contains("RSA JWK"));
        }
        other => panic!("expected UnsupportedOperation, got: {:?}", other),
    }
}

#[test]
fn jwk_factory_pqc_default_returns_unsupported() {
    let factory = MinimalJwkFactory;
    let pqc = PqcJwk {
        kty: "ML-DSA".into(),
        alg: "ML-DSA-44".to_string(),
        pub_key: "key".into(),
        kid: None,
    };
    let result = factory.verifier_from_pqc_jwk(&pqc, -48);
    assert!(result.is_err());
    let err = result.err().unwrap();
    match err {
        CryptoError::UnsupportedOperation(msg) => {
            assert!(msg.contains("PQC JWK"));
        }
        other => panic!("expected UnsupportedOperation, got: {:?}", other),
    }
}

#[test]
fn jwk_factory_verifier_from_jwk_dispatches_ec() {
    let factory = MinimalJwkFactory;
    let ec = EcJwk {
        kty: "EC".into(),
        crv: "P-256".into(),
        x: "x".into(),
        y: "y".into(),
        kid: None,
    };
    let jwk = Jwk::Ec(ec);
    let result = factory.verifier_from_jwk(&jwk, -7);
    // Should dispatch to verifier_from_ec_jwk which returns our test error
    assert!(result.is_err());
    let err = result.err().unwrap();
    match err {
        CryptoError::UnsupportedOperation(msg) => {
            assert!(msg.contains("test: not real"));
        }
        other => panic!("expected our test error, got: {:?}", other),
    }
}

#[test]
fn jwk_factory_verifier_from_jwk_dispatches_rsa() {
    let factory = MinimalJwkFactory;
    let rsa = RsaJwk {
        kty: "RSA".into(),
        n: "n".to_string(),
        e: "e".to_string(),
        kid: None,
    };
    let jwk = Jwk::Rsa(rsa);
    let result = factory.verifier_from_jwk(&jwk, -257);
    assert!(result.is_err());
    let err = result.err().unwrap();
    match err {
        CryptoError::UnsupportedOperation(msg) => {
            assert!(msg.contains("RSA JWK"));
        }
        other => panic!("expected RSA unsupported, got: {:?}", other),
    }
}

#[test]
fn jwk_factory_verifier_from_jwk_dispatches_pqc() {
    let factory = MinimalJwkFactory;
    let pqc = PqcJwk {
        kty: "ML-DSA".into(),
        alg: "ML-DSA-65".to_string(),
        pub_key: "key".into(),
        kid: None,
    };
    let jwk = Jwk::Pqc(pqc);
    let result = factory.verifier_from_jwk(&jwk, -49);
    assert!(result.is_err());
    let err = result.err().unwrap();
    match err {
        CryptoError::UnsupportedOperation(msg) => {
            assert!(msg.contains("PQC JWK"));
        }
        other => panic!("expected PQC unsupported, got: {:?}", other),
    }
}

// ============================================================================
// CryptoError Debug
// ============================================================================

#[test]
fn crypto_error_debug_signing_failed() {
    let err = CryptoError::SigningFailed("test".to_string());
    let dbg = format!("{:?}", err);
    assert!(dbg.contains("SigningFailed"));
    assert!(dbg.contains("test"));
}

#[test]
fn crypto_error_debug_verification_failed() {
    let err = CryptoError::VerificationFailed("bad".to_string());
    let dbg = format!("{:?}", err);
    assert!(dbg.contains("VerificationFailed"));
}

#[test]
fn crypto_error_debug_invalid_key() {
    let err = CryptoError::InvalidKey("corrupt".to_string());
    let dbg = format!("{:?}", err);
    assert!(dbg.contains("InvalidKey"));
}

#[test]
fn crypto_error_debug_unsupported_algorithm() {
    let err = CryptoError::UnsupportedAlgorithm(-999);
    let dbg = format!("{:?}", err);
    assert!(dbg.contains("UnsupportedAlgorithm"));
    assert!(dbg.contains("-999"));
}

#[test]
fn crypto_error_debug_unsupported_operation() {
    let err = CryptoError::UnsupportedOperation("nope".to_string());
    let dbg = format!("{:?}", err);
    assert!(dbg.contains("UnsupportedOperation"));
}

#[test]
fn crypto_error_is_std_error() {
    let err = CryptoError::SigningFailed("test".to_string());
    let std_err: &dyn std::error::Error = &err;
    assert!(!std_err.to_string().is_empty());
}

// ============================================================================
// CryptoSigner trait default: key_id() returns None
// ============================================================================

struct MinimalSigner;

impl CryptoSigner for MinimalSigner {
    fn sign(&self, _data: &[u8]) -> Result<Vec<u8>, CryptoError> {
        Ok(vec![0])
    }
    fn algorithm(&self) -> i64 {
        -7
    }
    fn key_type(&self) -> &str {
        "Test"
    }
}

#[test]
fn signer_default_key_id_is_none() {
    let signer = MinimalSigner;
    assert_eq!(signer.key_id(), None);
}

#[test]
fn signer_default_supports_streaming_is_false() {
    let signer = MinimalSigner;
    assert!(!signer.supports_streaming());
}

#[test]
fn signer_default_sign_init_returns_error() {
    let signer = MinimalSigner;
    let result = signer.sign_init();
    assert!(result.is_err());
}

// ============================================================================
// CryptoVerifier trait defaults
// ============================================================================

struct MinimalVerifier;

impl CryptoVerifier for MinimalVerifier {
    fn verify(&self, _data: &[u8], _signature: &[u8]) -> Result<bool, CryptoError> {
        Ok(true)
    }
    fn algorithm(&self) -> i64 {
        -7
    }
}

#[test]
fn verifier_default_supports_streaming_is_false() {
    let verifier = MinimalVerifier;
    assert!(!verifier.supports_streaming());
}

#[test]
fn verifier_default_verify_init_returns_error() {
    let verifier = MinimalVerifier;
    let result = verifier.verify_init(b"sig");
    assert!(result.is_err());
    let err = result.err().unwrap();
    match err {
        CryptoError::UnsupportedOperation(msg) => {
            assert!(msg.contains("streaming not supported"));
        }
        other => panic!("expected UnsupportedOperation, got: {:?}", other),
    }
}
