// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Cryptographic verification operations using OpenSSL.

use crate::ecdsa_format;
use crate::evp_key::{EvpPublicKey, KeyType};
use crypto_primitives::{CryptoError, CryptoVerifier, VerifyingContext};
use openssl::hash::MessageDigest;
use openssl::sign::Verifier;

/// OpenSSL-backed cryptographic verifier.
pub struct EvpVerifier {
    key: EvpPublicKey,
    cose_algorithm: i64,
    key_type: KeyType,
}

impl EvpVerifier {
    /// Creates a new EvpVerifier from a public key.
    ///
    /// # Arguments
    ///
    /// * `key` - The EVP public key
    /// * `cose_algorithm` - The COSE algorithm identifier
    pub fn new(key: EvpPublicKey, cose_algorithm: i64) -> Result<Self, CryptoError> {
        let key_type = key.key_type();
        Ok(Self {
            key,
            cose_algorithm,
            key_type,
        })
    }

    /// Creates an EvpVerifier from a DER-encoded public key.
    pub fn from_der(der: &[u8], cose_algorithm: i64) -> Result<Self, CryptoError> {
        let pkey = openssl::pkey::PKey::public_key_from_der(der)
            .map_err(|e| CryptoError::InvalidKey(format!("Failed to parse public key: {}", e)))?;
        let key = EvpPublicKey::from_pkey(pkey).map_err(CryptoError::InvalidKey)?;
        Self::new(key, cose_algorithm)
    }
}

impl CryptoVerifier for EvpVerifier {
    fn verify(&self, data: &[u8], signature: &[u8]) -> Result<bool, CryptoError> {
        verify_signature(&self.key, self.cose_algorithm, data, signature)
    }

    fn algorithm(&self) -> i64 {
        self.cose_algorithm
    }

    fn supports_streaming(&self) -> bool {
        // ED25519 does not support streaming in OpenSSL (EVP_DigestVerifyUpdate not supported)
        !matches!(self.key_type, KeyType::Ed25519)
    }

    fn verify_init(&self, signature: &[u8]) -> Result<Box<dyn VerifyingContext>, CryptoError> {
        Ok(Box::new(EvpVerifyingContext::new(
            &self.key,
            self.key_type,
            self.cose_algorithm,
            signature,
        )?))
    }
}

/// Streaming verification context for OpenSSL.
pub struct EvpVerifyingContext {
    verifier: Verifier<'static>,
    signature: Vec<u8>,
    // Keep key alive for 'static lifetime safety
    _key: Box<EvpPublicKey>,
}

impl EvpVerifyingContext {
    fn new(
        key: &EvpPublicKey,
        key_type: KeyType,
        cose_algorithm: i64,
        signature: &[u8],
    ) -> Result<Self, CryptoError> {
        // For ECDSA, convert fixed-length to DER format before verification
        let signature_for_verifier = match key_type {
            KeyType::Ec => ecdsa_format::fixed_to_der(signature).map_err(|e| {
                CryptoError::VerificationFailed(format!(
                    "ECDSA signature format conversion failed: {}",
                    e
                ))
            })?,
            _ => signature.to_vec(), // RSA, Ed25519, ML-DSA: use as-is
        };

        // Clone the key to own it in the context
        let owned_key = Box::new(clone_public_key(key)?);

        // Create verifier with the owned key's lifetime, then transmute to 'static
        // SAFETY: The key is owned by Self and will live as long as the Verifier
        let verifier = unsafe {
            let temp_verifier = create_verifier(&owned_key, cose_algorithm)?;
            std::mem::transmute::<Verifier<'_>, Verifier<'static>>(temp_verifier)
        };

        Ok(Self {
            verifier,
            signature: signature_for_verifier,
            _key: owned_key,
        })
    }
}

impl VerifyingContext for EvpVerifyingContext {
    fn update(&mut self, chunk: &[u8]) -> Result<(), CryptoError> {
        self.verifier.update(chunk).map_err(|e| {
            CryptoError::VerificationFailed(format!("Failed to update verifier: {}", e))
        })
    }

    fn finalize(self: Box<Self>) -> Result<bool, CryptoError> {
        self.verifier.verify(&self.signature).map_err(|e| {
            CryptoError::VerificationFailed(format!("Failed to finalize verification: {}", e))
        })
    }
}

/// Clones a public key by serializing and deserializing.
fn clone_public_key(key: &EvpPublicKey) -> Result<EvpPublicKey, CryptoError> {
    let der = key
        .pkey()
        .public_key_to_der()
        .map_err(|e| CryptoError::InvalidKey(format!("Failed to serialize public key: {}", e)))?;

    let pkey = openssl::pkey::PKey::public_key_from_der(&der)
        .map_err(|e| CryptoError::InvalidKey(format!("Failed to deserialize public key: {}", e)))?;

    EvpPublicKey::from_pkey(pkey).map_err(CryptoError::InvalidKey)
}

/// Creates a Verifier for the given key and algorithm.
fn create_verifier<'a>(key: &'a EvpPublicKey, cose_alg: i64) -> Result<Verifier<'a>, CryptoError> {
    match key.key_type() {
        KeyType::Ec | KeyType::Rsa => {
            let digest = get_digest_for_algorithm(cose_alg)?;
            let mut verifier = Verifier::new(digest, key.pkey()).map_err(|e| {
                CryptoError::VerificationFailed(format!("Failed to create verifier: {}", e))
            })?;

            // Set PSS padding for PS* algorithms
            if cose_alg == -37 || cose_alg == -38 || cose_alg == -39 {
                verifier
                    .set_rsa_padding(openssl::rsa::Padding::PKCS1_PSS)
                    .map_err(|e| {
                        CryptoError::VerificationFailed(format!("Failed to set PSS padding: {}", e))
                    })?;
                // AUTO recovers the actual salt length from the signature,
                // accepting any valid PSS salt length (DIGEST_LENGTH, MAX_LENGTH, etc.).
                verifier
                    .set_rsa_pss_saltlen(openssl::sign::RsaPssSaltlen::custom(-2))
                    .map_err(|e| {
                        CryptoError::VerificationFailed(format!(
                            "Failed to set PSS salt length: {}",
                            e
                        ))
                    })?;
            }

            Ok(verifier)
        }
        KeyType::Ed25519 => Verifier::new_without_digest(key.pkey()).map_err(|e| {
            CryptoError::VerificationFailed(format!("Failed to create EdDSA verifier: {}", e))
        }),
        #[cfg(feature = "pqc")]
        KeyType::MlDsa(_) => Verifier::new_without_digest(key.pkey()).map_err(|e| {
            CryptoError::VerificationFailed(format!("Failed to create ML-DSA verifier: {}", e))
        }),
    }
}

/// Verifies a signature using an EVP public key.
///
/// # Arguments
///
/// * `key` - The public key to verify with
/// * `cose_alg` - The COSE algorithm identifier
/// * `data` - The data that was signed (typically the Sig_structure)
/// * `signature` - The signature bytes to verify (in COSE format)
///
/// # Returns
///
/// `true` if the signature is valid, `false` otherwise.
fn verify_signature(
    key: &EvpPublicKey,
    cose_alg: i64,
    data: &[u8],
    signature: &[u8],
) -> Result<bool, CryptoError> {
    match key.key_type() {
        KeyType::Ec => verify_ecdsa(key, cose_alg, data, signature),
        KeyType::Rsa => verify_rsa(key, cose_alg, data, signature),
        KeyType::Ed25519 => verify_eddsa(key, data, signature),
        #[cfg(feature = "pqc")]
        KeyType::MlDsa(_) => verify_mldsa(key, data, signature),
    }
}

/// Verifies an ECDSA signature.
fn verify_ecdsa(
    key: &EvpPublicKey,
    cose_alg: i64,
    data: &[u8],
    signature: &[u8],
) -> Result<bool, CryptoError> {
    let digest = get_digest_for_algorithm(cose_alg)?;

    // Convert COSE fixed-length signature to DER format
    let der_sig = ecdsa_format::fixed_to_der(signature).map_err(|e| {
        CryptoError::VerificationFailed(format!("ECDSA signature format conversion failed: {}", e))
    })?;

    let mut verifier = Verifier::new(digest, key.pkey()).map_err(|e| {
        CryptoError::VerificationFailed(format!("Failed to create ECDSA verifier: {}", e))
    })?;

    verifier
        .verify_oneshot(&der_sig, data)
        .map_err(|e| CryptoError::VerificationFailed(format!("ECDSA verification failed: {}", e)))
}

/// Verifies an RSA signature.
fn verify_rsa(
    key: &EvpPublicKey,
    cose_alg: i64,
    data: &[u8],
    signature: &[u8],
) -> Result<bool, CryptoError> {
    let digest = get_digest_for_algorithm(cose_alg)?;

    let mut verifier = Verifier::new(digest, key.pkey()).map_err(|e| {
        CryptoError::VerificationFailed(format!("Failed to create RSA verifier: {}", e))
    })?;

    // Set PSS padding for PS* algorithms
    if cose_alg == -37 || cose_alg == -38 || cose_alg == -39 {
        verifier
            .set_rsa_padding(openssl::rsa::Padding::PKCS1_PSS)
            .map_err(|e| {
                CryptoError::VerificationFailed(format!("Failed to set PSS padding: {}", e))
            })?;
        // AUTO recovers the actual salt length from the signature.
        verifier
            .set_rsa_pss_saltlen(openssl::sign::RsaPssSaltlen::custom(-2))
            .map_err(|e| {
                CryptoError::VerificationFailed(format!("Failed to set PSS salt length: {}", e))
            })?;
    }

    verifier
        .verify_oneshot(signature, data)
        .map_err(|e| CryptoError::VerificationFailed(format!("RSA verification failed: {}", e)))
}

/// Verifies an EdDSA signature.
fn verify_eddsa(key: &EvpPublicKey, data: &[u8], signature: &[u8]) -> Result<bool, CryptoError> {
    let mut verifier = Verifier::new_without_digest(key.pkey()).map_err(|e| {
        CryptoError::VerificationFailed(format!("Failed to create EdDSA verifier: {}", e))
    })?;

    verifier
        .verify_oneshot(signature, data)
        .map_err(|e| CryptoError::VerificationFailed(format!("EdDSA verification failed: {}", e)))
}

/// Verifies an ML-DSA signature.
#[cfg(feature = "pqc")]
fn verify_mldsa(key: &EvpPublicKey, data: &[u8], signature: &[u8]) -> Result<bool, CryptoError> {
    // ML-DSA is a pure signature scheme (no external digest), like Ed25519
    let mut verifier = Verifier::new_without_digest(key.pkey()).map_err(|e| {
        CryptoError::VerificationFailed(format!("Failed to create ML-DSA verifier: {}", e))
    })?;

    // ML-DSA signatures are raw bytes (no DER conversion needed)
    verifier
        .verify_oneshot(signature, data)
        .map_err(|e| CryptoError::VerificationFailed(format!("ML-DSA verification failed: {}", e)))
}

/// Gets the message digest for a COSE algorithm.
fn get_digest_for_algorithm(cose_alg: i64) -> Result<MessageDigest, CryptoError> {
    match cose_alg {
        -7 | -257 | -37 => Ok(MessageDigest::sha256()), // ES256, RS256, PS256
        -35 | -258 | -38 => Ok(MessageDigest::sha384()), // ES384, RS384, PS384
        -36 | -259 | -39 => Ok(MessageDigest::sha512()), // ES512, RS512, PS512
        _ => Err(CryptoError::UnsupportedAlgorithm(cose_alg)),
    }
}
