// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Cryptographic signing operations using OpenSSL.

use crate::ecdsa_format;
use crate::evp_key::{EvpPrivateKey, KeyType};
use crypto_primitives::{CryptoError, CryptoSigner, SigningContext};
use openssl::hash::MessageDigest;
use openssl::sign::Signer;

/// OpenSSL-backed cryptographic signer.
pub struct EvpSigner {
    key: EvpPrivateKey,
    cose_algorithm: i64,
    key_type: KeyType,
}

impl EvpSigner {
    /// Creates a new EvpSigner from a private key.
    ///
    /// # Arguments
    ///
    /// * `key` - The EVP private key
    /// * `cose_algorithm` - The COSE algorithm identifier
    pub fn new(key: EvpPrivateKey, cose_algorithm: i64) -> Result<Self, CryptoError> {
        let key_type = key.key_type();
        Ok(Self {
            key,
            cose_algorithm,
            key_type,
        })
    }

    /// Creates an EvpSigner from a DER-encoded private key.
    pub fn from_der(der: &[u8], cose_algorithm: i64) -> Result<Self, CryptoError> {
        let pkey = openssl::pkey::PKey::private_key_from_der(der)
            .map_err(|e| CryptoError::InvalidKey(format!("Failed to parse private key: {}", e)))?;
        let key = EvpPrivateKey::from_pkey(pkey).map_err(CryptoError::InvalidKey)?;
        Self::new(key, cose_algorithm)
    }

    /// Creates an EvpSigner from a PEM-encoded private key.
    pub fn from_pem(pem: &[u8], cose_algorithm: i64) -> Result<Self, CryptoError> {
        let pkey = openssl::pkey::PKey::private_key_from_pem(pem).map_err(|e| {
            CryptoError::InvalidKey(format!("Failed to parse PEM private key: {}", e))
        })?;
        let key = EvpPrivateKey::from_pkey(pkey).map_err(CryptoError::InvalidKey)?;
        Self::new(key, cose_algorithm)
    }
}

impl CryptoSigner for EvpSigner {
    fn sign(&self, data: &[u8]) -> Result<Vec<u8>, CryptoError> {
        sign_data(&self.key, self.cose_algorithm, data)
    }

    fn algorithm(&self) -> i64 {
        self.cose_algorithm
    }

    fn key_id(&self) -> Option<&[u8]> {
        None
    }

    fn key_type(&self) -> &str {
        match self.key_type {
            KeyType::Ec => "EC2",
            KeyType::Rsa => "RSA",
            KeyType::Ed25519 => "OKP",
            #[cfg(feature = "pqc")]
            KeyType::MlDsa(_) => "ML-DSA",
        }
    }

    fn supports_streaming(&self) -> bool {
        // ED25519 does not support streaming in OpenSSL (EVP_DigestSignUpdate not supported)
        !matches!(self.key_type, KeyType::Ed25519)
    }

    fn sign_init(&self) -> Result<Box<dyn SigningContext>, CryptoError> {
        Ok(Box::new(EvpSigningContext::new(
            &self.key,
            self.key_type,
            self.cose_algorithm,
        )?))
    }
}

/// Streaming signing context for OpenSSL.
pub struct EvpSigningContext {
    signer: Signer<'static>,
    key_type: KeyType,
    cose_algorithm: i64,
    // Keep key alive for 'static lifetime safety
    _key: Box<EvpPrivateKey>,
}

impl EvpSigningContext {
    fn new(
        key: &EvpPrivateKey,
        key_type: KeyType,
        cose_algorithm: i64,
    ) -> Result<Self, CryptoError> {
        // Clone the key to own it in the context
        let owned_key = Box::new(clone_private_key(key)?);

        // Create signer with the owned key's lifetime, then transmute to 'static
        // SAFETY: The key is owned by Self and will live as long as the Signer
        let signer = unsafe {
            let temp_signer = create_signer(&owned_key, cose_algorithm)?;
            std::mem::transmute::<Signer<'_>, Signer<'static>>(temp_signer)
        };

        Ok(Self {
            signer,
            key_type,
            cose_algorithm,
            _key: owned_key,
        })
    }
}

impl SigningContext for EvpSigningContext {
    fn update(&mut self, chunk: &[u8]) -> Result<(), CryptoError> {
        self.signer
            .update(chunk)
            .map_err(|e| CryptoError::SigningFailed(format!("Failed to update signer: {}", e)))
    }

    fn finalize(self: Box<Self>) -> Result<Vec<u8>, CryptoError> {
        let raw_sig = self.signer.sign_to_vec().map_err(|e| {
            CryptoError::SigningFailed(format!("Failed to finalize signature: {}", e))
        })?;

        // For ECDSA, convert DER to fixed-length format
        match self.key_type {
            KeyType::Ec => {
                let expected_len = match self.cose_algorithm {
                    -7 => 64,   // ES256
                    -35 => 96,  // ES384
                    -36 => 132, // ES512
                    _ => return Err(CryptoError::UnsupportedAlgorithm(self.cose_algorithm)),
                };
                ecdsa_format::der_to_fixed(&raw_sig, expected_len)
                    .map_err(CryptoError::SigningFailed)
            }
            _ => Ok(raw_sig), // RSA, Ed25519, ML-DSA: use raw signature
        }
    }
}

/// Clones a private key by serializing and deserializing.
fn clone_private_key(key: &EvpPrivateKey) -> Result<EvpPrivateKey, CryptoError> {
    let der = key
        .pkey()
        .private_key_to_der()
        .map_err(|e| CryptoError::InvalidKey(format!("Failed to serialize private key: {}", e)))?;

    let pkey = openssl::pkey::PKey::private_key_from_der(&der).map_err(|e| {
        CryptoError::InvalidKey(format!("Failed to deserialize private key: {}", e))
    })?;

    EvpPrivateKey::from_pkey(pkey).map_err(CryptoError::InvalidKey)
}

/// Creates a Signer for the given key and algorithm.
fn create_signer<'a>(key: &'a EvpPrivateKey, cose_alg: i64) -> Result<Signer<'a>, CryptoError> {
    match key.key_type() {
        KeyType::Ec | KeyType::Rsa => {
            let digest = get_digest_for_algorithm(cose_alg)?;
            let mut signer = Signer::new(digest, key.pkey()).map_err(|e| {
                CryptoError::SigningFailed(format!("Failed to create signer: {}", e))
            })?;

            // Set PSS padding for PS* algorithms
            if cose_alg == -37 || cose_alg == -38 || cose_alg == -39 {
                signer
                    .set_rsa_padding(openssl::rsa::Padding::PKCS1_PSS)
                    .map_err(|e| {
                        CryptoError::SigningFailed(format!("Failed to set PSS padding: {}", e))
                    })?;
                signer
                    .set_rsa_pss_saltlen(openssl::sign::RsaPssSaltlen::DIGEST_LENGTH)
                    .map_err(|e| {
                        CryptoError::SigningFailed(format!("Failed to set PSS salt length: {}", e))
                    })?;
            }

            Ok(signer)
        }
        KeyType::Ed25519 => Signer::new_without_digest(key.pkey()).map_err(|e| {
            CryptoError::SigningFailed(format!("Failed to create EdDSA signer: {}", e))
        }),
        #[cfg(feature = "pqc")]
        KeyType::MlDsa(_) => Signer::new_without_digest(key.pkey()).map_err(|e| {
            CryptoError::SigningFailed(format!("Failed to create ML-DSA signer: {}", e))
        }),
    }
}

/// Signs data using an EVP private key.
///
/// # Arguments
///
/// * `key` - The private key to sign with
/// * `cose_alg` - The COSE algorithm identifier
/// * `data` - The data to sign (typically the Sig_structure)
///
/// # Returns
///
/// The signature bytes in COSE format.
fn sign_data(key: &EvpPrivateKey, cose_alg: i64, data: &[u8]) -> Result<Vec<u8>, CryptoError> {
    match key.key_type() {
        KeyType::Ec => sign_ecdsa(key, cose_alg, data),
        KeyType::Rsa => sign_rsa(key, cose_alg, data),
        KeyType::Ed25519 => sign_eddsa(key, data),
        #[cfg(feature = "pqc")]
        KeyType::MlDsa(_) => sign_mldsa(key, data),
    }
}

/// Signs data using ECDSA.
fn sign_ecdsa(key: &EvpPrivateKey, cose_alg: i64, data: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let digest = get_digest_for_algorithm(cose_alg)?;

    let mut signer = Signer::new(digest, key.pkey())
        .map_err(|e| CryptoError::SigningFailed(format!("Failed to create ECDSA signer: {}", e)))?;

    let der_sig = signer
        .sign_oneshot_to_vec(data)
        .map_err(|e| CryptoError::SigningFailed(format!("ECDSA signing failed: {}", e)))?;

    // Convert DER signature to fixed-length COSE format
    let expected_len = match cose_alg {
        -7 => 64,   // ES256: 2 * 32 bytes
        -35 => 96,  // ES384: 2 * 48 bytes
        -36 => 132, // ES512: 2 * 66 bytes
        _ => return Err(CryptoError::UnsupportedAlgorithm(cose_alg)),
    };

    ecdsa_format::der_to_fixed(&der_sig, expected_len).map_err(CryptoError::SigningFailed)
}

/// Signs data using RSA.
fn sign_rsa(key: &EvpPrivateKey, cose_alg: i64, data: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let digest = get_digest_for_algorithm(cose_alg)?;

    let mut signer = Signer::new(digest, key.pkey())
        .map_err(|e| CryptoError::SigningFailed(format!("Failed to create RSA signer: {}", e)))?;

    // Set PSS padding for PS* algorithms
    if cose_alg == -37 || cose_alg == -38 || cose_alg == -39 {
        signer
            .set_rsa_padding(openssl::rsa::Padding::PKCS1_PSS)
            .map_err(|e| CryptoError::SigningFailed(format!("Failed to set PSS padding: {}", e)))?;
        signer
            .set_rsa_pss_saltlen(openssl::sign::RsaPssSaltlen::DIGEST_LENGTH)
            .map_err(|e| {
                CryptoError::SigningFailed(format!("Failed to set PSS salt length: {}", e))
            })?;
    }

    signer
        .sign_oneshot_to_vec(data)
        .map_err(|e| CryptoError::SigningFailed(format!("RSA signing failed: {}", e)))
}

/// Signs data using EdDSA (Ed25519).
fn sign_eddsa(key: &EvpPrivateKey, data: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let mut signer = Signer::new_without_digest(key.pkey())
        .map_err(|e| CryptoError::SigningFailed(format!("Failed to create EdDSA signer: {}", e)))?;

    signer
        .sign_oneshot_to_vec(data)
        .map_err(|e| CryptoError::SigningFailed(format!("EdDSA signing failed: {}", e)))
}

/// Signs data using ML-DSA.
#[cfg(feature = "pqc")]
fn sign_mldsa(key: &EvpPrivateKey, data: &[u8]) -> Result<Vec<u8>, CryptoError> {
    // ML-DSA is a pure signature scheme (no external digest), like Ed25519
    let mut signer = Signer::new_without_digest(key.pkey()).map_err(|e| {
        CryptoError::SigningFailed(format!("Failed to create ML-DSA signer: {}", e))
    })?;

    // ML-DSA signatures are raw bytes (no DER conversion needed)
    signer
        .sign_oneshot_to_vec(data)
        .map_err(|e| CryptoError::SigningFailed(format!("ML-DSA signing failed: {}", e)))
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
