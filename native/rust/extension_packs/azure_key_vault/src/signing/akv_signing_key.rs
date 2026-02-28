// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Azure Key Vault signing key implementation.
//!
//! Provides a COSE signing key backed by Azure Key Vault cryptographic operations.

use std::sync::{Arc, Mutex};

use crypto_primitives::{CryptoError, CryptoSigner};
use cose_sign1_signing::{CryptographicKeyType, SigningKeyMetadata, SigningServiceKey};

use crate::common::{AkvError, KeyVaultCryptoClient};

/// Maps EC curve names to COSE algorithm identifiers.
fn curve_to_cose_algorithm(curve: &str) -> Option<i64> {
    match curve {
        "P-256" => Some(-7),   // ES256
        "P-384" => Some(-35),  // ES384
        "P-521" => Some(-36),  // ES512
        _ => None,
    }
}

/// Maps key type and parameters to COSE algorithm identifiers.
fn determine_cose_algorithm(key_type: &str, curve: Option<&str>) -> Result<i64, AkvError> {
    match key_type {
        "EC" => {
            let curve_name = curve.ok_or_else(|| {
                AkvError::InvalidKeyType("EC key missing curve name".to_string())
            })?;
            curve_to_cose_algorithm(curve_name).ok_or_else(|| {
                AkvError::InvalidKeyType(format!("Unsupported EC curve: {}", curve_name))
            })
        }
        "RSA" => Ok(-37), // PS256 (RSA-PSS with SHA-256)
        _ => Err(AkvError::InvalidKeyType(format!(
            "Unsupported key type: {}",
            key_type
        ))),
    }
}

/// Maps COSE algorithm to Azure Key Vault signing algorithm name.
fn cose_algorithm_to_akv_algorithm(algorithm: i64) -> Result<&'static str, AkvError> {
    match algorithm {
        -7 => Ok("ES256"),   // ECDSA with SHA-256
        -35 => Ok("ES384"),  // ECDSA with SHA-384
        -36 => Ok("ES512"),  // ECDSA with SHA-512
        -37 => Ok("PS256"),  // RSA-PSS with SHA-256
        _ => Err(AkvError::InvalidKeyType(format!(
            "Unsupported COSE algorithm: {}",
            algorithm
        ))),
    }
}

/// Signing key backed by Azure Key Vault.
///
/// Maps V2's `AzureKeyVaultSigningKey` class.
pub struct AzureKeyVaultSigningKey {
    pub(crate) crypto_client: Arc<Box<dyn KeyVaultCryptoClient>>,
    pub(crate) algorithm: i64,
    pub(crate) metadata: SigningKeyMetadata,
    /// Cached COSE_Key bytes (lazily computed).
    pub(crate) cached_cose_key: Arc<Mutex<Option<Vec<u8>>>>,
}

impl AzureKeyVaultSigningKey {
    /// Creates a new AKV signing key.
    ///
    /// # Arguments
    ///
    /// * `crypto_client` - The AKV crypto client for signing operations
    pub fn new(crypto_client: Box<dyn KeyVaultCryptoClient>) -> Result<Self, AkvError> {
        let key_type = crypto_client.key_type();
        let curve = crypto_client.curve_name();
        let algorithm = determine_cose_algorithm(key_type, curve)?;

        let cryptographic_key_type = match key_type {
            "EC" => CryptographicKeyType::Ecdsa,
            "RSA" => CryptographicKeyType::Rsa,
            _ => CryptographicKeyType::Other,
        };

        let metadata = SigningKeyMetadata::new(
            Some(crypto_client.key_id().as_bytes().to_vec()),
            algorithm,
            cryptographic_key_type,
            true, // is_remote
        );

        Ok(Self {
            crypto_client: Arc::new(crypto_client),
            algorithm,
            metadata,
            cached_cose_key: Arc::new(Mutex::new(None)),
        })
    }

    /// Returns a reference to the crypto client.
    pub fn crypto_client(&self) -> &dyn KeyVaultCryptoClient {
        &**self.crypto_client
    }

    /// Builds a COSE_Key representation of the public key.
    ///
    /// Uses double-checked locking for caching (matches V2 pattern).
    pub fn get_cose_key_bytes(&self) -> Result<Vec<u8>, AkvError> {
        // First check without locking (fast path)
        {
            let guard = self.cached_cose_key.lock().unwrap();
            if let Some(ref cached) = *guard {
                return Ok(cached.clone());
            }
        }

        // Compute and cache (slow path)
        let mut guard = self.cached_cose_key.lock().unwrap();
        // Double-check: another thread might have computed it
        if let Some(ref cached) = *guard {
            return Ok(cached.clone());
        }

        // Build COSE_Key map
        let cose_key_bytes = self.build_cose_key_cbor()?;
        *guard = Some(cose_key_bytes.clone());
        Ok(cose_key_bytes)
    }

    /// Builds the CBOR-encoded COSE_Key map.
    fn build_cose_key_cbor(&self) -> Result<Vec<u8>, AkvError> {
        // This is a simplified version. A full implementation would need to:
        // 1. Extract public key parameters from the crypto client
        // 2. Build a proper COSE_Key map with kty, alg, crv, x, y (for EC) or n, e (for RSA)
        // 3. Encode to CBOR
        //
        // For now, we return the public key bytes as-is (which is not a valid COSE_Key).
        // TODO: Implement full COSE_Key encoding with cbor_primitives
        self.crypto_client.public_key_bytes()
    }
}

impl CryptoSigner for AzureKeyVaultSigningKey {
    fn sign(&self, data: &[u8]) -> Result<Vec<u8>, CryptoError> {
        // data is the Sig_structure bytes
        // Hash the sig_structure according to the algorithm
        let digest = self.hash_sig_structure(data)?;

        // Sign with AKV
        let akv_algorithm = cose_algorithm_to_akv_algorithm(self.algorithm)
            .map_err(|e| CryptoError::SigningFailed(e.to_string()))?;

        self.crypto_client
            .sign(akv_algorithm, &digest)
            .map_err(|e| CryptoError::SigningFailed(format!("AKV signing failed: {}", e)))
    }

    fn algorithm(&self) -> i64 {
        self.algorithm
    }

    fn key_id(&self) -> Option<&[u8]> {
        Some(self.crypto_client.key_id().as_bytes())
    }

    fn key_type(&self) -> &str {
        self.crypto_client.key_type()
    }

    fn supports_streaming(&self) -> bool {
        // AKV is remote, one-shot only
        false
    }
}

impl SigningServiceKey for AzureKeyVaultSigningKey {
    fn metadata(&self) -> &SigningKeyMetadata {
        &self.metadata
    }
}

impl AzureKeyVaultSigningKey {
    /// Hashes the sig_structure according to the key's algorithm.
    fn hash_sig_structure(&self, sig_structure: &[u8]) -> Result<Vec<u8>, CryptoError> {
        use ring::digest;

        let digest_algorithm = match self.algorithm {
            -7 | -37 => &digest::SHA256,  // ES256, PS256
            -35 => &digest::SHA384,       // ES384
            -36 => &digest::SHA512,       // ES512
            _ => {
                return Err(CryptoError::UnsupportedOperation(format!(
                    "Unsupported algorithm for hashing: {}",
                    self.algorithm
                )))
            }
        };

        let hash = digest::digest(digest_algorithm, sig_structure);
        Ok(hash.as_ref().to_vec())
    }
}

impl Clone for AzureKeyVaultSigningKey {
    fn clone(&self) -> Self {
        Self {
            crypto_client: Arc::clone(&self.crypto_client),
            algorithm: self.algorithm,
            metadata: self.metadata.clone(),
            cached_cose_key: Arc::clone(&self.cached_cose_key),
        }
    }
}
