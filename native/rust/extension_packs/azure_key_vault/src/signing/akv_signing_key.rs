// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Azure Key Vault signing key implementation.
//!
//! Provides a COSE signing key backed by Azure Key Vault cryptographic operations.

use std::sync::{Arc, Mutex};

use cose_sign1_signing::{CryptographicKeyType, SigningKeyMetadata, SigningServiceKey};
use crypto_primitives::{CryptoError, CryptoSigner};

use crate::common::{AkvError, KeyVaultCryptoClient};

/// Maps EC curve names to COSE algorithm identifiers.
fn curve_to_cose_algorithm(curve: &str) -> Option<i64> {
    match curve {
        "P-256" => Some(-7),  // ES256
        "P-384" => Some(-35), // ES384
        "P-521" => Some(-36), // ES512
        _ => None,
    }
}

/// Maps key type and parameters to COSE algorithm identifiers.
fn determine_cose_algorithm(key_type: &str, curve: Option<&str>) -> Result<i64, AkvError> {
    match key_type {
        "EC" => {
            let curve_name = curve
                .ok_or_else(|| AkvError::InvalidKeyType("EC key missing curve name".to_string()))?;
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
        -7 => Ok("ES256"),  // ECDSA with SHA-256
        -35 => Ok("ES384"), // ECDSA with SHA-384
        -36 => Ok("ES512"), // ECDSA with SHA-512
        -37 => Ok("PS256"), // RSA-PSS with SHA-256
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
    ///
    /// For EC keys: `{1: 2(EC2), 3: alg, -1: crv, -2: x, -3: y}`
    /// For RSA keys: `{1: 3(RSA), 3: alg, -1: n, -2: e}`
    fn build_cose_key_cbor(&self) -> Result<Vec<u8>, AkvError> {
        use cbor_primitives::{CborEncoder, CborProvider};

        let provider = cose_sign1_primitives::provider::cbor_provider();
        let mut encoder = provider.encoder();

        let key_type = self.crypto_client.key_type();
        let public_key = self
            .crypto_client
            .public_key_bytes()
            .map_err(|e| AkvError::General(format!("failed to get public key: {}", e)))?;

        match key_type {
            "EC" => {
                // EC uncompressed point: 0x04 || x || y
                if public_key.is_empty() || public_key[0] != 0x04 {
                    return Err(AkvError::General("invalid EC public key format".into()));
                }
                let coord_len = (public_key.len() - 1) / 2;
                let x = &public_key[1..1 + coord_len];
                let y = &public_key[1 + coord_len..];

                let crv = match self.algorithm {
                    -7 => 1,  // P-256
                    -35 => 2, // P-384
                    -36 => 3, // P-521
                    _ => 1,   // default P-256
                };

                encoder
                    .encode_map(5)
                    .map_err(|e| AkvError::General(e.to_string()))?;
                encoder
                    .encode_i64(1)
                    .map_err(|e| AkvError::General(e.to_string()))?; // kty
                encoder
                    .encode_i64(2)
                    .map_err(|e| AkvError::General(e.to_string()))?; // EC2
                encoder
                    .encode_i64(3)
                    .map_err(|e| AkvError::General(e.to_string()))?; // alg
                encoder
                    .encode_i64(self.algorithm)
                    .map_err(|e| AkvError::General(e.to_string()))?;
                encoder
                    .encode_i64(-1)
                    .map_err(|e| AkvError::General(e.to_string()))?; // crv
                encoder
                    .encode_i64(crv)
                    .map_err(|e| AkvError::General(e.to_string()))?;
                encoder
                    .encode_i64(-2)
                    .map_err(|e| AkvError::General(e.to_string()))?; // x
                encoder
                    .encode_bstr(x)
                    .map_err(|e| AkvError::General(e.to_string()))?;
                encoder
                    .encode_i64(-3)
                    .map_err(|e| AkvError::General(e.to_string()))?; // y
                encoder
                    .encode_bstr(y)
                    .map_err(|e| AkvError::General(e.to_string()))?;
            }
            "RSA" => {
                // RSA: public_key = n || e (from public_key_bytes impl)
                // For COSE_Key, we need separate n and e
                // n is typically 256 bytes (2048-bit) or 512 bytes (4096-bit)
                // e is typically 3 bytes (65537)
                // Heuristic: last 3 bytes are e if they decode to 65537
                let rsa_e_len = 3; // standard RSA public exponent length
                if public_key.len() <= rsa_e_len {
                    return Err(AkvError::General("RSA public key too short".into()));
                }
                let n = &public_key[..public_key.len() - rsa_e_len];
                let e = &public_key[public_key.len() - rsa_e_len..];

                encoder
                    .encode_map(4)
                    .map_err(|e| AkvError::General(e.to_string()))?;
                encoder
                    .encode_i64(1)
                    .map_err(|e| AkvError::General(e.to_string()))?; // kty
                encoder
                    .encode_i64(3)
                    .map_err(|e| AkvError::General(e.to_string()))?; // RSA
                encoder
                    .encode_i64(3)
                    .map_err(|e| AkvError::General(e.to_string()))?; // alg
                encoder
                    .encode_i64(self.algorithm)
                    .map_err(|e| AkvError::General(e.to_string()))?;
                encoder
                    .encode_i64(-1)
                    .map_err(|e| AkvError::General(e.to_string()))?; // n
                encoder
                    .encode_bstr(n)
                    .map_err(|e| AkvError::General(e.to_string()))?;
                encoder
                    .encode_i64(-2)
                    .map_err(|e| AkvError::General(e.to_string()))?; // e
                encoder
                    .encode_bstr(e)
                    .map_err(|e| AkvError::General(e.to_string()))?;
            }
            _ => {
                return Err(AkvError::InvalidKeyType(format!(
                    "cannot build COSE_Key for key type: {}",
                    key_type
                )));
            }
        }

        Ok(encoder.into_bytes())
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
        use sha2::Digest;

        match self.algorithm {
            -7 | -37 => Ok(sha2::Sha256::digest(sig_structure).to_vec()), // ES256, PS256
            -35 => Ok(sha2::Sha384::digest(sig_structure).to_vec()),      // ES384
            -36 => Ok(sha2::Sha512::digest(sig_structure).to_vec()),      // ES512
            _ => Err(CryptoError::UnsupportedOperation(format!(
                "Unsupported algorithm for hashing: {}",
                self.algorithm
            ))),
        }
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
