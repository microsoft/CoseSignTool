// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! OpenSSL cryptographic provider for CoseSign1.

use crate::evp_signer::EvpSigner;
use crate::evp_verifier::EvpVerifier;
use crypto_primitives::{CryptoError, CryptoProvider, CryptoSigner, CryptoVerifier};

/// OpenSSL-based cryptographic provider.
///
/// This provider creates CryptoSigner and CryptoVerifier implementations
/// backed by OpenSSL's EVP API using safe Rust bindings from the `openssl` crate.
pub struct OpenSslCryptoProvider;

impl CryptoProvider for OpenSslCryptoProvider {
    fn signer_from_der(
        &self,
        private_key_der: &[u8],
    ) -> Result<Box<dyn CryptoSigner>, CryptoError> {
        // Parse DER to detect algorithm, default to ES256 for EC keys
        let pkey = openssl::pkey::PKey::private_key_from_der(private_key_der)
            .map_err(|e| CryptoError::InvalidKey(format!("Failed to parse private key: {}", e)))?;

        // Determine COSE algorithm based on key type
        let cose_algorithm = detect_algorithm_from_private_key(&pkey)?;

        let signer = EvpSigner::from_der(private_key_der, cose_algorithm)?;
        Ok(Box::new(signer))
    }

    fn verifier_from_der(
        &self,
        public_key_der: &[u8],
    ) -> Result<Box<dyn CryptoVerifier>, CryptoError> {
        // Parse DER to detect algorithm
        let pkey = openssl::pkey::PKey::public_key_from_der(public_key_der)
            .map_err(|e| CryptoError::InvalidKey(format!("Failed to parse public key: {}", e)))?;

        // Determine COSE algorithm based on key type
        let cose_algorithm = detect_algorithm_from_public_key(&pkey)?;

        let verifier = EvpVerifier::from_der(public_key_der, cose_algorithm)?;
        Ok(Box::new(verifier))
    }

    fn name(&self) -> &str {
        "OpenSSL"
    }
}

impl OpenSslCryptoProvider {
    /// Creates a signer from a PEM-encoded private key.
    ///
    /// Auto-detects the COSE algorithm from the key type (EC → ES256,
    /// RSA → RS256, Ed25519 → EdDSA).
    pub fn signer_from_pem(
        &self,
        private_key_pem: &[u8],
    ) -> Result<Box<dyn CryptoSigner>, CryptoError> {
        let pkey = openssl::pkey::PKey::private_key_from_pem(private_key_pem).map_err(|e| {
            CryptoError::InvalidKey(format!("Failed to parse PEM private key: {}", e))
        })?;

        let cose_algorithm = detect_algorithm_from_private_key(&pkey)?;
        let signer = EvpSigner::from_pem(private_key_pem, cose_algorithm)?;
        Ok(Box::new(signer))
    }

    /// Creates a verifier from a PEM-encoded public key.
    ///
    /// Auto-detects the COSE algorithm from the key type.
    pub fn verifier_from_pem(
        &self,
        public_key_pem: &[u8],
    ) -> Result<Box<dyn CryptoVerifier>, CryptoError> {
        let pkey = openssl::pkey::PKey::public_key_from_pem(public_key_pem).map_err(|e| {
            CryptoError::InvalidKey(format!("Failed to parse PEM public key: {}", e))
        })?;

        let cose_algorithm = detect_algorithm_from_public_key(&pkey)?;
        let verifier = EvpVerifier::from_pem(public_key_pem, cose_algorithm)?;
        Ok(Box::new(verifier))
    }
}

/// Detects the COSE algorithm from a private key.
fn detect_algorithm_from_private_key(
    pkey: &openssl::pkey::PKey<openssl::pkey::Private>,
) -> Result<i64, CryptoError> {
    use openssl::pkey::Id;

    match pkey.id() {
        Id::EC => {
            // Default to ES256 for EC keys
            // TODO: Detect curve and choose appropriate algorithm
            Ok(-7) // ES256
        }
        Id::RSA => {
            // Default to RS256 for RSA keys
            Ok(-257) // RS256
        }
        Id::ED25519 => {
            Ok(-8) // EdDSA
        }
        #[cfg(feature = "pqc")]
        _ => {
            // Try ML-DSA detection via EVP_PKEY_is_a
            use crate::evp_key::EvpPrivateKey;
            match EvpPrivateKey::from_pkey(pkey.clone()) {
                Ok(evp) => match evp.key_type() {
                    crate::evp_key::KeyType::MlDsa(variant) => Ok(variant.cose_algorithm()),
                    _ => Err(CryptoError::UnsupportedOperation(format!(
                        "Unsupported key type: {:?}",
                        pkey.id()
                    ))),
                },
                Err(_) => Err(CryptoError::UnsupportedOperation(format!(
                    "Unsupported key type: {:?}",
                    pkey.id()
                ))),
            }
        }
        #[cfg(not(feature = "pqc"))]
        _ => Err(CryptoError::UnsupportedOperation(format!(
            "Unsupported key type: {:?}",
            pkey.id()
        ))),
    }
}

/// Detects the COSE algorithm from a public key.
fn detect_algorithm_from_public_key(
    pkey: &openssl::pkey::PKey<openssl::pkey::Public>,
) -> Result<i64, CryptoError> {
    use openssl::pkey::Id;

    match pkey.id() {
        Id::EC => {
            // Default to ES256 for EC keys
            Ok(-7) // ES256
        }
        Id::RSA => {
            // Default to RS256 for RSA keys when algorithm not specified.
            // When used via x5chain resolution, the resolver overrides this
            // with the message's actual algorithm (PS256, RS384, etc.).
            Ok(-257) // RS256
        }
        Id::ED25519 => {
            Ok(-8) // EdDSA
        }
        #[cfg(feature = "pqc")]
        _ => {
            // Try ML-DSA detection via EVP_PKEY_is_a
            use crate::evp_key::EvpPublicKey;
            match EvpPublicKey::from_pkey(pkey.clone()) {
                Ok(evp) => match evp.key_type() {
                    crate::evp_key::KeyType::MlDsa(variant) => Ok(variant.cose_algorithm()),
                    _ => Err(CryptoError::UnsupportedOperation(format!(
                        "Unsupported key type: {:?}",
                        pkey.id()
                    ))),
                },
                Err(_) => Err(CryptoError::UnsupportedOperation(format!(
                    "Unsupported key type: {:?}",
                    pkey.id()
                ))),
            }
        }
        #[cfg(not(feature = "pqc"))]
        _ => Err(CryptoError::UnsupportedOperation(format!(
            "Unsupported key type: {:?}",
            pkey.id()
        ))),
    }
}
