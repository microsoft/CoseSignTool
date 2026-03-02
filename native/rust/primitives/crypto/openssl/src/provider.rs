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
    fn signer_from_der(&self, private_key_der: &[u8]) -> Result<Box<dyn CryptoSigner>, CryptoError> {
        // Parse DER to detect algorithm, default to ES256 for EC keys
        let pkey = openssl::pkey::PKey::private_key_from_der(private_key_der)
            .map_err(|e| CryptoError::InvalidKey(format!("Failed to parse private key: {}", e)))?;
        
        // Determine COSE algorithm based on key type
        let cose_algorithm = detect_algorithm_from_private_key(&pkey)?;
        
        let signer = EvpSigner::from_der(private_key_der, cose_algorithm)?;
        Ok(Box::new(signer))
    }

    fn verifier_from_der(&self, public_key_der: &[u8]) -> Result<Box<dyn CryptoVerifier>, CryptoError> {
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

/// Detects the COSE algorithm from a private key.
fn detect_algorithm_from_private_key(pkey: &openssl::pkey::PKey<openssl::pkey::Private>) -> Result<i64, CryptoError> {
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
            // Try ML-DSA detection
            if is_mldsa_key(pkey) {
                Ok(-48) // ML-DSA-44 (default)
            } else {
                Err(CryptoError::UnsupportedOperation(format!("Unsupported key type: {:?}", pkey.id())))
            }
        }
        #[cfg(not(feature = "pqc"))]
        _ => Err(CryptoError::UnsupportedOperation(format!("Unsupported key type: {:?}", pkey.id()))),
    }
}

/// Detects the COSE algorithm from a public key.
fn detect_algorithm_from_public_key(pkey: &openssl::pkey::PKey<openssl::pkey::Public>) -> Result<i64, CryptoError> {
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
            // Try ML-DSA detection
            if is_mldsa_key_public(pkey) {
                Ok(-48) // ML-DSA-44 (default)
            } else {
                Err(CryptoError::UnsupportedOperation(format!("Unsupported key type: {:?}", pkey.id())))
            }
        }
        #[cfg(not(feature = "pqc"))]
        _ => Err(CryptoError::UnsupportedOperation(format!("Unsupported key type: {:?}", pkey.id()))),
    }
}

#[cfg(feature = "pqc")]
fn is_mldsa_key<T>(_pkey: &openssl::pkey::PKey<T>) -> bool {
    // Simplified detection - in production, use EVP_PKEY_is_a
    false
}

#[cfg(feature = "pqc")]
fn is_mldsa_key_public(_pkey: &openssl::pkey::PKey<openssl::pkey::Public>) -> bool {
    false
}
