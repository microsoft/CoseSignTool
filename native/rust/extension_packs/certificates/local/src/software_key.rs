// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Software-based key provider for in-memory key generation.

use crate::error::CertLocalError;
use crate::key_algorithm::KeyAlgorithm;
use crate::traits::{GeneratedKey, PrivateKeyProvider};
use rcgen::KeyPair;

/// In-memory software key provider for generating cryptographic keys.
///
/// This provider generates keys entirely in software without hardware
/// security module (HSM) or TPM integration. Suitable for testing,
/// development, and scenarios where software-based keys are acceptable.
///
/// Maps V2 C# `SoftwareKeyProvider`.
pub struct SoftwareKeyProvider;

impl SoftwareKeyProvider {
    /// Creates a new software key provider.
    pub fn new() -> Self {
        Self
    }
}

impl Default for SoftwareKeyProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl PrivateKeyProvider for SoftwareKeyProvider {
    fn name(&self) -> &str {
        "SoftwareKeyProvider"
    }

    fn supports_algorithm(&self, algorithm: KeyAlgorithm) -> bool {
        match algorithm {
            KeyAlgorithm::Rsa => false, // ring backend doesn't support RSA key generation
            KeyAlgorithm::Ecdsa => true,
            #[cfg(feature = "pqc")]
            KeyAlgorithm::MlDsa => false, // Not yet implemented
        }
    }

    fn generate_key(
        &self,
        algorithm: KeyAlgorithm,
        key_size: Option<u32>,
    ) -> Result<GeneratedKey, CertLocalError> {
        if !self.supports_algorithm(algorithm) {
            return Err(CertLocalError::UnsupportedAlgorithm(format!(
                "{:?} is not supported by SoftwareKeyProvider",
                algorithm
            )));
        }

        let size = key_size.unwrap_or_else(|| algorithm.default_key_size());

        // Use rcgen's key pair generation
        let key_pair = match algorithm {
            KeyAlgorithm::Rsa => {
                // ring backend doesn't support RSA key generation
                return Err(CertLocalError::UnsupportedAlgorithm(
                    "RSA key generation is not supported with ring backend".to_string(),
                ));
            }
            KeyAlgorithm::Ecdsa => {
                KeyPair::generate()
                    .map_err(|e| CertLocalError::KeyGenerationFailed(e.to_string()))?
            }
            #[cfg(feature = "pqc")]
            KeyAlgorithm::MlDsa => {
                return Err(CertLocalError::UnsupportedAlgorithm(
                    "ML-DSA is not yet implemented".to_string(),
                ));
            }
        };

        let private_key_der = key_pair.serialize_der();
        let public_key_der = key_pair.public_key_der().to_vec();

        Ok(GeneratedKey {
            private_key_der,
            public_key_der,
            algorithm,
            key_size: size,
        })
    }
}
