// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Software-based key provider for in-memory key generation.

use crate::error::CertLocalError;
use crate::key_algorithm::KeyAlgorithm;
use crate::traits::{GeneratedKey, PrivateKeyProvider};
use openssl::ec::{EcGroup, EcKey};
use openssl::nid::Nid;
use openssl::pkey::PKey;

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

    fn supports_algorithm(&self, _algorithm: KeyAlgorithm) -> bool {
        match _algorithm {
            KeyAlgorithm::Rsa => true,
            KeyAlgorithm::Ecdsa => true,
            #[cfg(feature = "pqc")]
            KeyAlgorithm::MlDsa => true,
        }
    }

    fn generate_key(
        &self,
        algorithm: KeyAlgorithm,
        key_size: Option<u32>,
    ) -> Result<GeneratedKey, CertLocalError> {
        let size = key_size.unwrap_or_else(|| algorithm.default_key_size());

        match algorithm {
            KeyAlgorithm::Rsa => {
                let rsa = openssl::rsa::Rsa::generate(size)
                    .map_err(|e| CertLocalError::KeyGenerationFailed(e.to_string()))?;
                let pkey = PKey::from_rsa(rsa)
                    .map_err(|e| CertLocalError::KeyGenerationFailed(e.to_string()))?;
                let private_key_der = pkey
                    .private_key_to_der()
                    .map_err(|e| CertLocalError::KeyGenerationFailed(e.to_string()))?;
                let public_key_der = pkey
                    .public_key_to_der()
                    .map_err(|e| CertLocalError::KeyGenerationFailed(e.to_string()))?;

                Ok(GeneratedKey {
                    private_key_der,
                    public_key_der,
                    algorithm,
                    key_size: size,
                })
            }
            KeyAlgorithm::Ecdsa => {
                let nid = match size {
                    384 => Nid::SECP384R1,
                    521 => Nid::SECP521R1,
                    _ => Nid::X9_62_PRIME256V1,
                };
                let group = EcGroup::from_curve_name(nid)
                    .map_err(|e| CertLocalError::KeyGenerationFailed(e.to_string()))?;
                let ec_key = EcKey::generate(&group)
                    .map_err(|e| CertLocalError::KeyGenerationFailed(e.to_string()))?;
                let pkey = PKey::from_ec_key(ec_key)
                    .map_err(|e| CertLocalError::KeyGenerationFailed(e.to_string()))?;
                let private_key_der = pkey
                    .private_key_to_der()
                    .map_err(|e| CertLocalError::KeyGenerationFailed(e.to_string()))?;
                let public_key_der = pkey
                    .public_key_to_der()
                    .map_err(|e| CertLocalError::KeyGenerationFailed(e.to_string()))?;

                Ok(GeneratedKey {
                    private_key_der,
                    public_key_der,
                    algorithm,
                    key_size: size,
                })
            }
            #[cfg(feature = "pqc")]
            KeyAlgorithm::MlDsa => {
                use cose_sign1_crypto_openssl::{generate_mldsa_key_der, MlDsaVariant};

                // Map key_size parameter to ML-DSA variant:
                // 44 -> ML-DSA-44, 65 -> ML-DSA-65 (default), 87 -> ML-DSA-87
                let variant = match size {
                    44 => MlDsaVariant::MlDsa44,
                    87 => MlDsaVariant::MlDsa87,
                    _ => MlDsaVariant::MlDsa65, // default
                };

                let (private_key_der, public_key_der) =
                    generate_mldsa_key_der(variant).map_err(CertLocalError::KeyGenerationFailed)?;

                Ok(GeneratedKey {
                    private_key_der,
                    public_key_der,
                    algorithm,
                    key_size: size,
                })
            }
        }
    }
}
