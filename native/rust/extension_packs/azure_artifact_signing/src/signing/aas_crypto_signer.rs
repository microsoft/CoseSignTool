// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use crate::signing::certificate_source::AzureArtifactSigningCertificateSource;
use crypto_primitives::{CryptoError, CryptoSigner};
use std::sync::Arc;

pub struct AasCryptoSigner {
    source: Arc<AzureArtifactSigningCertificateSource>,
    algorithm_name: String,
    algorithm_id: i64,
    key_type: String,
}

impl AasCryptoSigner {
    pub fn new(
        source: Arc<AzureArtifactSigningCertificateSource>,
        algorithm_name: String,
        algorithm_id: i64,
        key_type: String,
    ) -> Self {
        Self {
            source,
            algorithm_name,
            algorithm_id,
            key_type,
        }
    }
}

impl CryptoSigner for AasCryptoSigner {
    fn sign(&self, data: &[u8]) -> Result<Vec<u8>, CryptoError> {
        // COSE sign expects us to sign the Sig_structure bytes.
        // AAS expects a pre-computed digest. Hash here based on algorithm.
        use sha2::Digest;

        // Keep digests on the stack as fixed-size arrays instead of heap-allocating
        // via to_vec(). sign_digest accepts &[u8], so we pass a slice reference.
        let (signature, _cert_der) = match self.algorithm_name.as_str() {
            "RS256" | "PS256" | "ES256" => {
                let digest = sha2::Sha256::digest(data);
                self.source
                    .sign_digest(&self.algorithm_name, digest.as_slice())
            }
            "RS384" | "PS384" | "ES384" => {
                let digest = sha2::Sha384::digest(data);
                self.source
                    .sign_digest(&self.algorithm_name, digest.as_slice())
            }
            "RS512" | "PS512" | "ES512" => {
                let digest = sha2::Sha512::digest(data);
                self.source
                    .sign_digest(&self.algorithm_name, digest.as_slice())
            }
            _ => {
                let digest = sha2::Sha256::digest(data);
                self.source
                    .sign_digest(&self.algorithm_name, digest.as_slice())
            }
        }
        .map_err(|e| CryptoError::SigningFailed(e.to_string()))?;

        Ok(signature)
    }

    fn algorithm(&self) -> i64 {
        self.algorithm_id
    }
    fn key_type(&self) -> &str {
        &self.key_type
    }
}
