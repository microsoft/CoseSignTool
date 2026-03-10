// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Concrete implementation of KeyVaultCryptoClient using the Azure SDK.

use super::crypto_client::KeyVaultCryptoClient;
use super::error::AkvError;
use azure_security_keyvault_keys::{
    KeyClient,
    models::{SignParameters, SignatureAlgorithm, KeyClientSignOptions, KeyClientGetKeyOptions},
};
use azure_identity::DeveloperToolsCredential;
use std::sync::Arc;

/// Concrete AKV crypto client wrapping `azure_security_keyvault_keys::KeyClient`.
pub struct AkvKeyClient {
    client: KeyClient,
    key_name: String,
    key_version: Option<String>,
    key_type: String,
    key_size: Option<usize>,
    curve_name: Option<String>,
    key_id: String,
    is_hsm: bool,
    runtime: tokio::runtime::Runtime,
}

impl AkvKeyClient {
    /// Create from vault URL + key name + credential.
    /// This fetches key metadata to determine type/curve.
    pub fn new(
        vault_url: &str,
        key_name: &str,
        key_version: Option<&str>,
        credential: Arc<dyn azure_core::credentials::TokenCredential>,
    ) -> Result<Self, AkvError> {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|e| AkvError::General(e.to_string()))?;

        let client = KeyClient::new(vault_url, credential, None)
            .map_err(|e| AkvError::General(e.to_string()))?;

        // Fetch key metadata to determine type, curve, etc.
        let key_response = runtime.block_on(async {
            let opts = key_version.map(|v| KeyClientGetKeyOptions {
                key_version: Some(v.to_string()),
                ..Default::default()
            });
            client.get_key(key_name, opts).await
        }).map_err(|e| AkvError::KeyNotFound(e.to_string()))?
          .into_model()
          .map_err(|e| AkvError::General(e.to_string()))?;

        let jwk = key_response.key.as_ref()
            .ok_or_else(|| AkvError::InvalidKeyType("no key material in response".into()))?;

        let key_type = jwk.kty.as_ref()
            .map(|t| format!("{:?}", t))
            .unwrap_or_default();
        let curve_name = jwk.crv.as_ref().map(|c| format!("{:?}", c));
        let key_id = key_response.key.as_ref()
            .and_then(|k| k.kid.clone())
            .unwrap_or_else(|| format!("{}/keys/{}", vault_url, key_name));

        Ok(Self {
            client,
            key_name: key_name.to_string(),
            key_version: key_version.map(|s| s.to_string()),
            key_type,
            key_size: None, // TODO: extract from JWK n/e for RSA
            curve_name,
            key_id,
            is_hsm: vault_url.contains("managedhsm"),
            runtime,
        })
    }

    /// Create with DeveloperToolsCredential (for local dev).
    pub fn new_dev(vault_url: &str, key_name: &str, key_version: Option<&str>) -> Result<Self, AkvError> {
        let credential = DeveloperToolsCredential::new(None)
            .map_err(|e| AkvError::AuthenticationFailed(e.to_string()))?;
        Self::new(vault_url, key_name, key_version, credential)
    }

    fn map_algorithm(&self, algorithm: &str) -> Result<SignatureAlgorithm, AkvError> {
        match algorithm {
            "ES256" => Ok(SignatureAlgorithm::Es256),
            "ES384" => Ok(SignatureAlgorithm::Es384),
            "ES512" => Ok(SignatureAlgorithm::Es512),
            "PS256" => Ok(SignatureAlgorithm::Ps256),
            "PS384" => Ok(SignatureAlgorithm::Ps384),
            "PS512" => Ok(SignatureAlgorithm::Ps512),
            "RS256" => Ok(SignatureAlgorithm::Rs256),
            "RS384" => Ok(SignatureAlgorithm::Rs384),
            "RS512" => Ok(SignatureAlgorithm::Rs512),
            _ => Err(AkvError::InvalidKeyType(format!("unsupported algorithm: {}", algorithm))),
        }
    }
}

impl KeyVaultCryptoClient for AkvKeyClient {
    fn sign(&self, algorithm: &str, digest: &[u8]) -> Result<Vec<u8>, AkvError> {
        let sig_alg = self.map_algorithm(algorithm)?;
        let params = SignParameters {
            algorithm: Some(sig_alg),
            value: Some(digest.to_vec()),
            ..Default::default()
        };
        let opts = self.key_version.as_ref().map(|v| KeyClientSignOptions {
            key_version: Some(v.clone()),
            ..Default::default()
        });
        let result = self.runtime.block_on(async {
            self.client.sign(&self.key_name, params.try_into()?, opts).await
        }).map_err(|e| AkvError::CryptoOperationFailed(e.to_string()))?
          .into_model()
          .map_err(|e| AkvError::CryptoOperationFailed(e.to_string()))?;

        result.result.ok_or_else(|| AkvError::CryptoOperationFailed("no signature in response".into()))
    }

    fn key_id(&self) -> &str { &self.key_id }
    fn key_type(&self) -> &str { &self.key_type }
    fn key_size(&self) -> Option<usize> { self.key_size }
    fn curve_name(&self) -> Option<&str> { self.curve_name.as_deref() }
    fn public_key_bytes(&self) -> Result<Vec<u8>, AkvError> {
        Err(AkvError::General("public_key_bytes not yet implemented for SDK client".into()))
    }
    fn name(&self) -> &str { &self.key_name }
    fn version(&self) -> &str { self.key_version.as_deref().unwrap_or("") }
    fn is_hsm_protected(&self) -> bool { self.is_hsm }
}
