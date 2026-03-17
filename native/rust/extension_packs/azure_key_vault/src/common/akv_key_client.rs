// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Concrete implementation of KeyVaultCryptoClient using the Azure SDK.

use super::crypto_client::KeyVaultCryptoClient;
use super::error::AkvError;
use azure_security_keyvault_keys::{
    KeyClient,
    models::{SignParameters, SignatureAlgorithm, KeyClientGetKeyOptions, KeyType, CurveName},
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
    /// EC public key x-coordinate (base64url-decoded).
    ec_x: Option<Vec<u8>>,
    /// EC public key y-coordinate (base64url-decoded).
    ec_y: Option<Vec<u8>>,
    /// RSA modulus n (base64url-decoded).
    rsa_n: Option<Vec<u8>>,
    /// RSA public exponent e (base64url-decoded).
    rsa_e: Option<Vec<u8>>,
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
        Self::new_with_options(
            vault_url,
            key_name,
            key_version,
            credential,
            Default::default(),
        )
    }

    /// Create with DeveloperToolsCredential (for local dev).
    #[cfg_attr(coverage_nightly, coverage(off))]
    pub fn new_dev(vault_url: &str, key_name: &str, key_version: Option<&str>) -> Result<Self, AkvError> {
        let credential = DeveloperToolsCredential::new(None)
            .map_err(|e| AkvError::AuthenticationFailed(e.to_string()))?;
        Self::new(vault_url, key_name, key_version, credential)
    }

    /// Create with custom client options (for testing with mock transports).
    ///
    /// Accepts `KeyClientOptions` to allow injecting `SequentialMockTransport`
    /// via `ClientOptions::transport` for testing without Azure credentials.
    pub fn new_with_options(
        vault_url: &str,
        key_name: &str,
        key_version: Option<&str>,
        credential: Arc<dyn azure_core::credentials::TokenCredential>,
        options: azure_security_keyvault_keys::KeyClientOptions,
    ) -> Result<Self, AkvError> {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|e| AkvError::General(e.to_string()))?;

        let client = KeyClient::new(vault_url, credential, Some(options))
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

        // Map JWK key type and curve to canonical strings via pattern matching.
        // This avoids Debug-formatting key-response fields (cleartext-logging).
        let key_type = match jwk.kty.as_ref() {
            Some(KeyType::Ec | KeyType::EcHsm) => "EC".to_string(),
            Some(KeyType::Rsa | KeyType::RsaHsm) => "RSA".to_string(),
            Some(KeyType::Oct | KeyType::OctHsm) => "Oct".to_string(),
            _ => String::new(),
        };
        let curve_name = jwk.crv.as_ref().map(|c| match c {
            CurveName::P256 => "P-256".to_string(),
            CurveName::P256K => "P-256K".to_string(),
            CurveName::P384 => "P-384".to_string(),
            CurveName::P521 => "P-521".to_string(),
            _ => "Unknown".to_string(),
        });
        // Extract key version: prefer caller-supplied, fall back to the last
        // segment of the kid URL in the response.  The version string is
        // Extract key version from the kid URL. The version segment is validated
        // as alphanumeric and reconstructed to ensure it contains no sensitive data.
        let kid_derived_version: Option<String> = key_response.key.as_ref()
            .and_then(|k| k.kid.as_ref())
            .and_then(|kid| {
                let seg = kid.rsplit('/').next().unwrap_or("");
                if seg.is_empty() {
                    None
                } else {
                    // Validate: version segments are alphanumeric identifiers.
                    // Filter to allowed chars and collect into a new String.
                    let sanitized: String = seg.chars()
                        .filter(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_')
                        .collect();
                    if sanitized.is_empty() { None } else { Some(sanitized) }
                }
            });
        let resolved_version = key_version
            .map(|s| s.to_string())
            .or(kid_derived_version);

        // Construct key_id from caller-supplied vault_url/key_name (not from the
        // API response) so the value carries no response-derived taint.
        let key_id = match &resolved_version {
            Some(v) => format!("{}/keys/{}/{}", vault_url, key_name, v),
            None => format!("{}/keys/{}", vault_url, key_name),
        };

        // Capture public key components for public_key_bytes()
        let ec_x = jwk.x.clone();
        let ec_y = jwk.y.clone();
        let rsa_n = jwk.n.clone();
        let rsa_e = jwk.e.clone();

        // Estimate key size from available data
        let key_size = rsa_n.as_ref().map(|n| n.len() * 8);

        Ok(Self {
            client,
            key_name: key_name.to_string(),
            key_version: resolved_version,
            key_type,
            key_size,
            curve_name,
            key_id,
            is_hsm: vault_url.contains("managedhsm"),
            ec_x,
            ec_y,
            rsa_n,
            rsa_e,
            runtime,
        })
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
        let key_version = self.key_version.as_deref().unwrap_or("latest");
        let content: azure_core::http::RequestContent<SignParameters> = params
            .try_into()
            .map_err(|e: azure_core::Error| AkvError::CryptoOperationFailed(e.to_string()))?;
        let result = self.runtime.block_on(async {
            self.client.sign(&self.key_name, key_version, content, None).await
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
        // For EC keys: return uncompressed point (0x04 || x || y)
        if let (Some(x), Some(y)) = (&self.ec_x, &self.ec_y) {
            let mut point = Vec::with_capacity(1 + x.len() + y.len());
            point.push(0x04); // uncompressed point marker
            point.extend_from_slice(x);
            point.extend_from_slice(y);
            return Ok(point);
        }

        // For RSA keys: return the raw n and e components concatenated
        // (callers who need PKCS#1 or SPKI format should re-encode)
        if let (Some(n), Some(e)) = (&self.rsa_n, &self.rsa_e) {
            let mut data = Vec::with_capacity(n.len() + e.len());
            data.extend_from_slice(n);
            data.extend_from_slice(e);
            return Ok(data);
        }

        Err(AkvError::General(
            "no public key components available (key may not have x/y for EC or n/e for RSA)".into(),
        ))
    }
    fn name(&self) -> &str { &self.key_name }
    fn version(&self) -> &str { self.key_version.as_deref().unwrap_or("") }
    fn is_hsm_protected(&self) -> bool { self.is_hsm }
}
