// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Azure Key Vault crypto client abstraction.
//!
//! This trait abstracts the Azure Key Vault SDK's CryptographyClient,
//! allowing for testability and different implementations.

use super::error::AkvError;

/// Abstraction for Azure Key Vault cryptographic operations.
///
/// Maps V2's `IKeyVaultClientFactory` + `KeyVaultCryptoClientWrapper` concepts.
/// Implementations wrap the Azure SDK's CryptographyClient or provide mocks for testing.
pub trait KeyVaultCryptoClient: Send + Sync {
    /// Signs a digest using the key in Azure Key Vault.
    ///
    /// # Arguments
    ///
    /// * `algorithm` - The signing algorithm (e.g., "ES256", "PS256")
    /// * `digest` - The pre-computed digest to sign
    ///
    /// # Returns
    ///
    /// The signature bytes on success.
    fn sign(&self, algorithm: &str, digest: &[u8]) -> Result<Vec<u8>, AkvError>;

    /// Returns the full key identifier URI.
    ///
    /// Format: `https://{vault}.vault.azure.net/keys/{name}/{version}`
    fn key_id(&self) -> &str;

    /// Returns the key type (e.g., "EC", "RSA").
    fn key_type(&self) -> &str;

    /// Returns the key size in bits for RSA keys.
    fn key_size(&self) -> Option<usize>;

    /// Returns the curve name for EC keys (e.g., "P-256", "P-384", "P-521").
    fn curve_name(&self) -> Option<&str>;

    /// Returns the public key bytes (DER-encoded SubjectPublicKeyInfo).
    fn public_key_bytes(&self) -> Result<Vec<u8>, AkvError>;

    /// Returns the key name in the vault.
    fn name(&self) -> &str;

    /// Returns the key version identifier.
    fn version(&self) -> &str;

    /// Returns whether this key is HSM-protected.
    fn is_hsm_protected(&self) -> bool;
}
