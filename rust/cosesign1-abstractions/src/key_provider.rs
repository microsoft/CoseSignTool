// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Extensible signing-key provider registry.
//!
//! Providers are registered using `inventory::submit!`.
//! The `cosesign1` facade uses this registry to resolve signing keys without
//! hard-coding any particular provider (e.g., x5c/X.509).

use std::any::Any;

use crate::ParsedCoseSign1;

#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub struct SigningKeyProviderId(pub uuid::Uuid);

#[derive(thiserror::Error, Debug)]
pub enum PublicKeyProviderError {
    #[error("{0}")]
    Message(String),
}

/// A resolved signing key.
///
/// `public_key_bytes` is forwarded to signature verification.
/// Providers may optionally attach additional material (e.g., full certificate chain)
/// to support signing-key validation.
pub struct ResolvedSigningKey {
    pub provider_id: SigningKeyProviderId,
    pub provider_name: &'static str,
    pub public_key_bytes: Vec<u8>,
    pub material: Option<Box<dyn Any + Send + Sync>>,
}

impl ResolvedSigningKey {
    /// Construct a resolved signing key. Provider identity will be filled in by the registry.
    pub fn new(public_key_bytes: Vec<u8>) -> Self {
        Self {
            provider_id: SigningKeyProviderId(uuid::Uuid::nil()),
            provider_name: "",
            public_key_bytes,
            material: None,
        }
    }

    /// Construct a resolved signing key with additional provider-specific material.
    /// Provider identity will be filled in by the registry.
    pub fn with_material(public_key_bytes: Vec<u8>, material: Box<dyn Any + Send + Sync>) -> Self {
        Self {
            provider_id: SigningKeyProviderId(uuid::Uuid::nil()),
            provider_name: "",
            public_key_bytes,
            material: Some(material),
        }
    }
}

/// A provider that may be able to resolve a signing key from a COSE_Sign1 message.
///
/// Contract:
/// - Return `Ok(None)` when the provider is not applicable (e.g., header missing).
/// - Return `Ok(Some(resolved))` when the provider successfully resolved key bytes.
/// - Return `Err(...)` when the provider is applicable but the message is malformed.
///
pub trait SigningKeyProvider: Sync {
    fn name(&self) -> &'static str;

    fn try_resolve_signing_key(
        &self,
        parsed: &ParsedCoseSign1,
    ) -> Result<Option<ResolvedSigningKey>, PublicKeyProviderError>;
}

pub struct SigningKeyProviderRegistration {
    pub id: SigningKeyProviderId,
    pub name: &'static str,
    pub priority: i32,
    pub provider: &'static dyn SigningKeyProvider,
}

inventory::collect!(SigningKeyProviderRegistration);

#[derive(thiserror::Error, Debug)]
pub enum ResolvePublicKeyError {
    #[error("no public key provider matched")]
    NoProviderMatched,

    #[error("provider '{provider}' failed: {error}")]
    ProviderFailed {
        provider: &'static str,
        error: PublicKeyProviderError,
    },
}

/// Iterate all registered providers ordered by descending priority.
pub fn providers_ordered() -> Vec<&'static SigningKeyProviderRegistration> {
    let mut regs: Vec<_> = inventory::iter::<SigningKeyProviderRegistration>.into_iter().collect();
    regs.sort_by(|a, b| b.priority.cmp(&a.priority));
    regs
}

/// Resolve a signing key using registered providers.
pub fn resolve_signing_key(parsed: &ParsedCoseSign1) -> Result<ResolvedSigningKey, ResolvePublicKeyError> {
    for reg in providers_ordered() {
        match reg.provider.try_resolve_signing_key(parsed) {
            Ok(Some(mut resolved)) => {
                resolved.provider_id = reg.id;
                resolved.provider_name = reg.name;
                return Ok(resolved);
            }
            Ok(None) => continue,
            Err(e) => {
                return Err(ResolvePublicKeyError::ProviderFailed {
                    provider: reg.provider.name(),
                    error: e,
                })
            }
        }
    }

    Err(ResolvePublicKeyError::NoProviderMatched)
}

pub fn provider_name(id: SigningKeyProviderId) -> Option<&'static str> {
    inventory::iter::<SigningKeyProviderRegistration>
        .into_iter()
        .find(|r| r.id == id)
        .map(|r| r.name)
}
