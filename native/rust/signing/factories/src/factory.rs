// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Router factory for COSE_Sign1 messages.

use std::any::{Any, TypeId};
use std::collections::HashMap;
use std::sync::Arc;

use cose_sign1_primitives::CoseSign1Message;
use cose_sign1_signing::{SigningService, transparency::TransparencyProvider};

use crate::{
    FactoryError,
    direct::{DirectSignatureFactory, DirectSignatureOptions},
    indirect::{IndirectSignatureFactory, IndirectSignatureOptions},
};

/// Trait for type-erased factory implementations.
///
/// Each concrete factory handles a specific options type.
/// Extension packs implement this trait to add custom signing workflows.
pub trait SignatureFactoryProvider: Send + Sync {
    /// Create a COSE_Sign1 message and return as bytes.
    ///
    /// # Arguments
    ///
    /// * `payload` - The payload bytes to sign
    /// * `content_type` - Content type of the payload
    /// * `options` - Type-erased options (must be downcast to concrete type)
    ///
    /// # Returns
    ///
    /// The COSE_Sign1 message as bytes, or an error if signing fails.
    fn create_bytes_dyn(
        &self,
        payload: &[u8],
        content_type: &str,
        options: &dyn Any,
    ) -> Result<Vec<u8>, FactoryError>;

    /// Create a COSE_Sign1 message.
    ///
    /// # Arguments
    ///
    /// * `payload` - The payload bytes to sign
    /// * `content_type` - Content type of the payload
    /// * `options` - Type-erased options (must be downcast to concrete type)
    ///
    /// # Returns
    ///
    /// The COSE_Sign1 message, or an error if signing fails.
    fn create_dyn(
        &self,
        payload: &[u8],
        content_type: &str,
        options: &dyn Any,
    ) -> Result<CoseSign1Message, FactoryError>;
}

/// Extensible factory router.
///
/// Maps V2 `CoseSign1MessageFactory` / `ICoseSign1MessageFactoryRouter`.
/// Packs register factories keyed by options TypeId.
///
/// The indirect factory wraps the direct factory following the V2 pattern,
/// and this router provides access to both via the indirect factory.
/// Extension factories are stored in a HashMap for type-based dispatch.
pub struct CoseSign1MessageFactory {
    factories: HashMap<TypeId, Box<dyn SignatureFactoryProvider>>,
    /// The built-in indirect factory (owns the direct factory).
    indirect_factory: IndirectSignatureFactory,
}

impl CoseSign1MessageFactory {
    /// Creates a new message factory with a signing service.
    ///
    /// Registers the built-in Direct and Indirect factories.
    pub fn new(signing_service: Arc<dyn SigningService>) -> Self {
        let direct_factory = DirectSignatureFactory::new(signing_service);
        let indirect_factory = IndirectSignatureFactory::new(direct_factory);
        let factories = HashMap::<TypeId, Box<dyn SignatureFactoryProvider>>::new();

        Self {
            factories,
            indirect_factory,
        }
    }

    /// Creates a new message factory with a signing service and transparency providers.
    ///
    /// Registers the built-in Direct and Indirect factories with transparency support.
    pub fn with_transparency(
        signing_service: Arc<dyn SigningService>,
        providers: Vec<Box<dyn TransparencyProvider>>,
    ) -> Self {
        let direct_factory =
            DirectSignatureFactory::with_transparency_providers(signing_service, providers);
        let indirect_factory = IndirectSignatureFactory::new(direct_factory);
        let factories = HashMap::<TypeId, Box<dyn SignatureFactoryProvider>>::new();

        Self {
            factories,
            indirect_factory,
        }
    }

    /// Register an extension factory for a custom options type.
    ///
    /// Used by support packs (e.g., CSS) to add new signing workflows.
    ///
    /// # Type Parameters
    ///
    /// * `T` - The options type that this factory handles
    ///
    /// # Arguments
    ///
    /// * `factory` - The factory implementation
    ///
    /// # Example
    ///
    /// ```ignore
    /// let mut factory = CoseSign1MessageFactory::new(signing_service);
    /// factory.register::<CustomOptions>(Box::new(CustomFactory::new()));
    /// ```
    pub fn register<T: 'static>(&mut self, factory: Box<dyn SignatureFactoryProvider>) {
        self.factories.insert(TypeId::of::<T>(), factory);
    }

    /// Creates a COSE_Sign1 message with a direct signature.
    ///
    /// # Arguments
    ///
    /// * `payload` - The payload bytes to sign
    /// * `content_type` - Content type of the payload
    /// * `options` - Optional signing options
    pub fn create_direct(
        &self,
        payload: &[u8],
        content_type: &str,
        options: Option<DirectSignatureOptions>,
    ) -> Result<CoseSign1Message, FactoryError> {
        self.indirect_factory
            .direct_factory()
            .create(payload, content_type, options)
    }

    /// Creates a COSE_Sign1 message with a direct signature and returns it as bytes.
    ///
    /// # Arguments
    ///
    /// * `payload` - The payload bytes to sign
    /// * `content_type` - Content type of the payload
    /// * `options` - Optional signing options
    pub fn create_direct_bytes(
        &self,
        payload: &[u8],
        content_type: &str,
        options: Option<DirectSignatureOptions>,
    ) -> Result<Vec<u8>, FactoryError> {
        self.indirect_factory
            .direct_factory()
            .create_bytes(payload, content_type, options)
    }

    /// Creates a COSE_Sign1 message with an indirect signature.
    ///
    /// # Arguments
    ///
    /// * `payload` - The payload bytes to hash and sign
    /// * `content_type` - Original content type of the payload
    /// * `options` - Optional signing options
    pub fn create_indirect(
        &self,        payload: &[u8],
        content_type: &str,
        options: Option<IndirectSignatureOptions>,
    ) -> Result<CoseSign1Message, FactoryError> {
        self.indirect_factory
            .create(payload, content_type, options)
    }

    /// Creates a COSE_Sign1 message with an indirect signature and returns it as bytes.
    ///
    /// # Arguments
    ///
    /// * `payload` - The payload bytes to hash and sign
    /// * `content_type` - Original content type of the payload
    /// * `options` - Optional signing options
    pub fn create_indirect_bytes(
        &self,
        payload: &[u8],
        content_type: &str,
        options: Option<IndirectSignatureOptions>,
    ) -> Result<Vec<u8>, FactoryError> {
        self.indirect_factory
            .create_bytes(payload, content_type, options)
    }

    /// Creates a COSE_Sign1 message with a direct signature from a streaming payload.
    ///
    /// # Arguments
    ///
    /// * `payload` - The streaming payload to sign
    /// * `content_type` - Content type of the payload
    /// * `options` - Optional signing options
    pub fn create_direct_streaming(
        &self,
        payload: std::sync::Arc<dyn cose_sign1_primitives::StreamingPayload>,
        content_type: &str,
        options: Option<DirectSignatureOptions>,
    ) -> Result<CoseSign1Message, FactoryError> {
        self.indirect_factory
            .direct_factory()
            .create_streaming(payload, content_type, options)
    }

    /// Creates a COSE_Sign1 message with a direct signature from a streaming payload and returns it as bytes.
    ///
    /// # Arguments
    ///
    /// * `payload` - The streaming payload to sign
    /// * `content_type` - Content type of the payload
    /// * `options` - Optional signing options
    pub fn create_direct_streaming_bytes(
        &self,
        payload: std::sync::Arc<dyn cose_sign1_primitives::StreamingPayload>,
        content_type: &str,
        options: Option<DirectSignatureOptions>,
    ) -> Result<Vec<u8>, FactoryError> {
        self.indirect_factory
            .direct_factory()
            .create_streaming_bytes(payload, content_type, options)
    }

    /// Creates a COSE_Sign1 message with an indirect signature from a streaming payload.
    ///
    /// # Arguments
    ///
    /// * `payload` - The streaming payload to hash and sign
    /// * `content_type` - Original content type of the payload
    /// * `options` - Optional signing options
    pub fn create_indirect_streaming(
        &self,
        payload: std::sync::Arc<dyn cose_sign1_primitives::StreamingPayload>,
        content_type: &str,
        options: Option<IndirectSignatureOptions>,
    ) -> Result<CoseSign1Message, FactoryError> {
        self.indirect_factory
            .create_streaming(payload, content_type, options)
    }

    /// Creates a COSE_Sign1 message with an indirect signature from a streaming payload and returns it as bytes.
    ///
    /// # Arguments
    ///
    /// * `payload` - The streaming payload to hash and sign
    /// * `content_type` - Original content type of the payload
    /// * `options` - Optional signing options
    pub fn create_indirect_streaming_bytes(
        &self,
        payload: std::sync::Arc<dyn cose_sign1_primitives::StreamingPayload>,
        content_type: &str,
        options: Option<IndirectSignatureOptions>,
    ) -> Result<Vec<u8>, FactoryError> {
        self.indirect_factory
            .create_streaming_bytes(payload, content_type, options)
    }

    /// Create via a registered extension factory.
    ///
    /// # Type Parameters
    ///
    /// * `T` - The options type that identifies the factory
    ///
    /// # Arguments
    ///
    /// * `payload` - The payload bytes to sign
    /// * `content_type` - Content type of the payload
    /// * `options` - The options for the factory (concrete type)
    ///
    /// # Returns
    ///
    /// The COSE_Sign1 message, or an error if no factory is registered
    /// for the options type or if signing fails.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let options = CustomOptions::new();
    /// let message = factory.create_with(payload, "application/custom", &options)?;
    /// ```
    pub fn create_with<T: 'static>(
        &self,
        payload: &[u8],
        content_type: &str,
        options: &T,
    ) -> Result<CoseSign1Message, FactoryError> {
        let factory = self
            .factories
            .get(&TypeId::of::<T>())
            .ok_or_else(|| {
                FactoryError::SigningFailed(format!(
                    "No factory registered for options type {:?}",
                    std::any::type_name::<T>()
                ))
            })?;
        factory.create_dyn(payload, content_type, options)
    }
}
