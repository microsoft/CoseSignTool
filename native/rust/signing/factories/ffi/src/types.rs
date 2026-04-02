// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! FFI-safe type wrappers for factory types.
//!
//! These types provide opaque handles that can be safely passed across the FFI boundary.

/// Opaque handle to CoseSign1MessageFactory.
#[repr(C)]
pub struct CoseSign1FactoriesHandle {
    _private: [u8; 0],
}

/// Opaque handle to a SigningService.
#[repr(C)]
pub struct CoseSign1FactoriesSigningServiceHandle {
    _private: [u8; 0],
}

/// Opaque handle to a TransparencyProvider.
#[repr(C)]
pub struct CoseSign1FactoriesTransparencyProviderHandle {
    _private: [u8; 0],
}

/// Internal wrapper for CoseSign1MessageFactory.
pub struct FactoryInner {
    pub factory: cose_sign1_factories::CoseSign1MessageFactory,
}

/// Internal wrapper for SigningService.
pub struct SigningServiceInner {
    pub service: std::sync::Arc<dyn cose_sign1_signing::SigningService>,
}

/// Internal wrapper for TransparencyProvider.
pub(crate) struct TransparencyProviderInner {
    pub provider: Box<dyn cose_sign1_signing::transparency::TransparencyProvider>,
}

// ============================================================================
// Factory handle conversions
// ============================================================================

/// Casts a factory handle to its inner representation (immutable).
///
/// # Safety
///
/// The handle must be valid and non-null.
pub(crate) unsafe fn factory_handle_to_inner<'a>(
    handle: *const CoseSign1FactoriesHandle,
) -> Option<&'a FactoryInner> {
    if handle.is_null() {
        return None;
    }
    Some(unsafe { &*(handle as *const FactoryInner) })
}

/// Creates a factory handle from an inner representation.
pub(crate) fn factory_inner_to_handle(inner: FactoryInner) -> *mut CoseSign1FactoriesHandle {
    let boxed = Box::new(inner);
    Box::into_raw(boxed) as *mut CoseSign1FactoriesHandle
}

// ============================================================================
// SigningService handle conversions
// ============================================================================

/// Casts a signing service handle to its inner representation (immutable).
///
/// # Safety
///
/// The handle must be valid and non-null.
pub(crate) unsafe fn signing_service_handle_to_inner<'a>(
    handle: *const CoseSign1FactoriesSigningServiceHandle,
) -> Option<&'a SigningServiceInner> {
    if handle.is_null() {
        return None;
    }
    Some(unsafe { &*(handle as *const SigningServiceInner) })
}

// ============================================================================
// Message handle types (compatible with primitives FFI handles)
// ============================================================================

/// Opaque handle to a CoseSign1Message.
///
/// This handle type is binary-compatible with `CoseSign1MessageHandle` from
/// `cose_sign1_primitives_ffi`. Handles returned by factory signing functions
/// can be passed to primitives FFI accessors (`cose_sign1_message_as_bytes`,
/// `cose_sign1_message_payload`, `cose_sign1_message_signature`, etc.) and
/// freed with `cose_sign1_message_free`.
#[repr(C)]
pub struct CoseSign1MessageHandle {
    _private: [u8; 0],
}

/// Internal wrapper for CoseSign1Message.
///
/// Layout matches `MessageInner` in `cose_sign1_primitives_ffi` so that
/// handles produced here are interchangeable with the primitives FFI.
#[allow(dead_code)] // Field accessed via raw pointer casts (opaque handle pattern)
pub(crate) struct MessageInner {
    pub message: cose_sign1_primitives::CoseSign1Message,
}

/// Creates a message handle from an inner representation.
pub(crate) fn message_inner_to_handle(inner: MessageInner) -> *mut CoseSign1MessageHandle {
    let boxed = Box::new(inner);
    Box::into_raw(boxed) as *mut CoseSign1MessageHandle
}
