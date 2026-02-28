// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! FFI-safe type wrappers for cose_sign1_primitives builder types.
//!
//! These types provide opaque handles that can be safely passed across the FFI boundary.

use cose_sign1_primitives::{CoseHeaderMap, CryptoSigner};

/// Opaque handle to a CoseSign1 builder.
#[repr(C)]
pub struct CoseSign1BuilderHandle {
    _private: [u8; 0],
}

/// Opaque handle to a header map for builder input.
#[repr(C)]
pub struct CoseHeaderMapHandle {
    _private: [u8; 0],
}

/// Opaque handle to a signing key.
#[repr(C)]
pub struct CoseKeyHandle {
    _private: [u8; 0],
}

/// Internal wrapper for builder state.
pub(crate) struct BuilderInner {
    pub protected: CoseHeaderMap,
    pub unprotected: Option<CoseHeaderMap>,
    pub external_aad: Option<Vec<u8>>,
    pub tagged: bool,
    pub detached: bool,
}

/// Internal wrapper for CoseHeaderMap.
pub(crate) struct HeaderMapInner {
    pub headers: CoseHeaderMap,
}

/// Internal wrapper for CryptoSigner.
pub struct KeyInner {
    pub key: std::sync::Arc<dyn CryptoSigner>,
}

// ============================================================================
// SigningService handle types
// ============================================================================

/// Opaque handle to a SigningService.
#[repr(C)]
pub struct CoseSign1SigningServiceHandle {
    _private: [u8; 0],
}

/// Internal wrapper for SigningService.
pub(crate) struct SigningServiceInner {
    pub service: std::sync::Arc<dyn cose_sign1_signing::SigningService>,
}

// ============================================================================
// Factory handle types
// ============================================================================

/// Opaque handle to CoseSign1MessageFactory.
#[repr(C)]
pub struct CoseSign1FactoryHandle {
    _private: [u8; 0],
}

/// Internal wrapper for CoseSign1MessageFactory.
pub(crate) struct FactoryInner {
    pub factory: cose_sign1_factories::CoseSign1MessageFactory,
}

// ============================================================================
// Builder handle conversions
// ============================================================================

/// Casts a builder handle to its inner representation (mutable).
///
/// # Safety
///
/// The handle must be valid and non-null.
pub(crate) unsafe fn builder_handle_to_inner_mut(
    handle: *mut CoseSign1BuilderHandle,
) -> Option<&'static mut BuilderInner> {
    if handle.is_null() {
        return None;
    }
    Some(unsafe { &mut *(handle as *mut BuilderInner) })
}

/// Creates a builder handle from an inner representation.
pub(crate) fn builder_inner_to_handle(inner: BuilderInner) -> *mut CoseSign1BuilderHandle {
    let boxed = Box::new(inner);
    Box::into_raw(boxed) as *mut CoseSign1BuilderHandle
}

// ============================================================================
// HeaderMap handle conversions
// ============================================================================

/// Casts a header map handle to its inner representation (immutable).
///
/// # Safety
///
/// The handle must be valid and non-null.
pub(crate) unsafe fn headermap_handle_to_inner(
    handle: *const CoseHeaderMapHandle,
) -> Option<&'static HeaderMapInner> {
    if handle.is_null() {
        return None;
    }
    Some(unsafe { &*(handle as *const HeaderMapInner) })
}

/// Casts a header map handle to its inner representation (mutable).
///
/// # Safety
///
/// The handle must be valid and non-null.
pub(crate) unsafe fn headermap_handle_to_inner_mut(
    handle: *mut CoseHeaderMapHandle,
) -> Option<&'static mut HeaderMapInner> {
    if handle.is_null() {
        return None;
    }
    Some(unsafe { &mut *(handle as *mut HeaderMapInner) })
}

/// Creates a header map handle from an inner representation.
pub(crate) fn headermap_inner_to_handle(inner: HeaderMapInner) -> *mut CoseHeaderMapHandle {
    let boxed = Box::new(inner);
    Box::into_raw(boxed) as *mut CoseHeaderMapHandle
}

// ============================================================================
// Key handle conversions
// ============================================================================

/// Casts a key handle to its inner representation.
///
/// # Safety
///
/// The handle must be valid and non-null.
pub(crate) unsafe fn key_handle_to_inner(
    handle: *const CoseKeyHandle,
) -> Option<&'static KeyInner> {
    if handle.is_null() {
        return None;
    }
    Some(unsafe { &*(handle as *const KeyInner) })
}

/// Creates a key handle from an inner representation.
pub fn key_inner_to_handle(inner: KeyInner) -> *mut CoseKeyHandle {
    let boxed = Box::new(inner);
    Box::into_raw(boxed) as *mut CoseKeyHandle
}

// ============================================================================
// SigningService handle conversions
// ============================================================================

/// Casts a signing service handle to its inner representation.
///
/// # Safety
///
/// The handle must be valid and non-null.
pub(crate) unsafe fn signing_service_handle_to_inner(
    handle: *const CoseSign1SigningServiceHandle,
) -> Option<&'static SigningServiceInner> {
    if handle.is_null() {
        return None;
    }
    Some(unsafe { &*(handle as *const SigningServiceInner) })
}

/// Creates a signing service handle from an inner representation.
pub(crate) fn signing_service_inner_to_handle(
    inner: SigningServiceInner,
) -> *mut CoseSign1SigningServiceHandle {
    let boxed = Box::new(inner);
    Box::into_raw(boxed) as *mut CoseSign1SigningServiceHandle
}

// ============================================================================
// Factory handle conversions
// ============================================================================

/// Casts a factory handle to its inner representation.
///
/// # Safety
///
/// The handle must be valid and non-null.
pub(crate) unsafe fn factory_handle_to_inner(
    handle: *const CoseSign1FactoryHandle,
) -> Option<&'static FactoryInner> {
    if handle.is_null() {
        return None;
    }
    Some(unsafe { &*(handle as *const FactoryInner) })
}

/// Creates a factory handle from an inner representation.
pub(crate) fn factory_inner_to_handle(inner: FactoryInner) -> *mut CoseSign1FactoryHandle {
    let boxed = Box::new(inner);
    Box::into_raw(boxed) as *mut CoseSign1FactoryHandle
}
