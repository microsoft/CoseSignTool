// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! FFI-safe type wrappers for cose_sign1_primitives types.
//!
//! These types provide opaque handles that can be safely passed across the FFI boundary.

use cose_sign1_primitives::{CoseHeaderMap, CoseSign1Message, CryptoVerifier};

/// Opaque handle to a CoseSign1Message.
///
/// This handle wraps a parsed COSE_Sign1 message and provides access to its
/// components through FFI-safe functions.
#[repr(C)]
pub struct CoseSign1MessageHandle {
    _private: [u8; 0],
}

/// Opaque handle to a verification/signing key.
///
/// This handle wraps a CryptoVerifier/CryptoSigner and provides access to
/// its functionality through FFI-safe functions.
#[repr(C)]
pub struct CoseKeyHandle {
    _private: [u8; 0],
}

/// Opaque handle to a CoseHeaderMap.
///
/// This handle wraps a header map (protected or unprotected) and provides
/// access to header values through FFI-safe functions.
#[repr(C)]
pub struct CoseHeaderMapHandle {
    _private: [u8; 0],
}

/// Internal wrapper for CoseSign1Message.
pub(crate) struct MessageInner {
    pub message: CoseSign1Message,
}

/// Internal wrapper for CryptoVerifier.
pub(crate) struct KeyInner {
    pub key: Box<dyn CryptoVerifier>,
}

/// Internal wrapper for CoseHeaderMap.
pub(crate) struct HeaderMapInner {
    pub headers: CoseHeaderMap,
}

// ============================================================================
// Message handle conversions
// ============================================================================

/// Casts a message handle to its inner representation.
///
/// # Safety
///
/// The handle must be valid and non-null, and must remain valid for the
/// lifetime `'a` of the returned reference.
pub(crate) unsafe fn message_handle_to_inner<'a>(
    handle: *const CoseSign1MessageHandle,
) -> Option<&'a MessageInner> {
    if handle.is_null() {
        return None;
    }
    Some(unsafe { &*(handle as *const MessageInner) })
}

/// Creates a message handle from an inner representation.
pub(crate) fn message_inner_to_handle(inner: MessageInner) -> *mut CoseSign1MessageHandle {
    let boxed = Box::new(inner);
    Box::into_raw(boxed) as *mut CoseSign1MessageHandle
}

// ============================================================================
// Key handle conversions
// ============================================================================

/// Casts a key handle to its inner representation.
///
/// # Safety
///
/// The handle must be valid and non-null, and must remain valid for the
/// lifetime `'a` of the returned reference.
pub(crate) unsafe fn key_handle_to_inner<'a>(
    handle: *const CoseKeyHandle,
) -> Option<&'a KeyInner> {
    if handle.is_null() {
        return None;
    }
    Some(unsafe { &*(handle as *const KeyInner) })
}

/// Creates a key handle from an inner representation.
pub(crate) fn key_inner_to_handle(inner: KeyInner) -> *mut CoseKeyHandle {
    let boxed = Box::new(inner);
    Box::into_raw(boxed) as *mut CoseKeyHandle
}

// ============================================================================
// HeaderMap handle conversions
// ============================================================================

/// Casts a header map handle to its inner representation.
///
/// # Safety
///
/// The handle must be valid and non-null, and must remain valid for the
/// lifetime `'a` of the returned reference.
pub(crate) unsafe fn headermap_handle_to_inner<'a>(
    handle: *const CoseHeaderMapHandle,
) -> Option<&'a HeaderMapInner> {
    if handle.is_null() {
        return None;
    }
    Some(unsafe { &*(handle as *const HeaderMapInner) })
}

/// Creates a header map handle from an inner representation.
pub(crate) fn headermap_inner_to_handle(inner: HeaderMapInner) -> *mut CoseHeaderMapHandle {
    let boxed = Box::new(inner);
    Box::into_raw(boxed) as *mut CoseHeaderMapHandle
}
