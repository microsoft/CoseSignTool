// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! FFI-safe type wrappers for did_x509 types.
//!
//! These types provide opaque handles that can be safely passed across the FFI boundary.

use did_x509::DidX509ParsedIdentifier;

/// Opaque handle to a parsed DID:x509 identifier.
#[repr(C)]
pub struct DidX509ParsedHandle {
    _private: [u8; 0],
}

/// Internal wrapper for parsed DID.
pub(crate) struct ParsedInner {
    pub parsed: DidX509ParsedIdentifier,
}

// ============================================================================
// Parsed handle conversions
// ============================================================================

/// Casts a parsed handle to its inner representation (immutable).
///
/// # Safety
///
/// The handle must be valid and non-null.
pub(crate) unsafe fn parsed_handle_to_inner(
    handle: *const DidX509ParsedHandle,
) -> Option<&'static ParsedInner> {
    if handle.is_null() {
        return None;
    }
    Some(unsafe { &*(handle as *const ParsedInner) })
}

/// Creates a parsed handle from an inner representation.
pub(crate) fn parsed_inner_to_handle(inner: ParsedInner) -> *mut DidX509ParsedHandle {
    let boxed = Box::new(inner);
    Box::into_raw(boxed) as *mut DidX509ParsedHandle
}
