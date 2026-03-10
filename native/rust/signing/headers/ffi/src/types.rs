// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! FFI-safe type wrappers for CWT Claims types.
//!
//! These types provide opaque handles that can be safely passed across the FFI boundary.

use cose_sign1_headers::CwtClaims;

/// Opaque handle to a CWT Claims instance.
#[repr(C)]
pub struct CoseCwtClaimsHandle {
    _private: [u8; 0],
}

/// Internal wrapper for CWT Claims.
pub(crate) struct CwtClaimsInner {
    pub claims: CwtClaims,
}

// ============================================================================
// CWT Claims handle conversions
// ============================================================================

/// Casts a CWT Claims handle to its inner representation (immutable).
///
/// # Safety
///
/// The handle must be valid and non-null.
pub(crate) unsafe fn cwt_claims_handle_to_inner(
    handle: *const CoseCwtClaimsHandle,
) -> Option<&'static CwtClaimsInner> {
    if handle.is_null() {
        return None;
    }
    Some(unsafe { &*(handle as *const CwtClaimsInner) })
}

/// Casts a CWT Claims handle to its inner representation (mutable).
///
/// # Safety
///
/// The handle must be valid and non-null.
pub(crate) unsafe fn cwt_claims_handle_to_inner_mut(
    handle: *mut CoseCwtClaimsHandle,
) -> Option<&'static mut CwtClaimsInner> {
    if handle.is_null() {
        return None;
    }
    Some(unsafe { &mut *(handle as *mut CwtClaimsInner) })
}

/// Creates a CWT Claims handle from an inner representation.
pub(crate) fn cwt_claims_inner_to_handle(inner: CwtClaimsInner) -> *mut CoseCwtClaimsHandle {
    let boxed = Box::new(inner);
    Box::into_raw(boxed) as *mut CoseCwtClaimsHandle
}
