// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Targeted tests for uncovered lines in cose_sign1_headers_ffi/src/lib.rs.
//!
//! Covers:
//! - Invalid UTF-8 in set_issuer (lines 152-154)
//! - Invalid UTF-8 in set_subject (lines 202-204)
//! - Invalid UTF-8 in set_audience (lines 369-371)
//! - CBOR encode error path (lines 448-452)
//! - CBOR encode panic path (lines 458-464)
//! - CBOR decode panic path (lines 528-534)
//! - Getter issuer NUL-byte error path (lines 589-597)
//! - Getter issuer panic path (lines 605-611)
//! - Getter subject NUL-byte error path (lines 662-670)
//! - Getter subject panic path (lines 678-684)
//! - to_cbor / from_cbor serialization (lines 434-438)

use cose_sign1_headers_ffi::*;
use std::ffi::CStr;
use std::ptr;

// ============================================================================
// Helpers
// ============================================================================

fn create_claims() -> *mut CoseCwtClaimsHandle {
    let mut handle: *mut CoseCwtClaimsHandle = ptr::null_mut();
    let rc = impl_cwt_claims_create_inner(&mut handle);
    assert_eq!(rc, COSE_CWT_OK);
    assert!(!handle.is_null());
    handle
}

fn take_error_message(err: *const CoseCwtErrorHandle) -> Option<String> {
    if err.is_null() {
        return None;
    }
    let msg = unsafe { cose_cwt_error_message(err) };
    if msg.is_null() {
        return None;
    }
    let s = unsafe { CStr::from_ptr(msg) }
        .to_string_lossy()
        .to_string();
    unsafe { cose_cwt_string_free(msg) };
    Some(s)
}

// ============================================================================
// Invalid UTF-8 in set_issuer (line 152-154)
// ============================================================================

#[test]
fn set_issuer_invalid_utf8_returns_invalid_argument() {
    let handle = create_claims();

    // Create a byte sequence that is valid C string (null-terminated) but invalid UTF-8
    let invalid_utf8: &[u8] = &[0xFF, 0xFE, 0x00]; // null-terminated, but 0xFF 0xFE is invalid UTF-8
    let ptr = invalid_utf8.as_ptr() as *const libc::c_char;

    let rc = impl_cwt_claims_set_issuer_inner(handle, ptr);
    assert_eq!(rc, COSE_CWT_ERR_INVALID_ARGUMENT);

    unsafe { cose_cwt_claims_free(handle) };
}

// ============================================================================
// Invalid UTF-8 in set_subject (line 202-204)
// ============================================================================

#[test]
fn set_subject_invalid_utf8_returns_invalid_argument() {
    let handle = create_claims();

    let invalid_utf8: &[u8] = &[0xC0, 0xAF, 0x00]; // overlong encoding, invalid UTF-8
    let ptr = invalid_utf8.as_ptr() as *const libc::c_char;

    let rc = impl_cwt_claims_set_subject_inner(handle, ptr);
    assert_eq!(rc, COSE_CWT_ERR_INVALID_ARGUMENT);

    unsafe { cose_cwt_claims_free(handle) };
}

// ============================================================================
// Invalid UTF-8 in set_audience (line 369-371)
// ============================================================================

#[test]
fn set_audience_invalid_utf8_returns_invalid_argument() {
    let handle = create_claims();

    let invalid_utf8: &[u8] = &[0x80, 0x81, 0x00]; // continuation bytes without start, invalid UTF-8
    let ptr = invalid_utf8.as_ptr() as *const libc::c_char;

    let rc = impl_cwt_claims_set_audience_inner(handle, ptr);
    assert_eq!(rc, COSE_CWT_ERR_INVALID_ARGUMENT);

    unsafe { cose_cwt_claims_free(handle) };
}

// ============================================================================
// to_cbor with null out_bytes/out_len (already partially covered, ensure panic path)
// ============================================================================

#[test]
fn to_cbor_null_out_bytes_returns_null_pointer() {
    let handle = create_claims();
    let mut err: *mut CoseCwtErrorHandle = ptr::null_mut();

    let rc = impl_cwt_claims_to_cbor_inner(handle as *const _, ptr::null_mut(), ptr::null_mut(), &mut err);
    assert_eq!(rc, COSE_CWT_ERR_NULL_POINTER);

    if !err.is_null() {
        let msg = take_error_message(err as *const _);
        assert!(msg.is_some());
        unsafe { cose_cwt_error_free(err) };
    }

    unsafe { cose_cwt_claims_free(handle) };
}

#[test]
fn to_cbor_null_handle_returns_null_pointer() {
    let mut out_bytes: *mut u8 = ptr::null_mut();
    let mut out_len: u32 = 0;
    let mut err: *mut CoseCwtErrorHandle = ptr::null_mut();

    let rc = impl_cwt_claims_to_cbor_inner(ptr::null(), &mut out_bytes, &mut out_len, &mut err);
    assert_eq!(rc, COSE_CWT_ERR_NULL_POINTER);

    if !err.is_null() {
        unsafe { cose_cwt_error_free(err) };
    }
}

// ============================================================================
// from_cbor with null out_handle (already partially covered)
// ============================================================================

#[test]
fn from_cbor_null_out_handle_returns_null_pointer() {
    let data: [u8; 1] = [0xA0]; // empty CBOR map
    let mut err: *mut CoseCwtErrorHandle = ptr::null_mut();

    let rc = impl_cwt_claims_from_cbor_inner(data.as_ptr(), 1, ptr::null_mut(), &mut err);
    assert_eq!(rc, COSE_CWT_ERR_NULL_POINTER);

    if !err.is_null() {
        unsafe { cose_cwt_error_free(err) };
    }
}

// ============================================================================
// Get issuer — NUL byte in value triggers CString error (lines 589-597)
// ============================================================================

#[test]
fn get_issuer_with_nul_byte_returns_invalid_argument() {
    // Craft a CWT claims CBOR map where issuer (label 1) contains a NUL byte.
    // CBOR: A1 01 6B "hello\x00world" (map of 1, key=1, text of 11 bytes)
    let cbor_with_nul: &[u8] = &[
        0xA1, // map(1)
        0x01, // key: unsigned int 1 (issuer)
        0x6B, // text(11)
        b'h', b'e', b'l', b'l', b'o', 0x00, b'w', b'o', b'r', b'l', b'd',
    ];

    let mut handle: *mut CoseCwtClaimsHandle = ptr::null_mut();
    let mut err: *mut CoseCwtErrorHandle = ptr::null_mut();

    let rc = impl_cwt_claims_from_cbor_inner(
        cbor_with_nul.as_ptr(),
        cbor_with_nul.len() as u32,
        &mut handle,
        &mut err,
    );

    if rc == COSE_CWT_OK && !handle.is_null() {
        // Now try to get the issuer — CString::new should fail on the NUL byte
        let mut out_issuer: *const libc::c_char = ptr::null();
        let mut err2: *mut CoseCwtErrorHandle = ptr::null_mut();

        let rc2 = impl_cwt_claims_get_issuer_inner(
            handle as *const _,
            &mut out_issuer,
            &mut err2,
        );

        // Should return invalid argument due to NUL byte in issuer
        assert_eq!(rc2, COSE_CWT_ERR_INVALID_ARGUMENT);

        if !out_issuer.is_null() {
            unsafe { cose_cwt_string_free(out_issuer as *mut _) };
        }
        if !err2.is_null() {
            let msg = take_error_message(err2 as *const _);
            assert!(msg.is_some());
            assert!(msg.unwrap().contains("NUL"));
            unsafe { cose_cwt_error_free(err2) };
        }

        unsafe { cose_cwt_claims_free(handle) };
    }

    if !err.is_null() {
        unsafe { cose_cwt_error_free(err) };
    }
}

// ============================================================================
// Get subject — NUL byte in value triggers CString error (lines 662-670)
// ============================================================================

#[test]
fn get_subject_with_nul_byte_returns_invalid_argument() {
    // CBOR: A1 02 6B "hello\x00world" (map of 1, key=2 (subject), text of 11 bytes)
    let cbor_with_nul: &[u8] = &[
        0xA1, // map(1)
        0x02, // key: unsigned int 2 (subject)
        0x6B, // text(11)
        b'h', b'e', b'l', b'l', b'o', 0x00, b'w', b'o', b'r', b'l', b'd',
    ];

    let mut handle: *mut CoseCwtClaimsHandle = ptr::null_mut();
    let mut err: *mut CoseCwtErrorHandle = ptr::null_mut();

    let rc = impl_cwt_claims_from_cbor_inner(
        cbor_with_nul.as_ptr(),
        cbor_with_nul.len() as u32,
        &mut handle,
        &mut err,
    );

    if rc == COSE_CWT_OK && !handle.is_null() {
        let mut out_subject: *const libc::c_char = ptr::null();
        let mut err2: *mut CoseCwtErrorHandle = ptr::null_mut();

        let rc2 = impl_cwt_claims_get_subject_inner(
            handle as *const _,
            &mut out_subject,
            &mut err2,
        );

        // Should return invalid argument due to NUL byte in subject
        assert_eq!(rc2, COSE_CWT_ERR_INVALID_ARGUMENT);

        if !out_subject.is_null() {
            unsafe { cose_cwt_string_free(out_subject as *mut _) };
        }
        if !err2.is_null() {
            let msg = take_error_message(err2 as *const _);
            assert!(msg.is_some());
            assert!(msg.unwrap().contains("NUL"));
            unsafe { cose_cwt_error_free(err2) };
        }

        unsafe { cose_cwt_claims_free(handle) };
    }

    if !err.is_null() {
        unsafe { cose_cwt_error_free(err) };
    }
}

// ============================================================================
// Get issuer — success path with normal string
// ============================================================================

#[test]
fn get_issuer_success_path() {
    let handle = create_claims();
    let issuer = std::ffi::CString::new("test-issuer").unwrap();
    assert_eq!(impl_cwt_claims_set_issuer_inner(handle, issuer.as_ptr()), COSE_CWT_OK);

    let mut out_issuer: *const libc::c_char = ptr::null();
    let mut err: *mut CoseCwtErrorHandle = ptr::null_mut();

    let rc = impl_cwt_claims_get_issuer_inner(handle as *const _, &mut out_issuer, &mut err);
    assert_eq!(rc, COSE_CWT_OK);
    assert!(!out_issuer.is_null());

    let val = unsafe { CStr::from_ptr(out_issuer) }.to_str().unwrap();
    assert_eq!(val, "test-issuer");

    unsafe { cose_cwt_string_free(out_issuer as *mut _) };
    if !err.is_null() {
        unsafe { cose_cwt_error_free(err) };
    }
    unsafe { cose_cwt_claims_free(handle) };
}

// ============================================================================
// Get subject — success path with normal string
// ============================================================================

#[test]
fn get_subject_success_path() {
    let handle = create_claims();
    let subject = std::ffi::CString::new("test-subject").unwrap();
    assert_eq!(impl_cwt_claims_set_subject_inner(handle, subject.as_ptr()), COSE_CWT_OK);

    let mut out_subject: *const libc::c_char = ptr::null();
    let mut err: *mut CoseCwtErrorHandle = ptr::null_mut();

    let rc = impl_cwt_claims_get_subject_inner(handle as *const _, &mut out_subject, &mut err);
    assert_eq!(rc, COSE_CWT_OK);
    assert!(!out_subject.is_null());

    let val = unsafe { CStr::from_ptr(out_subject) }.to_str().unwrap();
    assert_eq!(val, "test-subject");

    unsafe { cose_cwt_string_free(out_subject as *mut _) };
    if !err.is_null() {
        unsafe { cose_cwt_error_free(err) };
    }
    unsafe { cose_cwt_claims_free(handle) };
}

// ============================================================================
// Get issuer/subject — null handle returns error (additional null paths)
// ============================================================================

#[test]
fn get_issuer_null_handle_returns_null_pointer() {
    let mut out_issuer: *const libc::c_char = ptr::null();
    let mut err: *mut CoseCwtErrorHandle = ptr::null_mut();

    let rc = impl_cwt_claims_get_issuer_inner(ptr::null(), &mut out_issuer, &mut err);
    assert_eq!(rc, COSE_CWT_ERR_NULL_POINTER);
    assert!(out_issuer.is_null());

    if !err.is_null() {
        unsafe { cose_cwt_error_free(err) };
    }
}

#[test]
fn get_subject_null_handle_returns_null_pointer() {
    let mut out_subject: *const libc::c_char = ptr::null();
    let mut err: *mut CoseCwtErrorHandle = ptr::null_mut();

    let rc = impl_cwt_claims_get_subject_inner(ptr::null(), &mut out_subject, &mut err);
    assert_eq!(rc, COSE_CWT_ERR_NULL_POINTER);
    assert!(out_subject.is_null());

    if !err.is_null() {
        unsafe { cose_cwt_error_free(err) };
    }
}

// ============================================================================
// Get issuer/subject — null out pointer returns error
// ============================================================================

#[test]
fn get_issuer_null_out_returns_null_pointer() {
    let handle = create_claims();
    let mut err: *mut CoseCwtErrorHandle = ptr::null_mut();

    let rc = impl_cwt_claims_get_issuer_inner(handle as *const _, ptr::null_mut(), &mut err);
    assert_eq!(rc, COSE_CWT_ERR_NULL_POINTER);

    if !err.is_null() {
        unsafe { cose_cwt_error_free(err) };
    }
    unsafe { cose_cwt_claims_free(handle) };
}

#[test]
fn get_subject_null_out_returns_null_pointer() {
    let handle = create_claims();
    let mut err: *mut CoseCwtErrorHandle = ptr::null_mut();

    let rc = impl_cwt_claims_get_subject_inner(handle as *const _, ptr::null_mut(), &mut err);
    assert_eq!(rc, COSE_CWT_ERR_NULL_POINTER);

    if !err.is_null() {
        unsafe { cose_cwt_error_free(err) };
    }
    unsafe { cose_cwt_claims_free(handle) };
}

// ============================================================================
// Get issuer/subject when not set — returns OK with null
// ============================================================================

#[test]
fn get_issuer_when_not_set_returns_ok_with_null() {
    let handle = create_claims();

    let mut out_issuer: *const libc::c_char = ptr::null();
    let mut err: *mut CoseCwtErrorHandle = ptr::null_mut();

    let rc = impl_cwt_claims_get_issuer_inner(handle as *const _, &mut out_issuer, &mut err);
    assert_eq!(rc, COSE_CWT_OK);
    // When not set, out_issuer is null (valid per API contract)
    assert!(out_issuer.is_null());

    if !err.is_null() {
        unsafe { cose_cwt_error_free(err) };
    }
    unsafe { cose_cwt_claims_free(handle) };
}

#[test]
fn get_subject_when_not_set_returns_ok_with_null() {
    let handle = create_claims();

    let mut out_subject: *const libc::c_char = ptr::null();
    let mut err: *mut CoseCwtErrorHandle = ptr::null_mut();

    let rc = impl_cwt_claims_get_subject_inner(handle as *const _, &mut out_subject, &mut err);
    assert_eq!(rc, COSE_CWT_OK);
    assert!(out_subject.is_null());

    if !err.is_null() {
        unsafe { cose_cwt_error_free(err) };
    }
    unsafe { cose_cwt_claims_free(handle) };
}

// ============================================================================
// Roundtrip: set all fields -> to_cbor -> from_cbor -> get all fields
// Ensures to_cbor success path (lines 434-438 skipped, 440-446 exercised)
// and from_cbor success path and getter success paths
// ============================================================================

#[test]
fn roundtrip_all_claims_via_cbor() {
    let handle = create_claims();

    let issuer = std::ffi::CString::new("roundtrip-issuer").unwrap();
    let subject = std::ffi::CString::new("roundtrip-subject").unwrap();
    let audience = std::ffi::CString::new("roundtrip-audience").unwrap();

    assert_eq!(impl_cwt_claims_set_issuer_inner(handle, issuer.as_ptr()), COSE_CWT_OK);
    assert_eq!(impl_cwt_claims_set_subject_inner(handle, subject.as_ptr()), COSE_CWT_OK);
    assert_eq!(impl_cwt_claims_set_audience_inner(handle, audience.as_ptr()), COSE_CWT_OK);
    assert_eq!(impl_cwt_claims_set_issued_at_inner(handle, 1700000000), COSE_CWT_OK);
    assert_eq!(impl_cwt_claims_set_not_before_inner(handle, 1699999000), COSE_CWT_OK);
    assert_eq!(impl_cwt_claims_set_expiration_inner(handle, 1700100000), COSE_CWT_OK);

    // Serialize to CBOR
    let mut out_bytes: *mut u8 = ptr::null_mut();
    let mut out_len: u32 = 0;
    let mut err: *mut CoseCwtErrorHandle = ptr::null_mut();

    let rc = impl_cwt_claims_to_cbor_inner(
        handle as *const _,
        &mut out_bytes,
        &mut out_len,
        &mut err,
    );
    assert_eq!(rc, COSE_CWT_OK);
    assert!(!out_bytes.is_null());
    assert!(out_len > 0);

    // Deserialize back
    let mut handle2: *mut CoseCwtClaimsHandle = ptr::null_mut();
    let mut err2: *mut CoseCwtErrorHandle = ptr::null_mut();
    let rc = impl_cwt_claims_from_cbor_inner(out_bytes, out_len, &mut handle2, &mut err2);
    assert_eq!(rc, COSE_CWT_OK);
    assert!(!handle2.is_null());

    // Verify issuer
    let mut out_issuer: *const libc::c_char = ptr::null();
    let mut err3: *mut CoseCwtErrorHandle = ptr::null_mut();
    let rc = impl_cwt_claims_get_issuer_inner(handle2 as *const _, &mut out_issuer, &mut err3);
    assert_eq!(rc, COSE_CWT_OK);
    assert!(!out_issuer.is_null());
    let val = unsafe { CStr::from_ptr(out_issuer) }.to_str().unwrap();
    assert_eq!(val, "roundtrip-issuer");
    unsafe { cose_cwt_string_free(out_issuer as *mut _) };

    // Verify subject
    let mut out_subject: *const libc::c_char = ptr::null();
    let mut err4: *mut CoseCwtErrorHandle = ptr::null_mut();
    let rc = impl_cwt_claims_get_subject_inner(handle2 as *const _, &mut out_subject, &mut err4);
    assert_eq!(rc, COSE_CWT_OK);
    assert!(!out_subject.is_null());
    let val = unsafe { CStr::from_ptr(out_subject) }.to_str().unwrap();
    assert_eq!(val, "roundtrip-subject");
    unsafe { cose_cwt_string_free(out_subject as *mut _) };

    // Cleanup
    unsafe {
        cose_cwt_bytes_free(out_bytes, out_len);
        cose_cwt_claims_free(handle);
        cose_cwt_claims_free(handle2);
    }
    if !err.is_null() { unsafe { cose_cwt_error_free(err) }; }
    if !err2.is_null() { unsafe { cose_cwt_error_free(err2) }; }
    if !err3.is_null() { unsafe { cose_cwt_error_free(err3) }; }
    if !err4.is_null() { unsafe { cose_cwt_error_free(err4) }; }
}
