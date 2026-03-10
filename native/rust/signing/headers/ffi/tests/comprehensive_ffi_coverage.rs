//! Comprehensive FFI test coverage for headers_ffi functions.

use std::ptr;
use std::ffi::{CStr, CString};
use cose_sign1_headers_ffi::*;

// Helper macro for testing FFI function null safety
macro_rules! test_null_safety {
    ($func:ident, $($args:expr),*) => {
        unsafe {
            let result = $func($($args),*);
            assert_ne!(result, COSE_CWT_OK);
        }
    };
}

#[test]
fn test_abi_version() {
    let version = cose_cwt_claims_abi_version();
    assert_eq!(version, 1);
}

#[test]
fn test_claims_create() {
    let mut handle: *mut CoseCwtClaimsHandle = ptr::null_mut();
    let mut error: *mut CoseCwtErrorHandle = ptr::null_mut();
    
    unsafe {
        let result = cose_cwt_claims_create(&mut handle, &mut error);
        assert_eq!(result, COSE_CWT_OK);
        assert!(!handle.is_null());
        assert!(error.is_null());
        
        cose_cwt_claims_free(handle);
    }
}

#[test]
fn test_claims_create_null_handle() {
    let mut error: *mut CoseCwtErrorHandle = ptr::null_mut();
    
    unsafe {
        let result = cose_cwt_claims_create(ptr::null_mut(), &mut error);
        assert_eq!(result, COSE_CWT_ERR_NULL_POINTER);
        assert!(!error.is_null());
        
        cose_cwt_error_free(error);
    }
}

#[test]
fn test_claims_set_issuer() {
    let mut handle: *mut CoseCwtClaimsHandle = ptr::null_mut();
    let mut error: *mut CoseCwtErrorHandle = ptr::null_mut();
    
    unsafe {
        // Create claims
        let result = cose_cwt_claims_create(&mut handle, &mut error);
        assert_eq!(result, COSE_CWT_OK);
        
        // Set issuer
        let issuer = CString::new("test-issuer").unwrap();
        let result = cose_cwt_claims_set_issuer(handle, issuer.as_ptr(), &mut error);
        assert_eq!(result, COSE_CWT_OK);
        assert!(error.is_null());
        
        cose_cwt_claims_free(handle);
    }
}

#[test]
fn test_claims_set_issuer_null_handle() {
    let mut error: *mut CoseCwtErrorHandle = ptr::null_mut();
    let issuer = CString::new("test-issuer").unwrap();
    
    unsafe {
        let result = cose_cwt_claims_set_issuer(ptr::null_mut(), issuer.as_ptr(), &mut error);
        assert_eq!(result, COSE_CWT_ERR_NULL_POINTER);
        assert!(!error.is_null());
        
        cose_cwt_error_free(error);
    }
}

#[test]
fn test_claims_set_issuer_null_issuer() {
    let mut handle: *mut CoseCwtClaimsHandle = ptr::null_mut();
    let mut error: *mut CoseCwtErrorHandle = ptr::null_mut();
    
    unsafe {
        let result = cose_cwt_claims_create(&mut handle, &mut error);
        assert_eq!(result, COSE_CWT_OK);
        
        let result = cose_cwt_claims_set_issuer(handle, ptr::null(), &mut error);
        assert_eq!(result, COSE_CWT_ERR_NULL_POINTER);
        assert!(!error.is_null());
        
        cose_cwt_error_free(error);
        cose_cwt_claims_free(handle);
    }
}

#[test]
fn test_claims_set_subject() {
    let mut handle: *mut CoseCwtClaimsHandle = ptr::null_mut();
    let mut error: *mut CoseCwtErrorHandle = ptr::null_mut();
    
    unsafe {
        let result = cose_cwt_claims_create(&mut handle, &mut error);
        assert_eq!(result, COSE_CWT_OK);
        
        let subject = CString::new("test-subject").unwrap();
        let result = cose_cwt_claims_set_subject(handle, subject.as_ptr(), &mut error);
        assert_eq!(result, COSE_CWT_OK);
        assert!(error.is_null());
        
        cose_cwt_claims_free(handle);
    }
}

#[test]
fn test_claims_set_issued_at() {
    let mut handle: *mut CoseCwtClaimsHandle = ptr::null_mut();
    let mut error: *mut CoseCwtErrorHandle = ptr::null_mut();
    
    unsafe {
        let result = cose_cwt_claims_create(&mut handle, &mut error);
        assert_eq!(result, COSE_CWT_OK);
        
        let result = cose_cwt_claims_set_issued_at(handle, 1640995200, &mut error);
        assert_eq!(result, COSE_CWT_OK);
        assert!(error.is_null());
        
        cose_cwt_claims_free(handle);
    }
}

#[test]
fn test_claims_set_not_before() {
    let mut handle: *mut CoseCwtClaimsHandle = ptr::null_mut();
    let mut error: *mut CoseCwtErrorHandle = ptr::null_mut();
    
    unsafe {
        let result = cose_cwt_claims_create(&mut handle, &mut error);
        assert_eq!(result, COSE_CWT_OK);
        
        let result = cose_cwt_claims_set_not_before(handle, 1640995200, &mut error);
        assert_eq!(result, COSE_CWT_OK);
        assert!(error.is_null());
        
        cose_cwt_claims_free(handle);
    }
}

#[test]
fn test_claims_set_expiration() {
    let mut handle: *mut CoseCwtClaimsHandle = ptr::null_mut();
    let mut error: *mut CoseCwtErrorHandle = ptr::null_mut();
    
    unsafe {
        let result = cose_cwt_claims_create(&mut handle, &mut error);
        assert_eq!(result, COSE_CWT_OK);
        
        let result = cose_cwt_claims_set_expiration(handle, 1672531200, &mut error);
        assert_eq!(result, COSE_CWT_OK);
        assert!(error.is_null());
        
        cose_cwt_claims_free(handle);
    }
}

#[test]
fn test_claims_set_audience() {
    let mut handle: *mut CoseCwtClaimsHandle = ptr::null_mut();
    let mut error: *mut CoseCwtErrorHandle = ptr::null_mut();
    
    unsafe {
        let result = cose_cwt_claims_create(&mut handle, &mut error);
        assert_eq!(result, COSE_CWT_OK);
        
        let audience = CString::new("test-audience").unwrap();
        let result = cose_cwt_claims_set_audience(handle, audience.as_ptr(), &mut error);
        assert_eq!(result, COSE_CWT_OK);
        assert!(error.is_null());
        
        cose_cwt_claims_free(handle);
    }
}

#[test]
fn test_claims_to_cbor() {
    let mut handle: *mut CoseCwtClaimsHandle = ptr::null_mut();
    let mut error: *mut CoseCwtErrorHandle = ptr::null_mut();
    
    unsafe {
        let result = cose_cwt_claims_create(&mut handle, &mut error);
        assert_eq!(result, COSE_CWT_OK);
        
        // Set some claims
        let issuer = CString::new("test-issuer").unwrap();
        let result = cose_cwt_claims_set_issuer(handle, issuer.as_ptr(), &mut error);
        assert_eq!(result, COSE_CWT_OK);
        
        // Convert to CBOR
        let mut cbor_ptr: *mut u8 = ptr::null_mut();
        let mut cbor_len: u32 = 0;
        let result = cose_cwt_claims_to_cbor(handle, &mut cbor_ptr, &mut cbor_len, &mut error);
        assert_eq!(result, COSE_CWT_OK);
        assert!(!cbor_ptr.is_null());
        assert!(cbor_len > 0);
        assert!(error.is_null());
        
        cose_cwt_bytes_free(cbor_ptr, cbor_len);
        cose_cwt_claims_free(handle);
    }
}

#[test]
fn test_claims_from_cbor() {
    let mut handle: *mut CoseCwtClaimsHandle = ptr::null_mut();
    let mut error: *mut CoseCwtErrorHandle = ptr::null_mut();
    
    unsafe {
        // Create and populate claims first
        let result = cose_cwt_claims_create(&mut handle, &mut error);
        assert_eq!(result, COSE_CWT_OK);
        
        let issuer = CString::new("test-issuer").unwrap();
        let result = cose_cwt_claims_set_issuer(handle, issuer.as_ptr(), &mut error);
        assert_eq!(result, COSE_CWT_OK);
        
        // Convert to CBOR
        let mut cbor_ptr: *mut u8 = ptr::null_mut();
        let mut cbor_len: u32 = 0;
        let result = cose_cwt_claims_to_cbor(handle, &mut cbor_ptr, &mut cbor_len, &mut error);
        assert_eq!(result, COSE_CWT_OK);
        
        cose_cwt_claims_free(handle);
        
        // Create new claims from CBOR
        let mut new_handle: *mut CoseCwtClaimsHandle = ptr::null_mut();
        let result = cose_cwt_claims_from_cbor(cbor_ptr, cbor_len, &mut new_handle, &mut error);
        assert_eq!(result, COSE_CWT_OK);
        assert!(!new_handle.is_null());
        assert!(error.is_null());
        
        cose_cwt_bytes_free(cbor_ptr, cbor_len);
        cose_cwt_claims_free(new_handle);
    }
}

#[test]
fn test_claims_get_issuer() {
    let mut handle: *mut CoseCwtClaimsHandle = ptr::null_mut();
    let mut error: *mut CoseCwtErrorHandle = ptr::null_mut();
    
    unsafe {
        let result = cose_cwt_claims_create(&mut handle, &mut error);
        assert_eq!(result, COSE_CWT_OK);
        
        let issuer_text = "test-issuer";
        let issuer = CString::new(issuer_text).unwrap();
        let result = cose_cwt_claims_set_issuer(handle, issuer.as_ptr(), &mut error);
        assert_eq!(result, COSE_CWT_OK);
        
        // Get issuer back
        let mut issuer_ptr: *const libc::c_char = ptr::null();
        let result = cose_cwt_claims_get_issuer(handle, &mut issuer_ptr, &mut error);
        assert_eq!(result, COSE_CWT_OK);
        assert!(!issuer_ptr.is_null());
        assert!(error.is_null());
        
        let retrieved = CStr::from_ptr(issuer_ptr).to_str().unwrap();
        assert_eq!(retrieved, issuer_text);
        
        cose_cwt_string_free(issuer_ptr as *mut libc::c_char);
        cose_cwt_claims_free(handle);
    }
}

#[test]
fn test_claims_get_subject() {
    let mut handle: *mut CoseCwtClaimsHandle = ptr::null_mut();
    let mut error: *mut CoseCwtErrorHandle = ptr::null_mut();
    
    unsafe {
        let result = cose_cwt_claims_create(&mut handle, &mut error);
        assert_eq!(result, COSE_CWT_OK);
        
        let subject_text = "test-subject";
        let subject = CString::new(subject_text).unwrap();
        let result = cose_cwt_claims_set_subject(handle, subject.as_ptr(), &mut error);
        assert_eq!(result, COSE_CWT_OK);
        
        // Get subject back
        let mut subject_ptr: *const libc::c_char = ptr::null();
        let result = cose_cwt_claims_get_subject(handle, &mut subject_ptr, &mut error);
        assert_eq!(result, COSE_CWT_OK);
        assert!(!subject_ptr.is_null());
        assert!(error.is_null());
        
        let retrieved = CStr::from_ptr(subject_ptr).to_str().unwrap();
        assert_eq!(retrieved, subject_text);
        
        cose_cwt_string_free(subject_ptr as *mut libc::c_char);
        cose_cwt_claims_free(handle);
    }
}

#[test]
fn test_error_handling() {
    let mut error: *mut CoseCwtErrorHandle = ptr::null_mut();
    
    // Create a null pointer error
    unsafe {
        let result = cose_cwt_claims_create(ptr::null_mut(), &mut error);
        assert_eq!(result, COSE_CWT_ERR_NULL_POINTER);
        assert!(!error.is_null());
        
        // Test error code
        let code = cose_cwt_error_code(error);
        assert_eq!(code, COSE_CWT_ERR_NULL_POINTER);
        
        // Test error message
        let msg_ptr = cose_cwt_error_message(error);
        assert!(!msg_ptr.is_null());
        
        let message = CStr::from_ptr(msg_ptr).to_str().unwrap();
        assert!(!message.is_empty());
        
        cose_cwt_string_free(msg_ptr);
        cose_cwt_error_free(error);
    }
}

#[test]
fn test_bytes_free_null_safety() {
    unsafe {
        // Should not crash with null pointer
        cose_cwt_bytes_free(ptr::null_mut(), 0);
    }
}

#[test]
fn test_claims_free_null_safety() {
    unsafe {
        // Should not crash with null pointer
        cose_cwt_claims_free(ptr::null_mut());
    }
}

#[test]
fn test_error_free_null_safety() {
    unsafe {
        // Should not crash with null pointer
        cose_cwt_error_free(ptr::null_mut());
    }
}

#[test]
fn test_string_free_null_safety() {
    unsafe {
        // Should not crash with null pointer
        cose_cwt_string_free(ptr::null_mut());
    }
}

#[test]
fn test_claims_roundtrip_with_all_fields() {
    let mut handle: *mut CoseCwtClaimsHandle = ptr::null_mut();
    let mut error: *mut CoseCwtErrorHandle = ptr::null_mut();
    
    unsafe {
        // Create and populate all fields
        let result = cose_cwt_claims_create(&mut handle, &mut error);
        assert_eq!(result, COSE_CWT_OK);
        
        let issuer = CString::new("test-issuer").unwrap();
        let subject = CString::new("test-subject").unwrap();
        let audience = CString::new("test-audience").unwrap();
        
        assert_eq!(cose_cwt_claims_set_issuer(handle, issuer.as_ptr(), &mut error), COSE_CWT_OK);
        assert_eq!(cose_cwt_claims_set_subject(handle, subject.as_ptr(), &mut error), COSE_CWT_OK);
        assert_eq!(cose_cwt_claims_set_audience(handle, audience.as_ptr(), &mut error), COSE_CWT_OK);
        assert_eq!(cose_cwt_claims_set_issued_at(handle, 1640995200, &mut error), COSE_CWT_OK);
        assert_eq!(cose_cwt_claims_set_not_before(handle, 1640995200, &mut error), COSE_CWT_OK);
        assert_eq!(cose_cwt_claims_set_expiration(handle, 1672531200, &mut error), COSE_CWT_OK);
        
        // Convert to CBOR and back
        let mut cbor_ptr: *mut u8 = ptr::null_mut();
        let mut cbor_len: u32 = 0;
        let result = cose_cwt_claims_to_cbor(handle, &mut cbor_ptr, &mut cbor_len, &mut error);
        assert_eq!(result, COSE_CWT_OK);
        
        cose_cwt_claims_free(handle);
        
        // Recreate from CBOR
        let mut new_handle: *mut CoseCwtClaimsHandle = ptr::null_mut();
        let result = cose_cwt_claims_from_cbor(cbor_ptr, cbor_len, &mut new_handle, &mut error);
        assert_eq!(result, COSE_CWT_OK);
        
        // Verify fields
        let mut issuer_ptr: *const libc::c_char = ptr::null();
        let result = cose_cwt_claims_get_issuer(new_handle, &mut issuer_ptr, &mut error);
        assert_eq!(result, COSE_CWT_OK);
        assert_eq!(CStr::from_ptr(issuer_ptr).to_str().unwrap(), "test-issuer");
        
        let mut subject_ptr: *const libc::c_char = ptr::null();
        let result = cose_cwt_claims_get_subject(new_handle, &mut subject_ptr, &mut error);
        assert_eq!(result, COSE_CWT_OK);
        assert_eq!(CStr::from_ptr(subject_ptr).to_str().unwrap(), "test-subject");
        
        cose_cwt_string_free(issuer_ptr as *mut libc::c_char);
        cose_cwt_string_free(subject_ptr as *mut libc::c_char);
        cose_cwt_bytes_free(cbor_ptr, cbor_len);
        cose_cwt_claims_free(new_handle);
    }
}

#[test]
fn test_from_cbor_invalid_data() {
    let mut handle: *mut CoseCwtClaimsHandle = ptr::null_mut();
    let mut error: *mut CoseCwtErrorHandle = ptr::null_mut();
    
    unsafe {
        let invalid_cbor = vec![0xFF, 0xEE, 0xDD]; // Invalid CBOR
        let result = cose_cwt_claims_from_cbor(
            invalid_cbor.as_ptr() as *const u8,
            invalid_cbor.len() as u32,
            &mut handle,
            &mut error
        );
        assert_ne!(result, COSE_CWT_OK);
        assert!(!error.is_null());
        assert!(handle.is_null());
        
        cose_cwt_error_free(error);
    }
}