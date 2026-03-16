// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! FFI tests for CWT claims header operations.
//!
//! Tests uncovered paths in the headers FFI layer including:
//! - CWT claim FFI setters (all claim types)  
//! - Contributor lifecycle
//! - Error handling and null safety
//! - CBOR roundtrip through FFI

use std::ffi::CString;
use std::ptr;

// Import FFI functions
use cose_sign1_headers_ffi::*;

#[test]
fn test_cwt_claims_create_and_free() {
    unsafe {
        let mut handle = ptr::null_mut();
        let mut error = ptr::null_mut();
        let status = cose_cwt_claims_create(&mut handle, &mut error);
        
        assert_eq!(status, COSE_CWT_OK);
        assert!(!handle.is_null());
        
        if !error.is_null() {
            cose_cwt_error_free(error);
        }
        cose_cwt_claims_free(handle);
    }
}

#[test]
fn test_cwt_claims_create_null_param() {
    unsafe {
        let mut error = ptr::null_mut();
        let status = cose_cwt_claims_create(ptr::null_mut(), &mut error);
        assert_eq!(status, COSE_CWT_ERR_NULL_POINTER);
        if !error.is_null() {
            cose_cwt_error_free(error);
        }
    }
}

#[test]
fn test_cwt_claims_set_issuer() {
    unsafe {
        let mut handle = ptr::null_mut();
        let mut error = ptr::null_mut();
        assert_eq!(cose_cwt_claims_create(&mut handle, &mut error), COSE_CWT_OK);
        
        let issuer = CString::new("test-issuer").unwrap();
        let status = cose_cwt_claims_set_issuer(handle, issuer.as_ptr(), &mut error);
        
        assert_eq!(status, COSE_CWT_OK);
        
        if !error.is_null() {
            cose_cwt_error_free(error);
        }
        cose_cwt_claims_free(handle);
    }
}

#[test]
fn test_cwt_claims_set_issuer_null_handle() {
    unsafe {
        let issuer = CString::new("test-issuer").unwrap();
        let mut error = ptr::null_mut();
        let status = cose_cwt_claims_set_issuer(ptr::null_mut(), issuer.as_ptr(), &mut error);
        assert_eq!(status, COSE_CWT_ERR_NULL_POINTER);
        if !error.is_null() {
            cose_cwt_error_free(error);
        }
    }
}

#[test]
fn test_cwt_claims_set_issuer_null_value() {
    unsafe {
        let mut handle = ptr::null_mut();
        let mut error = ptr::null_mut();
        assert_eq!(cose_cwt_claims_create(&mut handle, &mut error), COSE_CWT_OK);
        
        let status = cose_cwt_claims_set_issuer(handle, ptr::null(), &mut error);
        assert_eq!(status, COSE_CWT_ERR_NULL_POINTER);
        
        if !error.is_null() {
            cose_cwt_error_free(error);
        }
        cose_cwt_claims_free(handle);
    }
}

#[test]
fn test_cwt_claims_set_subject() {
    unsafe {
        let mut handle = ptr::null_mut();
        let mut error = ptr::null_mut();
        assert_eq!(cose_cwt_claims_create(&mut handle, &mut error), COSE_CWT_OK);
        
        let subject = CString::new("test.subject").unwrap();
        let status = cose_cwt_claims_set_subject(handle, subject.as_ptr(), &mut error);
        
        assert_eq!(status, COSE_CWT_OK);
        
        if !error.is_null() {
            cose_cwt_error_free(error);
        }
        cose_cwt_claims_free(handle);
    }
}

#[test]
fn test_cwt_claims_set_audience() {
    unsafe {
        let mut handle = ptr::null_mut();
        let mut error = ptr::null_mut();
        assert_eq!(cose_cwt_claims_create(&mut handle, &mut error), COSE_CWT_OK);
        
        let audience = CString::new("test-audience").unwrap();
        let status = cose_cwt_claims_set_audience(handle, audience.as_ptr(), &mut error);
        
        assert_eq!(status, COSE_CWT_OK);
        
        if !error.is_null() {
            cose_cwt_error_free(error);
        }
        cose_cwt_claims_free(handle);
    }
}

#[test]
fn test_cwt_claims_set_expiration() {
    unsafe {
        let mut handle = ptr::null_mut();
        let mut error = ptr::null_mut();
        assert_eq!(cose_cwt_claims_create(&mut handle, &mut error), COSE_CWT_OK);
        
        let exp_time = 1640995200i64; // 2022-01-01 00:00:00 UTC
        let status = cose_cwt_claims_set_expiration(handle, exp_time, &mut error);
        
        assert_eq!(status, COSE_CWT_OK);
        
        if !error.is_null() {
            cose_cwt_error_free(error);
        }
        cose_cwt_claims_free(handle);
    }
}

#[test]
fn test_cwt_claims_set_not_before() {
    unsafe {
        let mut handle = ptr::null_mut();
        let mut error = ptr::null_mut();
        assert_eq!(cose_cwt_claims_create(&mut handle, &mut error), COSE_CWT_OK);
        
        let nbf_time = 1640991600i64; // Earlier timestamp
        let status = cose_cwt_claims_set_not_before(handle, nbf_time, &mut error);
        
        assert_eq!(status, COSE_CWT_OK);
        
        if !error.is_null() {
            cose_cwt_error_free(error);
        }
        cose_cwt_claims_free(handle);
    }
}

#[test]
fn test_cwt_claims_set_issued_at() {
    unsafe {
        let mut handle = ptr::null_mut();
        let mut error = ptr::null_mut();
        assert_eq!(cose_cwt_claims_create(&mut handle, &mut error), COSE_CWT_OK);
        
        let iat_time = 1640993400i64; // Middle timestamp
        let status = cose_cwt_claims_set_issued_at(handle, iat_time, &mut error);
        
        assert_eq!(status, COSE_CWT_OK);
        
        if !error.is_null() {
            cose_cwt_error_free(error);
        }
        cose_cwt_claims_free(handle);
    }
}

#[test]
fn test_cwt_claims_to_cbor() {
    unsafe {
        let mut handle = ptr::null_mut();
        let mut error = ptr::null_mut();
        assert_eq!(cose_cwt_claims_create(&mut handle, &mut error), COSE_CWT_OK);
        
        // Set some claims
        let issuer = CString::new("test-issuer").unwrap();
        assert_eq!(cose_cwt_claims_set_issuer(handle, issuer.as_ptr(), &mut error), COSE_CWT_OK);
        
        let subject = CString::new("test.subject").unwrap();
        assert_eq!(cose_cwt_claims_set_subject(handle, subject.as_ptr(), &mut error), COSE_CWT_OK);
        
        // Convert to CBOR
        let mut out_ptr = ptr::null_mut();
        let mut out_len = 0u32;
        let status = cose_cwt_claims_to_cbor(handle, &mut out_ptr, &mut out_len, &mut error);
        
        assert_eq!(status, COSE_CWT_OK);
        assert!(!out_ptr.is_null());
        assert!(out_len > 0);
        
        // Clean up
        cose_cwt_bytes_free(out_ptr, out_len);
        if !error.is_null() {
            cose_cwt_error_free(error);
        }
        cose_cwt_claims_free(handle);
    }
}

#[test]
fn test_cwt_claims_to_cbor_null_handle() {
    unsafe {
        let mut out_ptr = ptr::null_mut();
        let mut out_len = 0u32;
        let mut error = ptr::null_mut();
        let status = cose_cwt_claims_to_cbor(ptr::null_mut(), &mut out_ptr, &mut out_len, &mut error);
        
        assert_eq!(status, COSE_CWT_ERR_NULL_POINTER);
        if !error.is_null() {
            cose_cwt_error_free(error);
        }
    }
}

#[test]
fn test_cwt_claims_to_cbor_null_out_params() {
    unsafe {
        let mut handle = ptr::null_mut();
        let mut error = ptr::null_mut();
        assert_eq!(cose_cwt_claims_create(&mut handle, &mut error), COSE_CWT_OK);
        
        let mut out_len = 0u32;
        
        // Null out_ptr
        let status = cose_cwt_claims_to_cbor(handle, ptr::null_mut(), &mut out_len, &mut error);
        assert_eq!(status, COSE_CWT_ERR_NULL_POINTER);
        
        // Null out_len
        let mut out_ptr = ptr::null_mut();
        let status = cose_cwt_claims_to_cbor(handle, &mut out_ptr, ptr::null_mut(), &mut error);
        assert_eq!(status, COSE_CWT_ERR_NULL_POINTER);
        
        if !error.is_null() {
            cose_cwt_error_free(error);
        }
        cose_cwt_claims_free(handle);
    }
}

#[test]
fn test_cwt_claims_all_setters_null_handle() {
    unsafe {
        let test_string = CString::new("test").unwrap();
        let mut error = ptr::null_mut();
        
        // Test all setters with null handle
        assert_eq!(cose_cwt_claims_set_issuer(ptr::null_mut(), test_string.as_ptr(), &mut error), COSE_CWT_ERR_NULL_POINTER);
        assert_eq!(cose_cwt_claims_set_subject(ptr::null_mut(), test_string.as_ptr(), &mut error), COSE_CWT_ERR_NULL_POINTER);
        assert_eq!(cose_cwt_claims_set_audience(ptr::null_mut(), test_string.as_ptr(), &mut error), COSE_CWT_ERR_NULL_POINTER);
        assert_eq!(cose_cwt_claims_set_expiration(ptr::null_mut(), 1000, &mut error), COSE_CWT_ERR_NULL_POINTER);
        assert_eq!(cose_cwt_claims_set_not_before(ptr::null_mut(), 500, &mut error), COSE_CWT_ERR_NULL_POINTER);
        assert_eq!(cose_cwt_claims_set_issued_at(ptr::null_mut(), 750, &mut error), COSE_CWT_ERR_NULL_POINTER);
        
        if !error.is_null() {
            cose_cwt_error_free(error);
        }
    }
}

#[test]
fn test_cwt_claims_comprehensive_workflow() {
    unsafe {
        let mut handle = ptr::null_mut();
        let mut error = ptr::null_mut();
        assert_eq!(cose_cwt_claims_create(&mut handle, &mut error), COSE_CWT_OK);
        
        // Set all standard claims
        let issuer = CString::new("comprehensive-issuer").unwrap();
        assert_eq!(cose_cwt_claims_set_issuer(handle, issuer.as_ptr(), &mut error), COSE_CWT_OK);
        
        let subject = CString::new("comprehensive.subject").unwrap();
        assert_eq!(cose_cwt_claims_set_subject(handle, subject.as_ptr(), &mut error), COSE_CWT_OK);
        
        let audience = CString::new("comprehensive-audience").unwrap();
        assert_eq!(cose_cwt_claims_set_audience(handle, audience.as_ptr(), &mut error), COSE_CWT_OK);
        
        assert_eq!(cose_cwt_claims_set_expiration(handle, 2000000000, &mut error), COSE_CWT_OK);
        assert_eq!(cose_cwt_claims_set_not_before(handle, 1500000000, &mut error), COSE_CWT_OK);
        assert_eq!(cose_cwt_claims_set_issued_at(handle, 1600000000, &mut error), COSE_CWT_OK);
        
        // Convert to CBOR
        let mut out_ptr = ptr::null_mut();
        let mut out_len = 0u32;
        let status = cose_cwt_claims_to_cbor(handle, &mut out_ptr, &mut out_len, &mut error);
        
        assert_eq!(status, COSE_CWT_OK);
        assert!(!out_ptr.is_null());
        assert!(out_len > 0);
        
        // CBOR should contain all the claims we set
        assert!(out_len > 20); // Should be reasonably large with all the claims
        
        // Clean up
        cose_cwt_bytes_free(out_ptr, out_len);
        if !error.is_null() {
            cose_cwt_error_free(error);
        }
        cose_cwt_claims_free(handle);
    }
}

#[test]
fn test_cwt_claims_free_null() {
    unsafe {
        // Should handle null pointer gracefully
        cose_cwt_claims_free(ptr::null_mut());
    }
}

#[test]
fn test_cwt_bytes_free_null() {
    unsafe {
        // Should handle null pointer gracefully
        cose_cwt_bytes_free(ptr::null_mut(), 0);
    }
}

#[test]
fn test_cwt_string_free_null() {
    unsafe {
        // Should handle null pointer gracefully  
        cose_cwt_string_free(ptr::null_mut());
    }
}

#[test]
fn test_cwt_claims_zero_length_strings() {
    unsafe {
        let mut handle = ptr::null_mut();
        let mut error = ptr::null_mut();
        assert_eq!(cose_cwt_claims_create(&mut handle, &mut error), COSE_CWT_OK);
        
        // Test empty strings
        let empty_string = CString::new("").unwrap();
        assert_eq!(cose_cwt_claims_set_issuer(handle, empty_string.as_ptr(), &mut error), COSE_CWT_OK);
        assert_eq!(cose_cwt_claims_set_subject(handle, empty_string.as_ptr(), &mut error), COSE_CWT_OK);
        assert_eq!(cose_cwt_claims_set_audience(handle, empty_string.as_ptr(), &mut error), COSE_CWT_OK);
        
        if !error.is_null() {
            cose_cwt_error_free(error);
        }
        cose_cwt_claims_free(handle);
    }
}

#[test]
fn test_cwt_claims_get_issuer() {
    unsafe {
        let mut handle = ptr::null_mut();
        let mut error = ptr::null_mut();
        assert_eq!(cose_cwt_claims_create(&mut handle, &mut error), COSE_CWT_OK);
        
        // Set issuer
        let issuer = CString::new("test-issuer").unwrap();
        assert_eq!(cose_cwt_claims_set_issuer(handle, issuer.as_ptr(), &mut error), COSE_CWT_OK);
        
        // Get issuer back
        let mut out_issuer: *const libc::c_char = ptr::null();
        let status = cose_cwt_claims_get_issuer(handle, &mut out_issuer, &mut error);
        assert_eq!(status, COSE_CWT_OK);
        
        if !out_issuer.is_null() {
            let retrieved = std::ffi::CStr::from_ptr(out_issuer);
            assert_eq!(retrieved.to_str().unwrap(), "test-issuer");
            cose_cwt_string_free(out_issuer as *mut libc::c_char);
        }
        
        if !error.is_null() {
            cose_cwt_error_free(error);
        }
        cose_cwt_claims_free(handle);
    }
}

#[test]
fn test_cwt_claims_get_subject() {
    unsafe {
        let mut handle = ptr::null_mut();
        let mut error = ptr::null_mut();
        assert_eq!(cose_cwt_claims_create(&mut handle, &mut error), COSE_CWT_OK);
        
        // Set subject
        let subject = CString::new("test.subject").unwrap();
        assert_eq!(cose_cwt_claims_set_subject(handle, subject.as_ptr(), &mut error), COSE_CWT_OK);
        
        // Get subject back
        let mut out_subject: *const libc::c_char = ptr::null();
        let status = cose_cwt_claims_get_subject(handle, &mut out_subject, &mut error);
        assert_eq!(status, COSE_CWT_OK);
        
        if !out_subject.is_null() {
            let retrieved = std::ffi::CStr::from_ptr(out_subject);
            assert_eq!(retrieved.to_str().unwrap(), "test.subject");
            cose_cwt_string_free(out_subject as *mut libc::c_char);
        }
        
        if !error.is_null() {
            cose_cwt_error_free(error);
        }
        cose_cwt_claims_free(handle);
    }
}

#[test]
fn test_cwt_claims_from_cbor_roundtrip() {
    unsafe {
        let mut handle = ptr::null_mut();
        let mut error = ptr::null_mut();
        assert_eq!(cose_cwt_claims_create(&mut handle, &mut error), COSE_CWT_OK);
        
        // Set some claims
        let issuer = CString::new("roundtrip-issuer").unwrap();
        assert_eq!(cose_cwt_claims_set_issuer(handle, issuer.as_ptr(), &mut error), COSE_CWT_OK);
        
        let subject = CString::new("roundtrip.subject").unwrap();
        assert_eq!(cose_cwt_claims_set_subject(handle, subject.as_ptr(), &mut error), COSE_CWT_OK);
        
        // Convert to CBOR
        let mut cbor_ptr = ptr::null_mut();
        let mut cbor_len = 0u32;
        assert_eq!(cose_cwt_claims_to_cbor(handle, &mut cbor_ptr, &mut cbor_len, &mut error), COSE_CWT_OK);
        
        // Parse CBOR back into claims
        let mut handle2 = ptr::null_mut();
        let status = cose_cwt_claims_from_cbor(cbor_ptr, cbor_len, &mut handle2, &mut error);
        assert_eq!(status, COSE_CWT_OK);
        assert!(!handle2.is_null());
        
        // Verify the claims match
        let mut out_issuer: *const libc::c_char = ptr::null();
        assert_eq!(cose_cwt_claims_get_issuer(handle2, &mut out_issuer, &mut error), COSE_CWT_OK);
        if !out_issuer.is_null() {
            let retrieved = std::ffi::CStr::from_ptr(out_issuer);
            assert_eq!(retrieved.to_str().unwrap(), "roundtrip-issuer");
            cose_cwt_string_free(out_issuer as *mut libc::c_char);
        }
        
        // Clean up
        cose_cwt_bytes_free(cbor_ptr, cbor_len);
        if !error.is_null() {
            cose_cwt_error_free(error);
        }
        cose_cwt_claims_free(handle);
        cose_cwt_claims_free(handle2);
    }
}

#[test]
fn test_cwt_error_handling() {
    unsafe {
        let mut error = ptr::null_mut();
        
        // Trigger an error
        let status = cose_cwt_claims_create(ptr::null_mut(), &mut error);
        assert_eq!(status, COSE_CWT_ERR_NULL_POINTER);
        
        // Error might or might not be set depending on implementation
        if !error.is_null() {
            // Get error code
            let code = cose_cwt_error_code(error);
            assert_eq!(code, COSE_CWT_ERR_NULL_POINTER);
            
            // Get error message - returns directly, not via out param
            let msg_ptr = cose_cwt_error_message(error);
            
            if !msg_ptr.is_null() {
                cose_cwt_string_free(msg_ptr);
            }
            
            cose_cwt_error_free(error);
        }
    }
}
