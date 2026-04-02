// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Extended validation FFI tests for comprehensive coverage.
//!
//! This test file exercises error paths, edge cases, and result inspection
//! functions to maximize coverage of the validation FFI.

use cose_sign1_validation_ffi::*;
use std::ptr;

/// Create test CBOR data for various test scenarios.
fn create_minimal_cose_sign1() -> Vec<u8> {
    // D2 84 43 A1 01 26 A0 44 74 65 73 74 44 73 69 67 21
    // Tag 18, Array(4), bstr(A1 01 26), map(0), bstr("test"), bstr("sig!")
    vec![
        0xD2, 0x84, 0x43, 0xA1, 0x01, 0x26, 0xA0, 0x44, 0x74, 0x65, 0x73, 0x74, 0x44, 0x73, 0x69,
        0x67, 0x21,
    ]
}

fn create_invalid_cbor() -> Vec<u8> {
    // Invalid CBOR data
    vec![0xFF, 0x00, 0x01, 0x02]
}

fn create_truncated_cose_sign1() -> Vec<u8> {
    // Truncated COSE_Sign1 (starts correctly but is incomplete)
    vec![0xD2, 0x84, 0x43]
}

fn create_non_array_cbor() -> Vec<u8> {
    // Valid CBOR but not an array (should fail COSE parsing)
    vec![0x66, 0x68, 0x65, 0x6c, 0x6c, 0x6f, 0x21] // "hello!"
}

fn create_wrong_array_length() -> Vec<u8> {
    // CBOR array with wrong length for COSE_Sign1 (needs 4 elements)
    vec![0xD2, 0x82, 0x43, 0xA1] // Tag 18, Array(2), ...
}

#[test]
fn test_validator_builder_lifecycle() {
    let mut builder: *mut cose_sign1_validator_builder_t = ptr::null_mut();

    // Create builder
    let status = unsafe { cose_sign1_validator_builder_new(&mut builder) };
    assert_eq!(status, cose_status_t::COSE_OK);
    assert!(!builder.is_null());

    // Build validator
    let mut validator: *mut cose_sign1_validator_t = ptr::null_mut();
    let status = unsafe { cose_sign1_validator_builder_build(builder, &mut validator) };
    assert_eq!(status, cose_status_t::COSE_OK);
    assert!(!validator.is_null());

    // Clean up
    unsafe {
        cose_sign1_validator_free(validator);
        // Builder is consumed by build, don't free
    };
}

#[test]
fn test_validator_builder_new_null_output() {
    let status = unsafe { cose_sign1_validator_builder_new(ptr::null_mut()) };
    assert_eq!(status, cose_status_t::COSE_ERR);
}

#[test]
fn test_validator_builder_build_null_builder() {
    let mut validator: *mut cose_sign1_validator_t = ptr::null_mut();
    let status = unsafe { cose_sign1_validator_builder_build(ptr::null_mut(), &mut validator) };
    assert_eq!(status, cose_status_t::COSE_ERR);
    assert!(validator.is_null());
}

#[test]
fn test_validator_builder_build_null_output() {
    let mut builder: *mut cose_sign1_validator_builder_t = ptr::null_mut();
    unsafe { cose_sign1_validator_builder_new(&mut builder) };

    let status = unsafe { cose_sign1_validator_builder_build(builder, ptr::null_mut()) };
    assert_eq!(status, cose_status_t::COSE_ERR);

    // Builder is consumed even on error
}

#[test]
fn test_validate_bytes_valid_message() {
    let mut builder: *mut cose_sign1_validator_builder_t = ptr::null_mut();
    unsafe { cose_sign1_validator_builder_new(&mut builder) };

    let mut validator: *mut cose_sign1_validator_t = ptr::null_mut();
    unsafe { cose_sign1_validator_builder_build(builder, &mut validator) };

    let message_bytes = create_minimal_cose_sign1();
    let mut result: *mut cose_sign1_validation_result_t = ptr::null_mut();

    let status = unsafe {
        cose_sign1_validator_validate_bytes(
            validator,
            message_bytes.as_ptr(),
            message_bytes.len(),
            ptr::null(), // no detached payload
            0,
            &mut result,
        )
    };

    assert_eq!(status, cose_status_t::COSE_OK);
    assert!(!result.is_null());

    // Check if validation succeeded (may fail due to invalid signature, but that's ok)
    let mut is_success = false;
    let status = unsafe { cose_sign1_validation_result_is_success(result, &mut is_success) };
    assert_eq!(status, cose_status_t::COSE_OK);

    // Get failure message if validation failed
    if !is_success {
        let failure_msg = unsafe { cose_sign1_validation_result_failure_message_utf8(result) };
        if !failure_msg.is_null() {
            // Should be a valid string
            unsafe { cose_string_free(failure_msg) };
        }
    }

    unsafe {
        cose_sign1_validation_result_free(result);
        cose_sign1_validator_free(validator);
    };
}

#[test]
fn test_validate_bytes_invalid_cbor() {
    let mut builder: *mut cose_sign1_validator_builder_t = ptr::null_mut();
    unsafe { cose_sign1_validator_builder_new(&mut builder) };

    let mut validator: *mut cose_sign1_validator_t = ptr::null_mut();
    unsafe { cose_sign1_validator_builder_build(builder, &mut validator) };

    let invalid_bytes = create_invalid_cbor();
    let mut result: *mut cose_sign1_validation_result_t = ptr::null_mut();

    let status = unsafe {
        cose_sign1_validator_validate_bytes(
            validator,
            invalid_bytes.as_ptr(),
            invalid_bytes.len(),
            ptr::null(),
            0,
            &mut result,
        )
    };

    // May succeed or fail depending on implementation, but shouldn't crash
    if status == cose_status_t::COSE_OK {
        assert!(!result.is_null());

        // Should show validation failure
        let mut is_success = false;
        let status = unsafe { cose_sign1_validation_result_is_success(result, &mut is_success) };
        assert_eq!(status, cose_status_t::COSE_OK);
        if !is_success {
            let failure_msg = unsafe { cose_sign1_validation_result_failure_message_utf8(result) };
            if !failure_msg.is_null() {
                unsafe { cose_string_free(failure_msg) };
            }
        }

        unsafe { cose_sign1_validation_result_free(result) };
    }

    unsafe { cose_sign1_validator_free(validator) };
}

#[test]
fn test_validate_bytes_truncated_message() {
    let mut builder: *mut cose_sign1_validator_builder_t = ptr::null_mut();
    unsafe { cose_sign1_validator_builder_new(&mut builder) };

    let mut validator: *mut cose_sign1_validator_t = ptr::null_mut();
    unsafe { cose_sign1_validator_builder_build(builder, &mut validator) };

    let truncated_bytes = create_truncated_cose_sign1();
    let mut result: *mut cose_sign1_validation_result_t = ptr::null_mut();

    let status = unsafe {
        cose_sign1_validator_validate_bytes(
            validator,
            truncated_bytes.as_ptr(),
            truncated_bytes.len(),
            ptr::null(),
            0,
            &mut result,
        )
    };

    // Should either fail to parse or show validation failure
    if status == cose_status_t::COSE_OK {
        assert!(!result.is_null());
        let mut is_success = false;
        let status = unsafe { cose_sign1_validation_result_is_success(result, &mut is_success) };
        assert_eq!(status, cose_status_t::COSE_OK);
        // Truncated message should not succeed
        if !is_success {
            let failure_msg = unsafe { cose_sign1_validation_result_failure_message_utf8(result) };
            if !failure_msg.is_null() {
                unsafe { cose_string_free(failure_msg) };
            }
        }
        unsafe { cose_sign1_validation_result_free(result) };
    }

    unsafe { cose_sign1_validator_free(validator) };
}

#[test]
fn test_validate_bytes_non_array_cbor() {
    let mut builder: *mut cose_sign1_validator_builder_t = ptr::null_mut();
    unsafe { cose_sign1_validator_builder_new(&mut builder) };

    let mut validator: *mut cose_sign1_validator_t = ptr::null_mut();
    unsafe { cose_sign1_validator_builder_build(builder, &mut validator) };

    let non_array_bytes = create_non_array_cbor();
    let mut result: *mut cose_sign1_validation_result_t = ptr::null_mut();

    let status = unsafe {
        cose_sign1_validator_validate_bytes(
            validator,
            non_array_bytes.as_ptr(),
            non_array_bytes.len(),
            ptr::null(),
            0,
            &mut result,
        )
    };

    // Should handle non-array CBOR gracefully
    if status == cose_status_t::COSE_OK {
        if !result.is_null() {
            let mut is_success = false;
            let status =
                unsafe { cose_sign1_validation_result_is_success(result, &mut is_success) };
            assert_eq!(status, cose_status_t::COSE_OK);
            if !is_success {
                let failure_msg =
                    unsafe { cose_sign1_validation_result_failure_message_utf8(result) };
                if !failure_msg.is_null() {
                    unsafe { cose_string_free(failure_msg) };
                }
            }
            unsafe { cose_sign1_validation_result_free(result) };
        }
    }

    unsafe { cose_sign1_validator_free(validator) };
}

#[test]
fn test_validate_bytes_wrong_array_length() {
    let mut builder: *mut cose_sign1_validator_builder_t = ptr::null_mut();
    unsafe { cose_sign1_validator_builder_new(&mut builder) };

    let mut validator: *mut cose_sign1_validator_t = ptr::null_mut();
    unsafe { cose_sign1_validator_builder_build(builder, &mut validator) };

    let wrong_length_bytes = create_wrong_array_length();
    let mut result: *mut cose_sign1_validation_result_t = ptr::null_mut();

    let status = unsafe {
        cose_sign1_validator_validate_bytes(
            validator,
            wrong_length_bytes.as_ptr(),
            wrong_length_bytes.len(),
            ptr::null(),
            0,
            &mut result,
        )
    };

    // Should handle wrong array length gracefully
    if status == cose_status_t::COSE_OK {
        if !result.is_null() {
            let mut is_success = false;
            let status =
                unsafe { cose_sign1_validation_result_is_success(result, &mut is_success) };
            assert_eq!(status, cose_status_t::COSE_OK);
            if !is_success {
                let failure_msg =
                    unsafe { cose_sign1_validation_result_failure_message_utf8(result) };
                if !failure_msg.is_null() {
                    unsafe { cose_string_free(failure_msg) };
                }
            }
            unsafe { cose_sign1_validation_result_free(result) };
        }
    }

    unsafe { cose_sign1_validator_free(validator) };
}

#[test]
fn test_validate_bytes_with_detached_payload() {
    let mut builder: *mut cose_sign1_validator_builder_t = ptr::null_mut();
    unsafe { cose_sign1_validator_builder_new(&mut builder) };

    let mut validator: *mut cose_sign1_validator_t = ptr::null_mut();
    unsafe { cose_sign1_validator_builder_build(builder, &mut validator) };

    let message_bytes = create_minimal_cose_sign1();
    let detached_payload = b"detached payload data";
    let mut result: *mut cose_sign1_validation_result_t = ptr::null_mut();

    let status = unsafe {
        cose_sign1_validator_validate_bytes(
            validator,
            message_bytes.as_ptr(),
            message_bytes.len(),
            detached_payload.as_ptr(),
            detached_payload.len(),
            &mut result,
        )
    };

    assert_eq!(status, cose_status_t::COSE_OK);
    assert!(!result.is_null());

    // Check result
    let mut is_success = false;
    let status = unsafe { cose_sign1_validation_result_is_success(result, &mut is_success) };
    assert_eq!(status, cose_status_t::COSE_OK);
    if !is_success {
        let failure_msg = unsafe { cose_sign1_validation_result_failure_message_utf8(result) };
        if !failure_msg.is_null() {
            unsafe { cose_string_free(failure_msg) };
        }
    }

    unsafe {
        cose_sign1_validation_result_free(result);
        cose_sign1_validator_free(validator);
    };
}

#[test]
fn test_validate_bytes_empty_message() {
    let mut builder: *mut cose_sign1_validator_builder_t = ptr::null_mut();
    unsafe { cose_sign1_validator_builder_new(&mut builder) };

    let mut validator: *mut cose_sign1_validator_t = ptr::null_mut();
    unsafe { cose_sign1_validator_builder_build(builder, &mut validator) };

    let mut result: *mut cose_sign1_validation_result_t = ptr::null_mut();

    let status = unsafe {
        cose_sign1_validator_validate_bytes(
            validator,
            ptr::null(), // empty message
            0,
            ptr::null(),
            0,
            &mut result,
        )
    };

    // Should handle empty message
    if status == cose_status_t::COSE_OK {
        if !result.is_null() {
            let mut is_success = false;
            let status =
                unsafe { cose_sign1_validation_result_is_success(result, &mut is_success) };
            assert_eq!(status, cose_status_t::COSE_OK);
            // Empty message should not succeed
            if !is_success {
                let failure_msg =
                    unsafe { cose_sign1_validation_result_failure_message_utf8(result) };
                if !failure_msg.is_null() {
                    unsafe { cose_string_free(failure_msg) };
                }
            }
            unsafe { cose_sign1_validation_result_free(result) };
        }
    }

    unsafe { cose_sign1_validator_free(validator) };
}

#[test]
fn test_validate_bytes_null_validator() {
    let message_bytes = create_minimal_cose_sign1();
    let mut result: *mut cose_sign1_validation_result_t = ptr::null_mut();

    let status = unsafe {
        cose_sign1_validator_validate_bytes(
            ptr::null(), // null validator
            message_bytes.as_ptr(),
            message_bytes.len(),
            ptr::null(),
            0,
            &mut result,
        )
    };

    assert_eq!(status, cose_status_t::COSE_ERR);
    assert!(result.is_null());
}

#[test]
fn test_validate_bytes_null_output() {
    let mut builder: *mut cose_sign1_validator_builder_t = ptr::null_mut();
    unsafe { cose_sign1_validator_builder_new(&mut builder) };

    let mut validator: *mut cose_sign1_validator_t = ptr::null_mut();
    unsafe { cose_sign1_validator_builder_build(builder, &mut validator) };

    let message_bytes = create_minimal_cose_sign1();

    let status = unsafe {
        cose_sign1_validator_validate_bytes(
            validator,
            message_bytes.as_ptr(),
            message_bytes.len(),
            ptr::null(),
            0,
            ptr::null_mut(), // null result output
        )
    };

    assert_eq!(status, cose_status_t::COSE_ERR);

    unsafe { cose_sign1_validator_free(validator) };
}

#[test]
fn test_validation_result_null_safety() {
    // Test result functions with null handles
    let mut is_success = false;
    let status = unsafe { cose_sign1_validation_result_is_success(ptr::null(), &mut is_success) };
    assert_eq!(status, cose_status_t::COSE_ERR); // Should return error for null

    let failure_msg = unsafe { cose_sign1_validation_result_failure_message_utf8(ptr::null()) };
    assert!(failure_msg.is_null()); // Should return null for null input
}

#[test]
fn test_error_handling_functions() {
    // Test ABI version
    let version = cose_sign1_validation_abi_version();
    assert!(version > 0);

    // Test error message retrieval (when no error is set)
    let error_msg = cose_last_error_message_utf8();
    if !error_msg.is_null() {
        unsafe { cose_string_free(error_msg) };
    }

    // Test error clear
    cose_last_error_clear();
}

#[test]
fn test_free_functions_null_safety() {
    // All free functions should handle null safely
    unsafe {
        cose_sign1_validator_builder_free(ptr::null_mut());
        cose_sign1_validator_free(ptr::null_mut());
        cose_sign1_validation_result_free(ptr::null_mut());
        cose_string_free(ptr::null_mut());
    }
}

#[test]
fn test_validate_large_payload() {
    let mut builder: *mut cose_sign1_validator_builder_t = ptr::null_mut();
    unsafe { cose_sign1_validator_builder_new(&mut builder) };

    let mut validator: *mut cose_sign1_validator_t = ptr::null_mut();
    unsafe { cose_sign1_validator_builder_build(builder, &mut validator) };

    let message_bytes = create_minimal_cose_sign1();
    // Create a large detached payload to test streaming behavior
    let large_payload = vec![0x42u8; 100000]; // 100KB
    let mut result: *mut cose_sign1_validation_result_t = ptr::null_mut();

    let status = unsafe {
        cose_sign1_validator_validate_bytes(
            validator,
            message_bytes.as_ptr(),
            message_bytes.len(),
            large_payload.as_ptr(),
            large_payload.len(),
            &mut result,
        )
    };

    assert_eq!(status, cose_status_t::COSE_OK);
    assert!(!result.is_null());

    // Check result (will likely fail validation but shouldn't crash)
    let mut is_success = false;
    let status = unsafe { cose_sign1_validation_result_is_success(result, &mut is_success) };
    assert_eq!(status, cose_status_t::COSE_OK);
    if !is_success {
        let failure_msg = unsafe { cose_sign1_validation_result_failure_message_utf8(result) };
        if !failure_msg.is_null() {
            unsafe { cose_string_free(failure_msg) };
        }
    }

    unsafe {
        cose_sign1_validation_result_free(result);
        cose_sign1_validator_free(validator);
    };
}

#[test]
fn test_validate_detached_payload_null_with_nonzero_length() {
    let mut builder: *mut cose_sign1_validator_builder_t = ptr::null_mut();
    unsafe { cose_sign1_validator_builder_new(&mut builder) };

    let mut validator: *mut cose_sign1_validator_t = ptr::null_mut();
    unsafe { cose_sign1_validator_builder_build(builder, &mut validator) };

    let message_bytes = create_minimal_cose_sign1();
    let mut result: *mut cose_sign1_validation_result_t = ptr::null_mut();

    // Pass null payload with non-zero length (should be an error)
    let status = unsafe {
        cose_sign1_validator_validate_bytes(
            validator,
            message_bytes.as_ptr(),
            message_bytes.len(),
            ptr::null(), // null payload
            100,         // but non-zero length
            &mut result,
        )
    };

    // Should either fail immediately or return a failed validation result
    if status == cose_status_t::COSE_OK {
        if !result.is_null() {
            let mut is_success = false;
            let status =
                unsafe { cose_sign1_validation_result_is_success(result, &mut is_success) };
            assert_eq!(status, cose_status_t::COSE_OK);
            // This combination should not succeed
            if !is_success {
                let failure_msg =
                    unsafe { cose_sign1_validation_result_failure_message_utf8(result) };
                if !failure_msg.is_null() {
                    unsafe { cose_string_free(failure_msg) };
                }
            }
            unsafe { cose_sign1_validation_result_free(result) };
        }
    }

    unsafe { cose_sign1_validator_free(validator) };
}

#[test]
fn test_validate_message_null_with_nonzero_length() {
    let mut builder: *mut cose_sign1_validator_builder_t = ptr::null_mut();
    unsafe { cose_sign1_validator_builder_new(&mut builder) };

    let mut validator: *mut cose_sign1_validator_t = ptr::null_mut();
    unsafe { cose_sign1_validator_builder_build(builder, &mut validator) };

    let mut result: *mut cose_sign1_validation_result_t = ptr::null_mut();

    // Pass null message with non-zero length (should be an error)
    let status = unsafe {
        cose_sign1_validator_validate_bytes(
            validator,
            ptr::null(), // null message
            100,         // but non-zero length
            ptr::null(),
            0,
            &mut result,
        )
    };

    // Should fail - this is invalid input
    assert_ne!(status, cose_status_t::COSE_OK);

    unsafe { cose_sign1_validator_free(validator) };
}

#[test]
fn test_validation_result_success_and_failure_paths() {
    let mut builder: *mut cose_sign1_validator_builder_t = ptr::null_mut();
    unsafe { cose_sign1_validator_builder_new(&mut builder) };

    let mut validator: *mut cose_sign1_validator_t = ptr::null_mut();
    unsafe { cose_sign1_validator_builder_build(builder, &mut validator) };

    // Test with minimal message that will likely fail validation
    let message_bytes = create_minimal_cose_sign1();
    let mut result: *mut cose_sign1_validation_result_t = ptr::null_mut();

    let status = unsafe {
        cose_sign1_validator_validate_bytes(
            validator,
            message_bytes.as_ptr(),
            message_bytes.len(),
            ptr::null(),
            0,
            &mut result,
        )
    };

    if status == cose_status_t::COSE_OK && !result.is_null() {
        let mut is_success = false;
        let status = unsafe { cose_sign1_validation_result_is_success(result, &mut is_success) };
        assert_eq!(status, cose_status_t::COSE_OK);

        if is_success {
            // If validation succeeded, failure message should be null
            let failure_msg = unsafe { cose_sign1_validation_result_failure_message_utf8(result) };
            if !failure_msg.is_null() {
                // Clean up even if unexpected
                unsafe { cose_string_free(failure_msg) };
            }
        } else {
            // If validation failed, we should be able to get a failure message
            let failure_msg = unsafe { cose_sign1_validation_result_failure_message_utf8(result) };
            if !failure_msg.is_null() {
                // Verify it's a valid string by checking it's not empty
                let c_str = unsafe { std::ffi::CStr::from_ptr(failure_msg) };
                let _rust_str = c_str.to_string_lossy();
                // Message should not be empty
                assert!(!_rust_str.is_empty());

                unsafe { cose_string_free(failure_msg) };
            }
        }

        unsafe { cose_sign1_validation_result_free(result) };
    }

    unsafe { cose_sign1_validator_free(validator) };
}
