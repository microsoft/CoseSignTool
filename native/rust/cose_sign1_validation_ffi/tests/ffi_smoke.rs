use cose_sign1_validation_ffi::*;
use std::ffi::CStr;
use std::ptr;

fn last_error_string() -> Option<String> {
    let p = cose_last_error_message_utf8();
    if p.is_null() {
        return None;
    }
    let s = unsafe { CStr::from_ptr(p) }.to_string_lossy().to_string();
    unsafe { cose_string_free(p) };
    Some(s)
}

fn minimal_cose_sign1() -> Vec<u8> {
    // Minimal COSE_Sign1: [ bstr(a0), {}, null, bstr("sig") ]
    // Encoded as:
    //   0x84 (array 4)
    //   0x41 0xA0 (bstr len 1 containing 0xA0)
    //   0xA0 (map 0)
    //   0xF6 (null)
    //   0x43 0x73 0x69 0x67 (bstr "sig")
    vec![0x84, 0x41, 0xA0, 0xA0, 0xF6, 0x43, b's', b'i', b'g']
}

#[test]
fn ffi_null_free_noops_and_failure_message_null_result() {
    // Null frees should be safe no-ops.
    cose_validator_builder_free(ptr::null_mut());
    cose_validator_free(ptr::null_mut());
    cose_validation_result_free(ptr::null_mut());

    // failure_message on null result => null + last_error set.
    cose_last_error_clear();
    let p = cose_validation_result_failure_message_utf8(ptr::null());
    assert!(p.is_null());
    assert!(last_error_string().unwrap_or_default().contains("result must not be null"));
}

#[test]
fn ffi_smoke_builder() {
    let mut builder: *mut cose_validator_builder_t = ptr::null_mut();
    assert_eq!(cose_validator_builder_new(&mut builder), cose_status_t::COSE_OK);
    assert!(!builder.is_null());

    // Pack-specific functions are tested in their respective FFI crates.

    let mut validator: *mut cose_validator_t = ptr::null_mut();
    assert_eq!(
        cose_validator_builder_build(builder, &mut validator),
        cose_status_t::COSE_OK
    );
    assert!(!validator.is_null());

    cose_validator_free(validator);
    cose_validator_builder_free(builder);
}

#[test]
fn ffi_error_channel_and_string_ownership() {
    cose_last_error_clear();
    assert!(last_error_string().is_none());

    // Null out-parameter => COSE_ERR + last_error set.
    let status = cose_validator_builder_new(ptr::null_mut());
    assert_eq!(status, cose_status_t::COSE_ERR);
    let msg = last_error_string().unwrap_or_default();
    assert!(!msg.is_empty());

    // Freeing a null string is a no-op.
    unsafe { cose_string_free(ptr::null_mut()) };

    // Clearing removes the message.
    cose_last_error_clear();
    assert!(last_error_string().is_none());
}

#[test]
fn ffi_validator_validate_bytes_paths() {
    let mut builder: *mut cose_validator_builder_t = ptr::null_mut();
    assert_eq!(cose_validator_builder_new(&mut builder), cose_status_t::COSE_OK);

    // builder_build: null out => error
    assert_eq!(
        cose_validator_builder_build(builder, ptr::null_mut()),
        cose_status_t::COSE_ERR
    );
    assert!(last_error_string().unwrap_or_default().contains("out"));

    let mut validator: *mut cose_validator_t = ptr::null_mut();
    assert_eq!(
        cose_validator_builder_build(builder, &mut validator),
        cose_status_t::COSE_OK
    );
    assert!(!validator.is_null());

    // validate_bytes: null out_result => error
    assert_eq!(
        cose_validator_validate_bytes(validator, ptr::null(), 0, ptr::null(), 0, ptr::null_mut()),
        cose_status_t::COSE_ERR
    );
    assert!(last_error_string().unwrap_or_default().contains("out_result"));

    // validate_bytes: null cose_bytes => COSE_INVALID_ARG
    let mut result: *mut cose_validation_result_t = ptr::null_mut();
    assert_eq!(
        cose_validator_validate_bytes(validator, ptr::null(), 0, ptr::null(), 0, &mut result),
        cose_status_t::COSE_INVALID_ARG
    );
    assert!(result.is_null());

    // validate_bytes: malformed bytes => COSE_ERR
    let bad = [0x00u8];
    assert_eq!(
        cose_validator_validate_bytes(validator, bad.as_ptr(), bad.len(), ptr::null(), 0, &mut result),
        cose_status_t::COSE_ERR
    );
    assert!(last_error_string().is_some());
    assert!(result.is_null());

    // validate_bytes: minimal COSE bytes should produce a result (likely failure, but not an error).
    let bytes = minimal_cose_sign1();
    assert_eq!(
        cose_validator_validate_bytes(
            validator,
            bytes.as_ptr(),
            bytes.len(),
            ptr::null(),
            0,
            &mut result
        ),
        cose_status_t::COSE_OK,
        "{:?}",
        last_error_string()
    );
    assert!(!result.is_null());

    let mut ok = true;
    assert_eq!(
        cose_validation_result_is_success(result, &mut ok),
        cose_status_t::COSE_OK
    );
    // For minimal bytes, success is not guaranteed; just ensure the API behaves.
    let failure = cose_validation_result_failure_message_utf8(result);
    if !failure.is_null() {
        unsafe { cose_string_free(failure) };
    }

    cose_validation_result_free(result);

    // validate_bytes: exercise detached payload non-null branch (behavior may still be failure).
    let bytes = minimal_cose_sign1();
    let detached = [0x01u8, 0x02u8, 0x03u8];
    result = ptr::null_mut();
    assert_eq!(
        cose_validator_validate_bytes(
            validator,
            bytes.as_ptr(),
            bytes.len(),
            detached.as_ptr(),
            detached.len(),
            &mut result
        ),
        cose_status_t::COSE_OK,
        "{:?}",
        last_error_string()
    );
    assert!(!result.is_null());
    cose_validation_result_free(result);

    cose_validator_free(validator);
    cose_validator_builder_free(builder);
}
