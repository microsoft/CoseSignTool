// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use cosesign1_abstractions::ValidationResult;
use cosesign1_abstractions_ffi::*;
use std::ffi::{c_char, CStr};

fn encode_minimal_cose_sign1(payload: Option<&[u8]>) -> Vec<u8> {
    let mut protected_map = Vec::new();
    {
        let mut enc = minicbor::Encoder::new(&mut protected_map);
        enc.map(0).unwrap();
    }

    let mut out = Vec::new();
    let mut enc = minicbor::Encoder::new(&mut out);
    enc.array(4).unwrap();
    enc.bytes(&protected_map).unwrap();
    enc.map(0).unwrap();
    match payload {
        Some(p) => {
            enc.bytes(p).unwrap();
        }
        None => {
            enc.null().unwrap();
        }
    }
    enc.bytes(&[0u8; 64]).unwrap();
    out
}

unsafe fn cstr(ptr: *const c_char) -> String {
    if ptr.is_null() {
        return String::new();
    }
    CStr::from_ptr(ptr).to_string_lossy().into_owned()
}

#[test]
fn abstractions_inspect_covers_nulls_parse_error_and_success() {
    unsafe {
        // Null cose.
        let mut info = cosesign1_abstractions_info {
            is_detached: false,
            payload: cosesign1_byte_view {
                data: std::ptr::null(),
                len: 0,
            },
        };
        let res = cosesign1_abstractions_inspect(std::ptr::null(), 0, &mut info as *mut _);
        assert!(!cosesign1_abstractions_result_is_valid(res));
        assert_eq!(
            cstr(cosesign1_abstractions_result_failure_at(res, 0).error_code),
            "NULL_ARGUMENT"
        );
        cosesign1_abstractions_result_free(res);

        // Null out_info.
        let cose = encode_minimal_cose_sign1(Some(b"hi"));
        let res = cosesign1_abstractions_inspect(cose.as_ptr(), cose.len(), std::ptr::null_mut());
        assert!(!cosesign1_abstractions_result_is_valid(res));
        assert_eq!(
            cstr(cosesign1_abstractions_result_failure_at(res, 0).error_code),
            "NULL_ARGUMENT"
        );
        cosesign1_abstractions_result_free(res);

        // Parse error.
        let bad = [0x01u8, 0x02u8, 0x03u8];
        let mut info = cosesign1_abstractions_info {
            is_detached: false,
            payload: cosesign1_byte_view {
                data: std::ptr::null(),
                len: 0,
            },
        };
        let res = cosesign1_abstractions_inspect(bad.as_ptr(), bad.len(), &mut info as *mut _);
        assert!(!cosesign1_abstractions_result_is_valid(res));
        assert_eq!(
            cstr(cosesign1_abstractions_result_failure_at(res, 0).error_code),
            "CBOR_PARSE_ERROR"
        );
        cosesign1_abstractions_result_free(res);

        // Success (embedded payload).
        let cose = encode_minimal_cose_sign1(Some(b"hello"));
        let mut info = cosesign1_abstractions_info {
            is_detached: true,
            payload: cosesign1_byte_view {
                data: std::ptr::null(),
                len: 0,
            },
        };
        let res = cosesign1_abstractions_inspect(cose.as_ptr(), cose.len(), &mut info as *mut _);
        assert!(cosesign1_abstractions_result_is_valid(res));
        assert!(!info.is_detached);
        assert_eq!(info.payload.len, 5);
        assert!(!info.payload.data.is_null());

        // Exercise getters and out-of-range accessors.
        assert_eq!(cosesign1_abstractions_result_failure_count(res), 0);
        let missing = cosesign1_abstractions_result_failure_at(res, 123);
        assert!(missing.message.is_null());
        assert!(missing.error_code.is_null());

        assert_eq!(cosesign1_abstractions_result_metadata_count(res), 0);
        let missing_kv = cosesign1_abstractions_result_metadata_at(res, 123);
        assert!(missing_kv.key.is_null());
        assert!(missing_kv.value.is_null());

        assert!(!cosesign1_abstractions_result_validator_name(res).is_null());
        cosesign1_abstractions_result_free(res);

        // Detached payload success.
        let cose = encode_minimal_cose_sign1(None);
        let mut info = cosesign1_abstractions_info {
            is_detached: false,
            payload: cosesign1_byte_view {
                data: std::ptr::null(),
                len: 0,
            },
        };
        let res = cosesign1_abstractions_inspect(cose.as_ptr(), cose.len(), &mut info as *mut _);
        assert!(cosesign1_abstractions_result_is_valid(res));
        assert!(info.is_detached);
        assert_eq!(info.payload.len, 0);
        cosesign1_abstractions_result_free(res);

        // Anchor function.
        cosesign1_abstractions_unused_anchor(std::ptr::null_mut());
    }
}

#[test]
fn abstractions_result_helpers_cover_intern_opt_none_and_null_getters() {
    unsafe {
        // Cover test helper null handling.
        assert_eq!(cstr(std::ptr::null()), "");

        // Null getters.
        assert!(!cosesign1_abstractions_result_is_valid(std::ptr::null()));
        assert!(cosesign1_abstractions_result_validator_name(std::ptr::null()).is_null());
        assert_eq!(cosesign1_abstractions_result_failure_count(std::ptr::null()), 0);
        let fv = cosesign1_abstractions_result_failure_at(std::ptr::null(), 0);
        assert!(fv.message.is_null());
        assert!(fv.error_code.is_null());
        assert_eq!(cosesign1_abstractions_result_metadata_count(std::ptr::null()), 0);
        let kv = cosesign1_abstractions_result_metadata_at(std::ptr::null(), 0);
        assert!(kv.key.is_null());
        assert!(kv.value.is_null());

        // intern_opt(None) via an error without an error_code.
        let mut vr = ValidationResult::failure_message("Abstractions", "oops", None);
        vr.metadata.insert("k".to_string(), "v".to_string());
        let res = Box::into_raw(Box::new(cosesign1_abstractions_result::from_validation_result(vr)));
        assert!(!res.is_null());
        assert!(!cosesign1_abstractions_result_validator_name(res).is_null());
        assert!(cosesign1_abstractions_result_failure_count(res) >= 1);
        assert_eq!(cosesign1_abstractions_result_metadata_count(res), 1);

        // Out-of-range getters.
        let fv = cosesign1_abstractions_result_failure_at(res, usize::MAX);
        assert!(fv.message.is_null());
        assert!(fv.error_code.is_null());
        let kv = cosesign1_abstractions_result_metadata_at(res, usize::MAX);
        assert!(kv.key.is_null());
        assert!(kv.value.is_null());
        cosesign1_abstractions_result_free(res);
    }
}
