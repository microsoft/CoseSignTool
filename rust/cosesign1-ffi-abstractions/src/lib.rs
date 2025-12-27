// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![allow(clippy::missing_safety_doc)]
#![allow(non_camel_case_types)]

use cosesign1_abstractions::ValidationResult;
use std::ffi::{c_char, c_void, CString};

#[repr(C)]
#[derive(Copy, Clone)]
pub struct cosesign1_failure_view {
    pub message: *const c_char,
    pub error_code: *const c_char,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct cosesign1_kv_view {
    pub key: *const c_char,
    pub value: *const c_char,
}

/// Opaque result object that owns strings and vectors.
pub struct cosesign1_abstractions_result {
    pub is_valid: bool,
    pub validator_name: CString,
    pub failures: Vec<cosesign1_failure_view>,
    pub metadata: Vec<cosesign1_kv_view>,
    pub _strings: Vec<CString>,
    pub _bytes: Vec<Vec<u8>>,
}

impl cosesign1_abstractions_result {
    fn intern_opt(strings: &mut Vec<CString>, s: Option<&str>) -> *const c_char {
        match s {
            None => std::ptr::null(),
            Some(v) => {
                let cs = CString::new(v).unwrap_or_else(|_| CString::new("").expect("CString"));
                let ptr = cs.as_ptr();
                strings.push(cs);
                ptr
            }
        }
    }

    pub fn from_validation_result(vr: ValidationResult) -> Self {
        let mut strings: Vec<CString> = Vec::new();
        let validator_name = CString::new(vr.validator_name)
            .unwrap_or_else(|_| CString::new("Verify").expect("CString"));

        let mut failures: Vec<cosesign1_failure_view> = Vec::with_capacity(vr.failures.len());
        for f in vr.failures {
            let msg = Self::intern_opt(&mut strings, Some(&f.message));
            let code = Self::intern_opt(&mut strings, f.error_code.as_deref());
            failures.push(cosesign1_failure_view {
                message: msg,
                error_code: code,
            });
        }

        let mut metadata: Vec<cosesign1_kv_view> = Vec::with_capacity(vr.metadata.len());
        for (k, v) in vr.metadata {
            let kk = Self::intern_opt(&mut strings, Some(&k));
            let vv = Self::intern_opt(&mut strings, Some(&v));
            metadata.push(cosesign1_kv_view { key: kk, value: vv });
        }

        Self {
            is_valid: vr.is_valid,
            validator_name,
            failures,
            metadata,
            _strings: strings,
            _bytes: Vec::new(),
        }
    }

    pub fn from_error(validator: &str, message: &str, code: &str) -> Self {
        Self::from_validation_result(ValidationResult::failure_message(
            validator,
            message,
            Some(code.to_string()),
        ))
    }
}

// -----------------------------
// Abstractions API
// -----------------------------

#[no_mangle]
pub unsafe extern "C" fn cosesign1_abstractions_result_free(res: *mut cosesign1_abstractions_result) {
    if !res.is_null() {
        drop(Box::from_raw(res));
    }
}

#[no_mangle]
pub unsafe extern "C" fn cosesign1_abstractions_result_is_valid(res: *const cosesign1_abstractions_result) -> bool {
    if res.is_null() {
        return false;
    }
    (&*res).is_valid
}

#[no_mangle]
pub unsafe extern "C" fn cosesign1_abstractions_result_validator_name(res: *const cosesign1_abstractions_result) -> *const c_char {
    if res.is_null() {
        return std::ptr::null();
    }
    (&*res).validator_name.as_ptr()
}

#[no_mangle]
pub unsafe extern "C" fn cosesign1_abstractions_result_failure_count(res: *const cosesign1_abstractions_result) -> usize {
    if res.is_null() {
        return 0;
    }
    (&*res).failures.len()
}

#[no_mangle]
pub unsafe extern "C" fn cosesign1_abstractions_result_failure_at(
    res: *const cosesign1_abstractions_result,
    index: usize,
) -> cosesign1_failure_view {
    if res.is_null() {
        return cosesign1_failure_view {
            message: std::ptr::null(),
            error_code: std::ptr::null(),
        };
    }
    let res = &*res;
    res.failures
        .get(index)
        .copied()
        .unwrap_or(cosesign1_failure_view {
            message: std::ptr::null(),
            error_code: std::ptr::null(),
        })
}

#[no_mangle]
pub unsafe extern "C" fn cosesign1_abstractions_result_metadata_count(res: *const cosesign1_abstractions_result) -> usize {
    if res.is_null() {
        return 0;
    }
    (&*res).metadata.len()
}

#[no_mangle]
pub unsafe extern "C" fn cosesign1_abstractions_result_metadata_at(
    res: *const cosesign1_abstractions_result,
    index: usize,
) -> cosesign1_kv_view {
    if res.is_null() {
        return cosesign1_kv_view {
            key: std::ptr::null(),
            value: std::ptr::null(),
        };
    }

    let res = &*res;
    res.metadata
        .get(index)
        .copied()
        .unwrap_or(cosesign1_kv_view {
            key: std::ptr::null(),
            value: std::ptr::null(),
        })
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct cosesign1_byte_view {
    pub data: *const u8,
    pub len: usize,
}

#[repr(C)]
pub struct cosesign1_abstractions_info {
    pub is_detached: bool,
    pub payload: cosesign1_byte_view,
}

#[no_mangle]
pub unsafe extern "C" fn cosesign1_abstractions_inspect(
    cose: *const u8,
    cose_len: usize,
    out_info: *mut cosesign1_abstractions_info,
) -> *mut cosesign1_abstractions_result {
    if cose.is_null() {
        return Box::into_raw(Box::new(cosesign1_abstractions_result::from_error(
            "Abstractions",
            "cose pointer was null",
            "NULL_ARGUMENT",
        )));
    }

    if out_info.is_null() {
        return Box::into_raw(Box::new(cosesign1_abstractions_result::from_error(
            "Abstractions",
            "out_info pointer was null",
            "NULL_ARGUMENT",
        )));
    }

    let bytes = std::slice::from_raw_parts(cose, cose_len);
    let parsed = match cosesign1::parse_cose_sign1(bytes) {
        Ok(p) => p,
        Err(e) => {
            return Box::into_raw(Box::new(cosesign1_abstractions_result::from_error(
                "Abstractions",
                &e,
                "CBOR_PARSE_ERROR",
            )))
        }
    };

    // IMPORTANT: `parsed.payload` is owned by `parsed` (stack local). We must
    // keep a stable backing buffer alive past this function boundary.
    let mut res = cosesign1_abstractions_result::from_validation_result(ValidationResult::success(
        "Abstractions",
        Default::default(),
    ));

    match parsed.payload {
        None => {
            (*out_info).is_detached = true;
            (*out_info).payload = cosesign1_byte_view {
                data: std::ptr::null(),
                len: 0,
            };
        }
        Some(payload) => {
            (*out_info).is_detached = false;
            res._bytes.push(payload);
            let buf = res._bytes.last().expect("payload");
            (*out_info).payload = cosesign1_byte_view {
                data: buf.as_ptr(),
                len: buf.len(),
            };
        }
    }

    Box::into_raw(Box::new(res))
}

#[no_mangle]
pub unsafe extern "C" fn cosesign1_abstractions_unused_anchor(_p: *mut c_void) {
    // This exists only to ensure the staticlib is not empty on some toolchains.
}


