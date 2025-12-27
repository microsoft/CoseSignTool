// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![allow(clippy::missing_safety_doc)]
#![allow(non_camel_case_types)]

use cosesign1_abstractions::ValidationResult;
use cosesign1_abstractions_ffi::cosesign1_abstractions_result as base_result;
use std::ffi::c_char;

pub use cosesign1_abstractions_ffi::{cosesign1_failure_view, cosesign1_kv_view};

pub type cosesign1_mst_result = base_result;

#[no_mangle]
pub unsafe extern "C" fn cosesign1_mst_result_free(res: *mut cosesign1_mst_result) {
    if !res.is_null() {
        drop(Box::from_raw(res));
    }
}

#[no_mangle]
pub unsafe extern "C" fn cosesign1_mst_result_is_valid(res: *const cosesign1_mst_result) -> bool {
    if res.is_null() {
        return false;
    }
    (&*res).is_valid
}

#[no_mangle]
pub unsafe extern "C" fn cosesign1_mst_result_validator_name(res: *const cosesign1_mst_result) -> *const c_char {
    if res.is_null() {
        return std::ptr::null();
    }
    (&*res).validator_name.as_ptr()
}

#[no_mangle]
pub unsafe extern "C" fn cosesign1_mst_result_failure_count(res: *const cosesign1_mst_result) -> usize {
    if res.is_null() {
        return 0;
    }
    (&*res).failures.len()
}

#[no_mangle]
pub unsafe extern "C" fn cosesign1_mst_result_failure_at(res: *const cosesign1_mst_result, index: usize) -> cosesign1_failure_view {
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
pub unsafe extern "C" fn cosesign1_mst_result_metadata_count(res: *const cosesign1_mst_result) -> usize {
    if res.is_null() {
        return 0;
    }
    (&*res).metadata.len()
}

#[no_mangle]
pub unsafe extern "C" fn cosesign1_mst_result_metadata_at(res: *const cosesign1_mst_result, index: usize) -> cosesign1_kv_view {
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
pub struct cosesign1_byte_view {
    pub data: *const u8,
    pub len: usize,
}

#[repr(C)]
pub struct cosesign1_string_view {
    pub data: *const c_char,
}

#[repr(C)]
pub struct cosesign1_mst_verification_options {
    pub authorized_receipt_behavior: i32,
    pub unauthorized_receipt_behavior: i32,
}

pub struct cosesign1_mst_keystore {
    store: cosesign1_mst_core::OfflineEcKeyStore,
}

#[no_mangle]
pub unsafe extern "C" fn cosesign1_mst_keystore_new() -> *mut cosesign1_mst_keystore {
    Box::into_raw(Box::new(cosesign1_mst_keystore {
        store: Default::default(),
    }))
}

#[no_mangle]
pub unsafe extern "C" fn cosesign1_mst_keystore_free(p: *mut cosesign1_mst_keystore) {
    if !p.is_null() {
        drop(Box::from_raw(p));
    }
}

#[no_mangle]
pub unsafe extern "C" fn cosesign1_mst_keystore_add_issuer_jwks(
    store: *mut cosesign1_mst_keystore,
    issuer_host: *const c_char,
    jwks_json: *const u8,
    jwks_len: usize,
) -> *mut cosesign1_mst_result {
    if store.is_null() {
        return Box::into_raw(Box::new(base_result::from_error(
            "mst",
            "store pointer was null",
            "NULL_ARGUMENT",
        )));
    }
    if issuer_host.is_null() {
        return Box::into_raw(Box::new(base_result::from_error(
            "mst",
            "issuer_host pointer was null",
            "NULL_ARGUMENT",
        )));
    }
    if jwks_json.is_null() {
        return Box::into_raw(Box::new(base_result::from_error(
            "mst",
            "jwks_json pointer was null",
            "NULL_ARGUMENT",
        )));
    }

    let issuer = match std::ffi::CStr::from_ptr(issuer_host).to_str() {
        Ok(s) => s,
        Err(_) => {
            return Box::into_raw(Box::new(base_result::from_error(
                "mst",
                "issuer_host was not valid UTF-8",
                "INVALID_ARGUMENT",
            )))
        }
    };

    let jwks = std::slice::from_raw_parts(jwks_json, jwks_len);

    let doc = match cosesign1_mst_core::parse_jwks(jwks) {
        Ok(d) => d,
        Err(e) => {
            return Box::into_raw(Box::new(base_result::from_error(
                "mst",
                &e,
                "MST_JWKS_PARSE_ERROR",
            )))
        }
    };

    let added = match cosesign1_mst_core::add_issuer_keys(unsafe { &mut (*store).store }, issuer, &doc) {
        Ok(n) => n,
        Err(e) => {
            return Box::into_raw(Box::new(base_result::from_error(
                "mst",
                &e,
                "MST_JWKS_ERROR",
            )))
        }
    };

    let mut vr = ValidationResult::success("mst", Default::default());
    vr.metadata.insert("keysAdded".to_string(), added.to_string());
    Box::into_raw(Box::new(base_result::from_validation_result(vr)))
}

#[no_mangle]
pub unsafe extern "C" fn cosesign1_mst_verify_transparent_statement(
    store: *const cosesign1_mst_keystore,
    transparent_statement_cose_sign1: *const u8,
    transparent_statement_len: usize,
    authorized_domains: *const cosesign1_string_view,
    authorized_domain_count: usize,
    options: cosesign1_mst_verification_options,
) -> *mut cosesign1_mst_result {
    if store.is_null() {
        return Box::into_raw(Box::new(base_result::from_error(
            "mst",
            "store pointer was null",
            "NULL_ARGUMENT",
        )));
    }
    if transparent_statement_cose_sign1.is_null() {
        return Box::into_raw(Box::new(base_result::from_error(
            "mst",
            "transparent_statement pointer was null",
            "NULL_ARGUMENT",
        )));
    }

    let mut opt = cosesign1_mst_core::VerificationOptions::default();
    opt.allow_network_key_fetch = false;

    // behaviors
    opt.authorized_receipt_behavior = match options.authorized_receipt_behavior {
        0 => cosesign1_mst_core::AuthorizedReceiptBehavior::VerifyAnyMatching,
        1 => cosesign1_mst_core::AuthorizedReceiptBehavior::VerifyAllMatching,
        2 => cosesign1_mst_core::AuthorizedReceiptBehavior::RequireAll,
        _ => {
            return Box::into_raw(Box::new(base_result::from_error(
                "mst",
                "invalid authorized_receipt_behavior",
                "INVALID_ARGUMENT",
            )))
        }
    };

    opt.unauthorized_receipt_behavior = match options.unauthorized_receipt_behavior {
        0 => cosesign1_mst_core::UnauthorizedReceiptBehavior::VerifyAll,
        1 => cosesign1_mst_core::UnauthorizedReceiptBehavior::IgnoreAll,
        2 => cosesign1_mst_core::UnauthorizedReceiptBehavior::FailIfPresent,
        _ => {
            return Box::into_raw(Box::new(base_result::from_error(
                "mst",
                "invalid unauthorized_receipt_behavior",
                "INVALID_ARGUMENT",
            )))
        }
    };

    if !authorized_domains.is_null() {
        let domains = std::slice::from_raw_parts(authorized_domains, authorized_domain_count);
        for d in domains {
            if d.data.is_null() {
                continue;
            }
            if let Ok(s) = std::ffi::CStr::from_ptr(d.data).to_str() {
                opt.authorized_domains.push(s.to_string());
            }
        }
    }

    let msg = std::slice::from_raw_parts(transparent_statement_cose_sign1, transparent_statement_len);
    let res = cosesign1_mst_core::verify_transparent_statement("mst", msg, &(*store).store, &opt);
    Box::into_raw(Box::new(base_result::from_validation_result(res)))
}

#[cfg(test)]
#[path = "../tests/support/coverage_unit.rs"]
mod coverage_unit;


