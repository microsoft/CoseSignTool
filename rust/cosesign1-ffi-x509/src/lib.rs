// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![allow(clippy::missing_safety_doc)]
#![allow(non_camel_case_types)]

use cosesign1_abstractions_ffi::cosesign1_abstractions_result as base_result;
use cosesign1_abstractions::ValidationResult;
use cosesign1::VerificationSettings;
use std::ffi::c_char;

pub use cosesign1_abstractions_ffi::{cosesign1_failure_view, cosesign1_kv_view};

pub type cosesign1_x509_result = base_result;

#[no_mangle]
pub unsafe extern "C" fn cosesign1_x509_result_free(res: *mut cosesign1_x509_result) {
    if !res.is_null() {
        drop(Box::from_raw(res));
    }
}

#[no_mangle]
pub unsafe extern "C" fn cosesign1_x509_result_is_valid(res: *const cosesign1_x509_result) -> bool {
    if res.is_null() {
        return false;
    }
    (&*res).is_valid
}

#[no_mangle]
pub unsafe extern "C" fn cosesign1_x509_result_validator_name(res: *const cosesign1_x509_result) -> *const c_char {
    if res.is_null() {
        return std::ptr::null();
    }
    (&*res).validator_name.as_ptr()
}

#[no_mangle]
pub unsafe extern "C" fn cosesign1_x509_result_failure_count(res: *const cosesign1_x509_result) -> usize {
    if res.is_null() {
        return 0;
    }
    (&*res).failures.len()
}

#[no_mangle]
pub unsafe extern "C" fn cosesign1_x509_result_failure_at(res: *const cosesign1_x509_result, index: usize) -> cosesign1_failure_view {
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
pub unsafe extern "C" fn cosesign1_x509_result_metadata_count(res: *const cosesign1_x509_result) -> usize {
    if res.is_null() {
        return 0;
    }
    (&*res).metadata.len()
}

#[no_mangle]
pub unsafe extern "C" fn cosesign1_x509_result_metadata_at(res: *const cosesign1_x509_result, index: usize) -> cosesign1_kv_view {
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
pub struct cosesign1_x509_chain_options {
    pub trust_mode: i32,
    pub revocation_mode: i32,
    pub allow_untrusted_roots: bool,
}

#[no_mangle]
pub unsafe extern "C" fn cosesign1_x509_verify_cose_sign1_with_x5c_chain(
    cose: *const u8,
    cose_len: usize,
    payload: *const u8,
    payload_len: usize,
    trusted_roots: *const cosesign1_byte_view,
    trusted_root_count: usize,
    options: cosesign1_x509_chain_options,
) -> *mut cosesign1_x509_result {
    if cose.is_null() {
        return Box::into_raw(Box::new(base_result::from_error(
            "x5c",
            "cose pointer was null",
            "NULL_ARGUMENT",
        )));
    }

    let cose_bytes = std::slice::from_raw_parts(cose, cose_len);
    let payload_opt = if payload.is_null() {
        None
    } else {
        Some(std::slice::from_raw_parts(payload, payload_len))
    };

    // Convert roots.
    let root_views = if trusted_roots.is_null() {
        &[][..]
    } else {
        std::slice::from_raw_parts(trusted_roots, trusted_root_count)
    };
    let mut roots: Vec<Vec<u8>> = Vec::with_capacity(root_views.len());
    for v in root_views {
        if v.data.is_null() {
            return Box::into_raw(Box::new(base_result::from_error(
                "x5c",
                "trusted root entry pointer was null",
                "NULL_ARGUMENT",
            )));
        }
        roots.push(std::slice::from_raw_parts(v.data, v.len).to_vec());
    }

    // Build X509 options.
    let mut chain = cosesign1_x509_core::X509ChainVerifyOptions::default();
    chain.trust_mode = match options.trust_mode {
        0 => cosesign1_x509_core::X509TrustMode::System,
        1 => cosesign1_x509_core::X509TrustMode::CustomRoots,
        _ => {
            return Box::into_raw(Box::new(base_result::from_error(
                "x5c",
                "invalid trust_mode",
                "INVALID_ARGUMENT",
            )))
        }
    };
    chain.revocation_mode = match options.revocation_mode {
        0 => cosesign1_x509_core::X509RevocationMode::NoCheck,
        1 => cosesign1_x509_core::X509RevocationMode::Online,
        2 => cosesign1_x509_core::X509RevocationMode::Offline,
        _ => {
            return Box::into_raw(Box::new(base_result::from_error(
                "x5c",
                "invalid revocation_mode",
                "INVALID_ARGUMENT",
            )))
        }
    };
    chain.allow_untrusted_roots = options.allow_untrusted_roots;
    chain.trusted_roots_der = roots;

    // Pipeline: signature verification + x5c chain trust.
    let msg = match cosesign1::CoseSign1::from_bytes(cose_bytes) {
        Ok(m) => m,
        Err(e) => {
            let vr = ValidationResult::failure_message("x5c", e, Some("CBOR_PARSE_ERROR".to_string()));
            return Box::into_raw(Box::new(base_result::from_validation_result(vr)));
        }
    };

    let settings = VerificationSettings::default()
        .with_validator_options(cosesign1_x509_core::x5c_chain_validation_options(chain));

    let res = msg.verify(payload_opt, None, &settings);
    Box::into_raw(Box::new(base_result::from_validation_result(res)))
}

#[no_mangle]
pub unsafe extern "C" fn cosesign1_x509_validate_x5c_chain(
    certs: *const cosesign1_byte_view,
    cert_count: usize,
    trusted_roots: *const cosesign1_byte_view,
    trusted_root_count: usize,
    options: cosesign1_x509_chain_options,
) -> *mut cosesign1_x509_result {
    if certs.is_null() {
        return Box::into_raw(Box::new(base_result::from_error(
            "x5c_chain",
            "certs pointer was null",
            "NULL_ARGUMENT",
        )));
    }

    let cert_views = std::slice::from_raw_parts(certs, cert_count);
    let mut chain: Vec<Vec<u8>> = Vec::with_capacity(cert_views.len());
    for v in cert_views {
        if v.data.is_null() {
            return Box::into_raw(Box::new(base_result::from_error(
                "x5c_chain",
                "cert entry pointer was null",
                "NULL_ARGUMENT",
            )));
        }
        chain.push(std::slice::from_raw_parts(v.data, v.len).to_vec());
    }

    let root_views = if trusted_roots.is_null() {
        &[][..]
    } else {
        std::slice::from_raw_parts(trusted_roots, trusted_root_count)
    };
    let mut roots: Vec<Vec<u8>> = Vec::with_capacity(root_views.len());
    for v in root_views {
        if v.data.is_null() {
            return Box::into_raw(Box::new(base_result::from_error(
                "x5c_chain",
                "trusted root entry pointer was null",
                "NULL_ARGUMENT",
            )));
        }
        roots.push(std::slice::from_raw_parts(v.data, v.len).to_vec());
    }

    let mut opt = cosesign1_x509_core::X509ChainVerifyOptions::default();
    opt.trust_mode = match options.trust_mode {
        0 => cosesign1_x509_core::X509TrustMode::System,
        1 => cosesign1_x509_core::X509TrustMode::CustomRoots,
        _ => {
            return Box::into_raw(Box::new(base_result::from_error(
                "x5c_chain",
                "invalid trust_mode",
                "INVALID_ARGUMENT",
            )))
        }
    };
    opt.revocation_mode = match options.revocation_mode {
        0 => cosesign1_x509_core::X509RevocationMode::NoCheck,
        1 => cosesign1_x509_core::X509RevocationMode::Online,
        2 => cosesign1_x509_core::X509RevocationMode::Offline,
        _ => {
            return Box::into_raw(Box::new(base_result::from_error(
                "x5c_chain",
                "invalid revocation_mode",
                "INVALID_ARGUMENT",
            )))
        }
    };
    opt.allow_untrusted_roots = options.allow_untrusted_roots;
    opt.trusted_roots_der = roots;

    let res = cosesign1_x509_core::validate_x5c_chain("x5c_chain", &chain, &opt);
    Box::into_raw(Box::new(base_result::from_validation_result(res)))
}

#[cfg(test)]
#[path = "../tests/support/coverage_unit.rs"]
mod coverage_unit;


