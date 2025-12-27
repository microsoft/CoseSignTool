// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![allow(clippy::missing_safety_doc)]
#![allow(non_camel_case_types)]

use cosesign1_abstractions::ValidationResult;
use cosesign1_abstractions_ffi::cosesign1_abstractions_result as base_result;
use std::ffi::{c_char, c_void};
use std::io::{Read, Seek, SeekFrom};

pub use cosesign1_abstractions_ffi::{cosesign1_failure_view, cosesign1_kv_view};

pub type cosesign1_validation_result = base_result;

#[no_mangle]
pub unsafe extern "C" fn cosesign1_validation_result_free(res: *mut cosesign1_validation_result) {
    if !res.is_null() {
        drop(Box::from_raw(res));
    }
}

#[no_mangle]
pub unsafe extern "C" fn cosesign1_validation_result_is_valid(res: *const cosesign1_validation_result) -> bool {
    if res.is_null() {
        return false;
    }
    (&*res).is_valid
}

#[no_mangle]
pub unsafe extern "C" fn cosesign1_validation_result_validator_name(res: *const cosesign1_validation_result) -> *const c_char {
    if res.is_null() {
        return std::ptr::null();
    }
    (&*res).validator_name.as_ptr()
}

#[no_mangle]
pub unsafe extern "C" fn cosesign1_validation_result_failure_count(res: *const cosesign1_validation_result) -> usize {
    if res.is_null() {
        return 0;
    }
    (&*res).failures.len()
}

#[no_mangle]
pub unsafe extern "C" fn cosesign1_validation_result_failure_at(
    res: *const cosesign1_validation_result,
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
pub unsafe extern "C" fn cosesign1_validation_result_metadata_count(res: *const cosesign1_validation_result) -> usize {
    if res.is_null() {
        return 0;
    }
    (&*res).metadata.len()
}

#[no_mangle]
pub unsafe extern "C" fn cosesign1_validation_result_metadata_at(
    res: *const cosesign1_validation_result,
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
pub struct cosesign1_reader {
    pub ctx: *mut c_void,
    pub read: Option<extern "C" fn(ctx: *mut c_void, out: *mut u8, out_len: usize, bytes_read: *mut usize) -> i32>,
    pub seek: Option<extern "C" fn(ctx: *mut c_void, offset: i64, origin: i32, new_pos: *mut u64) -> i32>,
}

struct CallbackReader {
    r: cosesign1_reader,
}

impl Read for CallbackReader {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let Some(f) = self.r.read else {
            return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, "read callback missing"));
        };

        let mut n: usize = 0;
        let rc = f(self.r.ctx, buf.as_mut_ptr(), buf.len(), &mut n as *mut usize);
        if rc != 0 {
            return Err(std::io::Error::new(std::io::ErrorKind::Other, "read callback failed"));
        }
        Ok(n)
    }
}

impl Seek for CallbackReader {
    fn seek(&mut self, pos: SeekFrom) -> std::io::Result<u64> {
        let Some(f) = self.r.seek else {
            return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, "seek callback missing"));
        };

        let (offset, origin) = match pos {
            SeekFrom::Start(n) => (n as i64, 0),
            SeekFrom::Current(n) => (n, 1),
            SeekFrom::End(n) => (n, 2),
        };

        let mut new_pos: u64 = 0;
        let rc = f(self.r.ctx, offset, origin, &mut new_pos as *mut u64);
        if rc != 0 {
            return Err(std::io::Error::new(std::io::ErrorKind::Other, "seek callback failed"));
        }
        Ok(new_pos)
    }
}

#[no_mangle]
pub unsafe extern "C" fn cosesign1_validation_verify_signature(
    cose: *const u8,
    cose_len: usize,
    payload: *const u8,
    payload_len: usize,
    public_key: *const u8,
    public_key_len: usize,
) -> *mut cosesign1_validation_result {
    if cose.is_null() {
        return Box::into_raw(Box::new(base_result::from_error(
            "Signature",
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
    let pk_opt = if public_key.is_null() {
        None
    } else {
        Some(std::slice::from_raw_parts(public_key, public_key_len))
    };

    let res = match cosesign1::CoseSign1::from_bytes(cose_bytes) {
        Ok(msg) => msg.verify_signature(payload_opt, pk_opt),
        Err(e) => ValidationResult::failure_message("Signature", e, Some("CBOR_PARSE_ERROR".to_string())),
    };

    Box::into_raw(Box::new(base_result::from_validation_result(res)))
}

#[no_mangle]
pub unsafe extern "C" fn cosesign1_validation_verify_signature_with_payload_reader(
    cose: *const u8,
    cose_len: usize,
    reader: cosesign1_reader,
    public_key: *const u8,
    public_key_len: usize,
) -> *mut cosesign1_validation_result {
    if cose.is_null() {
        return Box::into_raw(Box::new(base_result::from_error(
            "Signature",
            "cose pointer was null",
            "NULL_ARGUMENT",
        )));
    }

    let cose_bytes = std::slice::from_raw_parts(cose, cose_len);
    let pk_opt = if public_key.is_null() {
        None
    } else {
        Some(std::slice::from_raw_parts(public_key, public_key_len))
    };

    let msg = match cosesign1::CoseSign1::from_bytes(cose_bytes) {
        Ok(m) => m,
        Err(e) => {
            return Box::into_raw(Box::new(base_result::from_validation_result(
                ValidationResult::failure_message("Signature", e, Some("CBOR_PARSE_ERROR".to_string())),
            )))
        }
    };

    let mut rdr = CallbackReader { r: reader };
    let res = msg.verify_signature_with_payload_reader(&mut rdr, pk_opt);
    Box::into_raw(Box::new(base_result::from_validation_result(res)))
}

#[cfg(test)]
#[path = "../tests/support/coverage_unit.rs"]
mod coverage_unit;


