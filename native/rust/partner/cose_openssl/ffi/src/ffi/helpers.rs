use cose_openssl::EvpKey;
use cose_openssl::cose_sign1;
use std::slice;

/// Raw pointer + length to slice. Returns an empty slice for null/zero-length.
pub unsafe fn as_slice<'a>(ptr: *const u8, len: usize) -> &'a [u8] {
    if ptr.is_null() || len == 0 {
        &[]
    } else {
        unsafe { slice::from_raw_parts(ptr, len) }
    }
}

/// Write a `Vec<u8>` result into caller-supplied output pointers.
pub unsafe fn write_output(
    v: Vec<u8>,
    out_ptr: *mut *mut u8,
    out_len: *mut usize,
) {
    let b = v.into_boxed_slice();
    let len = b.len();
    let ptr = Box::into_raw(b) as *mut u8;
    unsafe {
        *out_len = len;
        *out_ptr = ptr;
    }
}

/// Shared implementation for `cose_sign` and `cose_sign_detached`.
pub unsafe fn sign_inner(
    phdr_ptr: *const u8,
    phdr_len: usize,
    uhdr_ptr: *const u8,
    uhdr_len: usize,
    payload_ptr: *const u8,
    payload_len: usize,
    key_der_ptr: *const u8,
    key_der_len: usize,
    out_ptr: *mut *mut u8,
    out_len: *mut usize,
    detached: bool,
) -> i32 {
    unsafe {
        if out_ptr.is_null() || out_len.is_null() {
            return -1;
        }

        let key = match EvpKey::from_der_private(as_slice(
            key_der_ptr,
            key_der_len,
        )) {
            Ok(k) => k,
            Err(_) => return -1,
        };

        match cose_sign1(
            &key,
            as_slice(phdr_ptr, phdr_len),
            as_slice(uhdr_ptr, uhdr_len),
            as_slice(payload_ptr, payload_len),
            detached,
        ) {
            Ok(envelope) => {
                write_output(envelope, out_ptr, out_len);
                0
            }
            Err(_) => -1,
        }
    }
}
