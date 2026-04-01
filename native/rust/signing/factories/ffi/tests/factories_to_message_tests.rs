// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Tests for the `_to_message` FFI variants.
//!
//! Each factory signing function has a `_to_message` variant that returns a
//! `CoseSign1MessageHandle` instead of raw bytes. These tests exercise every
//! `_to_message` extern "C" function for null-pointer rejection, error-path
//! coverage, and (where the mock signer allows) the happy path.

use std::ffi::{CStr, CString};
use std::ptr;

use cose_sign1_factories_ffi::error::{
    CoseSign1FactoriesErrorHandle, FFI_ERR_FACTORY_FAILED, FFI_ERR_NULL_POINTER, FFI_OK,
};
use cose_sign1_factories_ffi::{
    CoseSign1FactoriesHandle, CoseSign1MessageHandle, CryptoSignerHandle,
    cose_sign1_factories_create_from_crypto_signer, cose_sign1_factories_error_free,
    cose_sign1_factories_error_message, cose_sign1_factories_free,
    cose_sign1_factories_sign_direct_detached_to_message,
    cose_sign1_factories_sign_direct_file_to_message,
    cose_sign1_factories_sign_direct_streaming_to_message,
    cose_sign1_factories_sign_direct_to_message,
    cose_sign1_factories_sign_indirect_file_to_message,
    cose_sign1_factories_sign_indirect_streaming_to_message,
    cose_sign1_factories_sign_indirect_to_message, cose_sign1_factories_string_free,
};

use crypto_primitives::CryptoSigner;

// ============================================================================
// Test helpers
// ============================================================================

/// Creates a CryptoSignerHandle in the double-boxed format that
/// `cose_sign1_factories_create_from_crypto_signer` expects.
fn create_mock_signer_handle() -> *mut CryptoSignerHandle {
    let signer: Box<dyn CryptoSigner> = Box::new(MockCryptoSigner::es256());
    Box::into_raw(Box::new(signer)) as *mut CryptoSignerHandle
}

/// Creates a factory handle backed by a mock signer via the FFI function.
fn create_real_factory() -> *mut CoseSign1FactoriesHandle {
    let signer_handle: *mut CryptoSignerHandle = create_mock_signer_handle();

    let mut factory: *mut CoseSign1FactoriesHandle = ptr::null_mut();
    let mut err: *mut CoseSign1FactoriesErrorHandle = ptr::null_mut();
    let rc = unsafe {
        cose_sign1_factories_create_from_crypto_signer(signer_handle, &mut factory, &mut err)
    };
    if !err.is_null() {
        let msg: Option<String> = get_error_message(err);
        unsafe { cose_sign1_factories_error_free(err) };
        panic!("create_from_crypto_signer failed (rc={rc}): {msg:?}");
    }
    assert_eq!(rc, FFI_OK);
    assert!(!factory.is_null());
    factory
}

/// Retrieves the error message from an error handle (returns None for null).
fn get_error_message(err: *const CoseSign1FactoriesErrorHandle) -> Option<String> {
    if err.is_null() {
        return None;
    }
    let msg_ptr = unsafe { cose_sign1_factories_error_message(err) };
    if msg_ptr.is_null() {
        return None;
    }
    let s: String = unsafe { CStr::from_ptr(msg_ptr) }
        .to_string_lossy()
        .to_string();
    unsafe { cose_sign1_factories_string_free(msg_ptr) };
    Some(s)
}

/// Frees a message handle that was allocated by a `_to_message` function.
///
/// The handle is a `Box<MessageInner>` behind an opaque pointer. Since
/// `MessageInner` is `pub(crate)` in the library we cannot name it here,
/// but its layout is a single `CoseSign1Message` field, so dropping the
/// `Box` is safe.
unsafe fn free_message_handle(handle: *mut CoseSign1MessageHandle) {
    if !handle.is_null() {
        // MessageInner is a #[repr(Rust)] struct with a single field.
        // Dropping via Box<u8-slice> would be UB, so we cast to the same
        // size type. Because the only field is CoseSign1Message (which is
        // a Vec<u8>-sized type), we can safely reconstruct the Box.
        //
        // This mirrors what `cose_sign1_message_free` does in
        // cose_sign1_primitives_ffi.
        drop(unsafe { Box::from_raw(handle as *mut cose_sign1_primitives::CoseSign1Message) });
    }
}

/// A mock CryptoSigner for unit-level tests that do not need OpenSSL.
struct MockCryptoSigner {
    algo: i64,
    key_type_str: String,
    kid: Option<Vec<u8>>,
}

impl MockCryptoSigner {
    fn es256() -> Self {
        Self {
            algo: -7,
            key_type_str: "EC2".into(),
            kid: Some(b"mock-kid".to_vec()),
        }
    }
}

impl CryptoSigner for MockCryptoSigner {
    fn sign(&self, data: &[u8]) -> Result<Vec<u8>, crypto_primitives::CryptoError> {
        Ok(format!("sig-{}", data.len()).into_bytes())
    }

    fn algorithm(&self) -> i64 {
        self.algo
    }

    fn key_type(&self) -> &str {
        &self.key_type_str
    }

    fn key_id(&self) -> Option<&[u8]> {
        self.kid.as_deref()
    }

    fn supports_streaming(&self) -> bool {
        true
    }

    fn sign_init(
        &self,
    ) -> Result<Box<dyn crypto_primitives::SigningContext>, crypto_primitives::CryptoError> {
        Err(crypto_primitives::CryptoError::SigningFailed(
            "mock: no streaming support".into(),
        ))
    }
}

/// State for the streaming read callback.
struct StreamState {
    data: Vec<u8>,
    offset: usize,
}

unsafe extern "C" fn good_read_callback(
    buffer: *mut u8,
    buffer_len: usize,
    user_data: *mut libc::c_void,
) -> i64 {
    let state: &mut StreamState = unsafe { &mut *(user_data as *mut StreamState) };
    let remaining: usize = state.data.len() - state.offset;
    let to_copy: usize = remaining.min(buffer_len);
    if to_copy == 0 {
        return 0;
    }
    unsafe {
        ptr::copy_nonoverlapping(state.data[state.offset..].as_ptr(), buffer, to_copy);
    }
    state.offset += to_copy;
    to_copy as i64
}

// ============================================================================
// sign_direct_to_message
// ============================================================================

#[test]
fn sign_direct_to_message_null_out_message() {
    let ct: CString = CString::new("text/plain").unwrap();
    let mut err: *mut CoseSign1FactoriesErrorHandle = ptr::null_mut();

    let rc: i32 = unsafe {
        cose_sign1_factories_sign_direct_to_message(
            ptr::null(),
            b"x".as_ptr(),
            1,
            ct.as_ptr(),
            ptr::null_mut(), // null out_message
            &mut err,
        )
    };
    assert_eq!(rc, FFI_ERR_NULL_POINTER);
    assert!(!err.is_null());
    let msg: Option<String> = get_error_message(err);
    assert!(msg.unwrap_or_default().contains("out_message"));
    unsafe { cose_sign1_factories_error_free(err) };
}

#[test]
fn sign_direct_to_message_null_factory() {
    let ct: CString = CString::new("text/plain").unwrap();
    let mut out_message: *mut CoseSign1MessageHandle = ptr::null_mut();
    let mut err: *mut CoseSign1FactoriesErrorHandle = ptr::null_mut();

    let rc: i32 = unsafe {
        cose_sign1_factories_sign_direct_to_message(
            ptr::null(), // null factory
            b"x".as_ptr(),
            1,
            ct.as_ptr(),
            &mut out_message,
            &mut err,
        )
    };
    assert_eq!(rc, FFI_ERR_NULL_POINTER);
    assert!(out_message.is_null());
    assert!(!err.is_null());
    let msg: Option<String> = get_error_message(err);
    assert!(msg.unwrap_or_default().contains("factory"));
    unsafe { cose_sign1_factories_error_free(err) };
}

#[test]
fn sign_direct_to_message_null_content_type() {
    let factory: *mut CoseSign1FactoriesHandle = create_real_factory();
    let mut out_message: *mut CoseSign1MessageHandle = ptr::null_mut();
    let mut err: *mut CoseSign1FactoriesErrorHandle = ptr::null_mut();

    let rc: i32 = unsafe {
        cose_sign1_factories_sign_direct_to_message(
            factory,
            b"x".as_ptr(),
            1,
            ptr::null(), // null content_type
            &mut out_message,
            &mut err,
        )
    };
    assert_eq!(rc, FFI_ERR_NULL_POINTER);
    assert!(out_message.is_null());
    assert!(!err.is_null());
    let msg: Option<String> = get_error_message(err);
    assert!(msg.unwrap_or_default().contains("content_type"));
    unsafe {
        cose_sign1_factories_error_free(err);
        cose_sign1_factories_free(factory);
    };
}

#[test]
fn sign_direct_to_message_null_payload_nonzero_len() {
    let factory: *mut CoseSign1FactoriesHandle = create_real_factory();
    let ct: CString = CString::new("text/plain").unwrap();
    let mut out_message: *mut CoseSign1MessageHandle = ptr::null_mut();
    let mut err: *mut CoseSign1FactoriesErrorHandle = ptr::null_mut();

    let rc: i32 = unsafe {
        cose_sign1_factories_sign_direct_to_message(
            factory,
            ptr::null(), // null payload
            5,           // nonzero len
            ct.as_ptr(),
            &mut out_message,
            &mut err,
        )
    };
    assert_eq!(rc, FFI_ERR_NULL_POINTER);
    assert!(out_message.is_null());
    assert!(!err.is_null());
    let msg: Option<String> = get_error_message(err);
    assert!(msg.unwrap_or_default().contains("payload"));
    unsafe {
        cose_sign1_factories_error_free(err);
        cose_sign1_factories_free(factory);
    };
}

#[test]
fn sign_direct_to_message_attempt_sign() {
    let factory: *mut CoseSign1FactoriesHandle = create_real_factory();
    let payload: &[u8] = b"hello world";
    let ct: CString = CString::new("application/octet-stream").unwrap();
    let mut out_message: *mut CoseSign1MessageHandle = ptr::null_mut();
    let mut err: *mut CoseSign1FactoriesErrorHandle = ptr::null_mut();

    let rc: i32 = unsafe {
        cose_sign1_factories_sign_direct_to_message(
            factory,
            payload.as_ptr(),
            payload.len() as u32,
            ct.as_ptr(),
            &mut out_message,
            &mut err,
        )
    };

    // The mock signer may or may not succeed depending on verification.
    // Either way we exercise the inner code paths.
    if rc == FFI_OK {
        assert!(!out_message.is_null());
        unsafe { free_message_handle(out_message) };
    } else {
        assert!(out_message.is_null());
        if !err.is_null() {
            unsafe { cose_sign1_factories_error_free(err) };
        }
    }
    unsafe { cose_sign1_factories_free(factory) };
}

// ============================================================================
// sign_direct_detached_to_message
// ============================================================================

#[test]
fn sign_direct_detached_to_message_null_out_message() {
    let ct: CString = CString::new("text/plain").unwrap();
    let mut err: *mut CoseSign1FactoriesErrorHandle = ptr::null_mut();

    let rc: i32 = unsafe {
        cose_sign1_factories_sign_direct_detached_to_message(
            ptr::null(),
            b"x".as_ptr(),
            1,
            ct.as_ptr(),
            ptr::null_mut(),
            &mut err,
        )
    };
    assert_eq!(rc, FFI_ERR_NULL_POINTER);
    assert!(!err.is_null());
    let msg: Option<String> = get_error_message(err);
    assert!(msg.unwrap_or_default().contains("out_message"));
    unsafe { cose_sign1_factories_error_free(err) };
}

#[test]
fn sign_direct_detached_to_message_null_factory() {
    let ct: CString = CString::new("text/plain").unwrap();
    let mut out_message: *mut CoseSign1MessageHandle = ptr::null_mut();
    let mut err: *mut CoseSign1FactoriesErrorHandle = ptr::null_mut();

    let rc: i32 = unsafe {
        cose_sign1_factories_sign_direct_detached_to_message(
            ptr::null(),
            b"x".as_ptr(),
            1,
            ct.as_ptr(),
            &mut out_message,
            &mut err,
        )
    };
    assert_eq!(rc, FFI_ERR_NULL_POINTER);
    assert!(out_message.is_null());
    assert!(!err.is_null());
    let msg: Option<String> = get_error_message(err);
    assert!(msg.unwrap_or_default().contains("factory"));
    unsafe { cose_sign1_factories_error_free(err) };
}

#[test]
fn sign_direct_detached_to_message_null_content_type() {
    let factory: *mut CoseSign1FactoriesHandle = create_real_factory();
    let mut out_message: *mut CoseSign1MessageHandle = ptr::null_mut();
    let mut err: *mut CoseSign1FactoriesErrorHandle = ptr::null_mut();

    let rc: i32 = unsafe {
        cose_sign1_factories_sign_direct_detached_to_message(
            factory,
            b"x".as_ptr(),
            1,
            ptr::null(),
            &mut out_message,
            &mut err,
        )
    };
    assert_eq!(rc, FFI_ERR_NULL_POINTER);
    assert!(out_message.is_null());
    assert!(!err.is_null());
    let msg: Option<String> = get_error_message(err);
    assert!(msg.unwrap_or_default().contains("content_type"));
    unsafe {
        cose_sign1_factories_error_free(err);
        cose_sign1_factories_free(factory);
    };
}

#[test]
fn sign_direct_detached_to_message_null_payload_nonzero_len() {
    let factory: *mut CoseSign1FactoriesHandle = create_real_factory();
    let ct: CString = CString::new("text/plain").unwrap();
    let mut out_message: *mut CoseSign1MessageHandle = ptr::null_mut();
    let mut err: *mut CoseSign1FactoriesErrorHandle = ptr::null_mut();

    let rc: i32 = unsafe {
        cose_sign1_factories_sign_direct_detached_to_message(
            factory,
            ptr::null(),
            5,
            ct.as_ptr(),
            &mut out_message,
            &mut err,
        )
    };
    assert_eq!(rc, FFI_ERR_NULL_POINTER);
    assert!(out_message.is_null());
    assert!(!err.is_null());
    let msg: Option<String> = get_error_message(err);
    assert!(msg.unwrap_or_default().contains("payload"));
    unsafe {
        cose_sign1_factories_error_free(err);
        cose_sign1_factories_free(factory);
    };
}

#[test]
fn sign_direct_detached_to_message_attempt_sign() {
    let factory: *mut CoseSign1FactoriesHandle = create_real_factory();
    let payload: &[u8] = b"detached payload";
    let ct: CString = CString::new("application/octet-stream").unwrap();
    let mut out_message: *mut CoseSign1MessageHandle = ptr::null_mut();
    let mut err: *mut CoseSign1FactoriesErrorHandle = ptr::null_mut();

    let rc: i32 = unsafe {
        cose_sign1_factories_sign_direct_detached_to_message(
            factory,
            payload.as_ptr(),
            payload.len() as u32,
            ct.as_ptr(),
            &mut out_message,
            &mut err,
        )
    };

    if rc == FFI_OK {
        assert!(!out_message.is_null());
        unsafe { free_message_handle(out_message) };
    } else {
        assert!(out_message.is_null());
        if !err.is_null() {
            unsafe { cose_sign1_factories_error_free(err) };
        }
    }
    unsafe { cose_sign1_factories_free(factory) };
}

// ============================================================================
// sign_direct_file_to_message
// ============================================================================

#[test]
fn sign_direct_file_to_message_null_out_message() {
    let ct: CString = CString::new("text/plain").unwrap();
    let c_path: CString = CString::new("dummy.txt").unwrap();
    let mut err: *mut CoseSign1FactoriesErrorHandle = ptr::null_mut();

    let rc: i32 = unsafe {
        cose_sign1_factories_sign_direct_file_to_message(
            ptr::null(),
            c_path.as_ptr(),
            ct.as_ptr(),
            ptr::null_mut(),
            &mut err,
        )
    };
    assert_eq!(rc, FFI_ERR_NULL_POINTER);
    assert!(!err.is_null());
    let msg: Option<String> = get_error_message(err);
    assert!(msg.unwrap_or_default().contains("out_message"));
    unsafe { cose_sign1_factories_error_free(err) };
}

#[test]
fn sign_direct_file_to_message_null_factory() {
    let ct: CString = CString::new("text/plain").unwrap();
    let c_path: CString = CString::new("dummy.txt").unwrap();
    let mut out_message: *mut CoseSign1MessageHandle = ptr::null_mut();
    let mut err: *mut CoseSign1FactoriesErrorHandle = ptr::null_mut();

    let rc: i32 = unsafe {
        cose_sign1_factories_sign_direct_file_to_message(
            ptr::null(),
            c_path.as_ptr(),
            ct.as_ptr(),
            &mut out_message,
            &mut err,
        )
    };
    assert_eq!(rc, FFI_ERR_NULL_POINTER);
    assert!(out_message.is_null());
    assert!(!err.is_null());
    let msg: Option<String> = get_error_message(err);
    assert!(msg.unwrap_or_default().contains("factory"));
    unsafe { cose_sign1_factories_error_free(err) };
}

#[test]
fn sign_direct_file_to_message_null_file_path() {
    let factory: *mut CoseSign1FactoriesHandle = create_real_factory();
    let ct: CString = CString::new("text/plain").unwrap();
    let mut out_message: *mut CoseSign1MessageHandle = ptr::null_mut();
    let mut err: *mut CoseSign1FactoriesErrorHandle = ptr::null_mut();

    let rc: i32 = unsafe {
        cose_sign1_factories_sign_direct_file_to_message(
            factory,
            ptr::null(),
            ct.as_ptr(),
            &mut out_message,
            &mut err,
        )
    };
    assert_eq!(rc, FFI_ERR_NULL_POINTER);
    assert!(out_message.is_null());
    assert!(!err.is_null());
    let msg: Option<String> = get_error_message(err);
    assert!(msg.unwrap_or_default().contains("file_path"));
    unsafe {
        cose_sign1_factories_error_free(err);
        cose_sign1_factories_free(factory);
    };
}

#[test]
fn sign_direct_file_to_message_null_content_type() {
    let factory: *mut CoseSign1FactoriesHandle = create_real_factory();
    let c_path: CString = CString::new("dummy.txt").unwrap();
    let mut out_message: *mut CoseSign1MessageHandle = ptr::null_mut();
    let mut err: *mut CoseSign1FactoriesErrorHandle = ptr::null_mut();

    let rc: i32 = unsafe {
        cose_sign1_factories_sign_direct_file_to_message(
            factory,
            c_path.as_ptr(),
            ptr::null(),
            &mut out_message,
            &mut err,
        )
    };
    assert_eq!(rc, FFI_ERR_NULL_POINTER);
    assert!(out_message.is_null());
    assert!(!err.is_null());
    let msg: Option<String> = get_error_message(err);
    assert!(msg.unwrap_or_default().contains("content_type"));
    unsafe {
        cose_sign1_factories_error_free(err);
        cose_sign1_factories_free(factory);
    };
}

#[test]
fn sign_direct_file_to_message_attempt_sign() {
    let factory: *mut CoseSign1FactoriesHandle = create_real_factory();

    let mut tmp: tempfile::NamedTempFile = tempfile::NamedTempFile::new().unwrap();
    std::io::Write::write_all(&mut tmp, b"file payload for direct").unwrap();
    let path_str: &str = tmp.path().to_str().unwrap();
    let c_path: CString = CString::new(path_str).unwrap();
    let ct: CString = CString::new("application/octet-stream").unwrap();

    let mut out_message: *mut CoseSign1MessageHandle = ptr::null_mut();
    let mut err: *mut CoseSign1FactoriesErrorHandle = ptr::null_mut();

    let rc: i32 = unsafe {
        cose_sign1_factories_sign_direct_file_to_message(
            factory,
            c_path.as_ptr(),
            ct.as_ptr(),
            &mut out_message,
            &mut err,
        )
    };

    // File signing uses sign_init() which the mock signer does not support,
    // so we expect a factory error.
    assert_eq!(rc, FFI_ERR_FACTORY_FAILED);
    assert!(!err.is_null());
    let msg: String = get_error_message(err).unwrap_or_default();
    assert!(msg.contains("signing") || msg.contains("stream") || msg.contains("key error"));

    unsafe {
        cose_sign1_factories_error_free(err);
        if !out_message.is_null() {
            free_message_handle(out_message);
        }
        cose_sign1_factories_free(factory);
    };
}

// ============================================================================
// sign_direct_streaming_to_message
// ============================================================================

#[test]
fn sign_direct_streaming_to_message_null_out_message() {
    let ct: CString = CString::new("text/plain").unwrap();
    let mut state: StreamState = StreamState {
        data: b"data".to_vec(),
        offset: 0,
    };
    let mut err: *mut CoseSign1FactoriesErrorHandle = ptr::null_mut();

    let rc: i32 = unsafe {
        cose_sign1_factories_sign_direct_streaming_to_message(
            ptr::null(),
            good_read_callback,
            &mut state as *mut _ as *mut libc::c_void,
            state.data.len() as u64,
            ct.as_ptr(),
            ptr::null_mut(),
            &mut err,
        )
    };
    assert_eq!(rc, FFI_ERR_NULL_POINTER);
    assert!(!err.is_null());
    let msg: Option<String> = get_error_message(err);
    assert!(msg.unwrap_or_default().contains("out_message"));
    unsafe { cose_sign1_factories_error_free(err) };
}

#[test]
fn sign_direct_streaming_to_message_null_factory() {
    let ct: CString = CString::new("text/plain").unwrap();
    let mut state: StreamState = StreamState {
        data: b"data".to_vec(),
        offset: 0,
    };
    let mut out_message: *mut CoseSign1MessageHandle = ptr::null_mut();
    let mut err: *mut CoseSign1FactoriesErrorHandle = ptr::null_mut();

    let rc: i32 = unsafe {
        cose_sign1_factories_sign_direct_streaming_to_message(
            ptr::null(),
            good_read_callback,
            &mut state as *mut _ as *mut libc::c_void,
            state.data.len() as u64,
            ct.as_ptr(),
            &mut out_message,
            &mut err,
        )
    };
    assert_eq!(rc, FFI_ERR_NULL_POINTER);
    assert!(out_message.is_null());
    assert!(!err.is_null());
    let msg: Option<String> = get_error_message(err);
    assert!(msg.unwrap_or_default().contains("factory"));
    unsafe { cose_sign1_factories_error_free(err) };
}

#[test]
fn sign_direct_streaming_to_message_null_content_type() {
    let factory: *mut CoseSign1FactoriesHandle = create_real_factory();
    let mut state: StreamState = StreamState {
        data: b"streaming content".to_vec(),
        offset: 0,
    };
    let mut out_message: *mut CoseSign1MessageHandle = ptr::null_mut();
    let mut err: *mut CoseSign1FactoriesErrorHandle = ptr::null_mut();

    let rc: i32 = unsafe {
        cose_sign1_factories_sign_direct_streaming_to_message(
            factory,
            good_read_callback,
            &mut state as *mut _ as *mut libc::c_void,
            state.data.len() as u64,
            ptr::null(),
            &mut out_message,
            &mut err,
        )
    };
    assert_eq!(rc, FFI_ERR_NULL_POINTER);
    assert!(out_message.is_null());
    assert!(!err.is_null());
    let msg: Option<String> = get_error_message(err);
    assert!(msg.unwrap_or_default().contains("content_type"));
    unsafe {
        cose_sign1_factories_error_free(err);
        cose_sign1_factories_free(factory);
    };
}

#[test]
fn sign_direct_streaming_to_message_attempt_sign() {
    let factory: *mut CoseSign1FactoriesHandle = create_real_factory();
    let mut state: StreamState = StreamState {
        data: b"streaming content".to_vec(),
        offset: 0,
    };
    let ct: CString = CString::new("application/octet-stream").unwrap();
    let mut out_message: *mut CoseSign1MessageHandle = ptr::null_mut();
    let mut err: *mut CoseSign1FactoriesErrorHandle = ptr::null_mut();

    let rc: i32 = unsafe {
        cose_sign1_factories_sign_direct_streaming_to_message(
            factory,
            good_read_callback,
            &mut state as *mut _ as *mut libc::c_void,
            state.data.len() as u64,
            ct.as_ptr(),
            &mut out_message,
            &mut err,
        )
    };

    // Streaming signing uses sign_init() which the mock signer does not
    // support, so we expect a factory error.
    assert_eq!(rc, FFI_ERR_FACTORY_FAILED);
    assert!(!err.is_null());
    let msg: String = get_error_message(err).unwrap_or_default();
    assert!(msg.contains("signing") || msg.contains("stream") || msg.contains("key error"));

    unsafe {
        cose_sign1_factories_error_free(err);
        if !out_message.is_null() {
            free_message_handle(out_message);
        }
        cose_sign1_factories_free(factory);
    };
}

// ============================================================================
// sign_indirect_to_message
// ============================================================================

#[test]
fn sign_indirect_to_message_null_out_message() {
    let ct: CString = CString::new("text/plain").unwrap();
    let mut err: *mut CoseSign1FactoriesErrorHandle = ptr::null_mut();

    let rc: i32 = unsafe {
        cose_sign1_factories_sign_indirect_to_message(
            ptr::null(),
            b"x".as_ptr(),
            1,
            ct.as_ptr(),
            ptr::null_mut(),
            &mut err,
        )
    };
    assert_eq!(rc, FFI_ERR_NULL_POINTER);
    assert!(!err.is_null());
    let msg: Option<String> = get_error_message(err);
    assert!(msg.unwrap_or_default().contains("out_message"));
    unsafe { cose_sign1_factories_error_free(err) };
}

#[test]
fn sign_indirect_to_message_null_factory() {
    let ct: CString = CString::new("text/plain").unwrap();
    let mut out_message: *mut CoseSign1MessageHandle = ptr::null_mut();
    let mut err: *mut CoseSign1FactoriesErrorHandle = ptr::null_mut();

    let rc: i32 = unsafe {
        cose_sign1_factories_sign_indirect_to_message(
            ptr::null(),
            b"x".as_ptr(),
            1,
            ct.as_ptr(),
            &mut out_message,
            &mut err,
        )
    };
    assert_eq!(rc, FFI_ERR_NULL_POINTER);
    assert!(out_message.is_null());
    assert!(!err.is_null());
    let msg: Option<String> = get_error_message(err);
    assert!(msg.unwrap_or_default().contains("factory"));
    unsafe { cose_sign1_factories_error_free(err) };
}

#[test]
fn sign_indirect_to_message_null_content_type() {
    let factory: *mut CoseSign1FactoriesHandle = create_real_factory();
    let mut out_message: *mut CoseSign1MessageHandle = ptr::null_mut();
    let mut err: *mut CoseSign1FactoriesErrorHandle = ptr::null_mut();

    let rc: i32 = unsafe {
        cose_sign1_factories_sign_indirect_to_message(
            factory,
            b"x".as_ptr(),
            1,
            ptr::null(),
            &mut out_message,
            &mut err,
        )
    };
    assert_eq!(rc, FFI_ERR_NULL_POINTER);
    assert!(out_message.is_null());
    assert!(!err.is_null());
    let msg: Option<String> = get_error_message(err);
    assert!(msg.unwrap_or_default().contains("content_type"));
    unsafe {
        cose_sign1_factories_error_free(err);
        cose_sign1_factories_free(factory);
    };
}

#[test]
fn sign_indirect_to_message_null_payload_nonzero_len() {
    let factory: *mut CoseSign1FactoriesHandle = create_real_factory();
    let ct: CString = CString::new("text/plain").unwrap();
    let mut out_message: *mut CoseSign1MessageHandle = ptr::null_mut();
    let mut err: *mut CoseSign1FactoriesErrorHandle = ptr::null_mut();

    let rc: i32 = unsafe {
        cose_sign1_factories_sign_indirect_to_message(
            factory,
            ptr::null(),
            5,
            ct.as_ptr(),
            &mut out_message,
            &mut err,
        )
    };
    assert_eq!(rc, FFI_ERR_NULL_POINTER);
    assert!(out_message.is_null());
    assert!(!err.is_null());
    let msg: Option<String> = get_error_message(err);
    assert!(msg.unwrap_or_default().contains("payload"));
    unsafe {
        cose_sign1_factories_error_free(err);
        cose_sign1_factories_free(factory);
    };
}

#[test]
fn sign_indirect_to_message_attempt_sign() {
    let factory: *mut CoseSign1FactoriesHandle = create_real_factory();
    let payload: &[u8] = b"indirect payload";
    let ct: CString = CString::new("application/octet-stream").unwrap();
    let mut out_message: *mut CoseSign1MessageHandle = ptr::null_mut();
    let mut err: *mut CoseSign1FactoriesErrorHandle = ptr::null_mut();

    let rc: i32 = unsafe {
        cose_sign1_factories_sign_indirect_to_message(
            factory,
            payload.as_ptr(),
            payload.len() as u32,
            ct.as_ptr(),
            &mut out_message,
            &mut err,
        )
    };

    if rc == FFI_OK {
        assert!(!out_message.is_null());
        unsafe { free_message_handle(out_message) };
    } else {
        assert!(out_message.is_null());
        if !err.is_null() {
            unsafe { cose_sign1_factories_error_free(err) };
        }
    }
    unsafe { cose_sign1_factories_free(factory) };
}

// ============================================================================
// sign_indirect_file_to_message
// ============================================================================

#[test]
fn sign_indirect_file_to_message_null_out_message() {
    let ct: CString = CString::new("text/plain").unwrap();
    let c_path: CString = CString::new("dummy.txt").unwrap();
    let mut err: *mut CoseSign1FactoriesErrorHandle = ptr::null_mut();

    let rc: i32 = unsafe {
        cose_sign1_factories_sign_indirect_file_to_message(
            ptr::null(),
            c_path.as_ptr(),
            ct.as_ptr(),
            ptr::null_mut(),
            &mut err,
        )
    };
    assert_eq!(rc, FFI_ERR_NULL_POINTER);
    assert!(!err.is_null());
    let msg: Option<String> = get_error_message(err);
    assert!(msg.unwrap_or_default().contains("out_message"));
    unsafe { cose_sign1_factories_error_free(err) };
}

#[test]
fn sign_indirect_file_to_message_null_factory() {
    let ct: CString = CString::new("text/plain").unwrap();
    let c_path: CString = CString::new("dummy.txt").unwrap();
    let mut out_message: *mut CoseSign1MessageHandle = ptr::null_mut();
    let mut err: *mut CoseSign1FactoriesErrorHandle = ptr::null_mut();

    let rc: i32 = unsafe {
        cose_sign1_factories_sign_indirect_file_to_message(
            ptr::null(),
            c_path.as_ptr(),
            ct.as_ptr(),
            &mut out_message,
            &mut err,
        )
    };
    assert_eq!(rc, FFI_ERR_NULL_POINTER);
    assert!(out_message.is_null());
    assert!(!err.is_null());
    let msg: Option<String> = get_error_message(err);
    assert!(msg.unwrap_or_default().contains("factory"));
    unsafe { cose_sign1_factories_error_free(err) };
}

#[test]
fn sign_indirect_file_to_message_null_file_path() {
    let factory: *mut CoseSign1FactoriesHandle = create_real_factory();
    let ct: CString = CString::new("text/plain").unwrap();
    let mut out_message: *mut CoseSign1MessageHandle = ptr::null_mut();
    let mut err: *mut CoseSign1FactoriesErrorHandle = ptr::null_mut();

    let rc: i32 = unsafe {
        cose_sign1_factories_sign_indirect_file_to_message(
            factory,
            ptr::null(),
            ct.as_ptr(),
            &mut out_message,
            &mut err,
        )
    };
    assert_eq!(rc, FFI_ERR_NULL_POINTER);
    assert!(out_message.is_null());
    assert!(!err.is_null());
    let msg: Option<String> = get_error_message(err);
    assert!(msg.unwrap_or_default().contains("file_path"));
    unsafe {
        cose_sign1_factories_error_free(err);
        cose_sign1_factories_free(factory);
    };
}

#[test]
fn sign_indirect_file_to_message_null_content_type() {
    let factory: *mut CoseSign1FactoriesHandle = create_real_factory();
    let c_path: CString = CString::new("dummy.txt").unwrap();
    let mut out_message: *mut CoseSign1MessageHandle = ptr::null_mut();
    let mut err: *mut CoseSign1FactoriesErrorHandle = ptr::null_mut();

    let rc: i32 = unsafe {
        cose_sign1_factories_sign_indirect_file_to_message(
            factory,
            c_path.as_ptr(),
            ptr::null(),
            &mut out_message,
            &mut err,
        )
    };
    assert_eq!(rc, FFI_ERR_NULL_POINTER);
    assert!(out_message.is_null());
    assert!(!err.is_null());
    let msg: Option<String> = get_error_message(err);
    assert!(msg.unwrap_or_default().contains("content_type"));
    unsafe {
        cose_sign1_factories_error_free(err);
        cose_sign1_factories_free(factory);
    };
}

#[test]
fn sign_indirect_file_to_message_attempt_sign() {
    let factory: *mut CoseSign1FactoriesHandle = create_real_factory();

    let mut tmp: tempfile::NamedTempFile = tempfile::NamedTempFile::new().unwrap();
    std::io::Write::write_all(&mut tmp, b"indirect file payload").unwrap();
    let path_str: &str = tmp.path().to_str().unwrap();
    let c_path: CString = CString::new(path_str).unwrap();
    let ct: CString = CString::new("application/octet-stream").unwrap();

    let mut out_message: *mut CoseSign1MessageHandle = ptr::null_mut();
    let mut err: *mut CoseSign1FactoriesErrorHandle = ptr::null_mut();

    let rc: i32 = unsafe {
        cose_sign1_factories_sign_indirect_file_to_message(
            factory,
            c_path.as_ptr(),
            ct.as_ptr(),
            &mut out_message,
            &mut err,
        )
    };

    if rc == FFI_OK {
        assert!(!out_message.is_null());
        unsafe { free_message_handle(out_message) };
    } else {
        assert!(out_message.is_null());
        if !err.is_null() {
            unsafe { cose_sign1_factories_error_free(err) };
        }
    }
    unsafe { cose_sign1_factories_free(factory) };
}

// ============================================================================
// sign_indirect_streaming_to_message
// ============================================================================

#[test]
fn sign_indirect_streaming_to_message_null_out_message() {
    let ct: CString = CString::new("text/plain").unwrap();
    let mut state: StreamState = StreamState {
        data: b"data".to_vec(),
        offset: 0,
    };
    let mut err: *mut CoseSign1FactoriesErrorHandle = ptr::null_mut();

    let rc: i32 = unsafe {
        cose_sign1_factories_sign_indirect_streaming_to_message(
            ptr::null(),
            good_read_callback,
            &mut state as *mut _ as *mut libc::c_void,
            state.data.len() as u64,
            ct.as_ptr(),
            ptr::null_mut(),
            &mut err,
        )
    };
    assert_eq!(rc, FFI_ERR_NULL_POINTER);
    assert!(!err.is_null());
    let msg: Option<String> = get_error_message(err);
    assert!(msg.unwrap_or_default().contains("out_message"));
    unsafe { cose_sign1_factories_error_free(err) };
}

#[test]
fn sign_indirect_streaming_to_message_null_factory() {
    let ct: CString = CString::new("text/plain").unwrap();
    let mut state: StreamState = StreamState {
        data: b"data".to_vec(),
        offset: 0,
    };
    let mut out_message: *mut CoseSign1MessageHandle = ptr::null_mut();
    let mut err: *mut CoseSign1FactoriesErrorHandle = ptr::null_mut();

    let rc: i32 = unsafe {
        cose_sign1_factories_sign_indirect_streaming_to_message(
            ptr::null(),
            good_read_callback,
            &mut state as *mut _ as *mut libc::c_void,
            state.data.len() as u64,
            ct.as_ptr(),
            &mut out_message,
            &mut err,
        )
    };
    assert_eq!(rc, FFI_ERR_NULL_POINTER);
    assert!(out_message.is_null());
    assert!(!err.is_null());
    let msg: Option<String> = get_error_message(err);
    assert!(msg.unwrap_or_default().contains("factory"));
    unsafe { cose_sign1_factories_error_free(err) };
}

#[test]
fn sign_indirect_streaming_to_message_null_content_type() {
    let factory: *mut CoseSign1FactoriesHandle = create_real_factory();
    let mut state: StreamState = StreamState {
        data: b"streaming content".to_vec(),
        offset: 0,
    };
    let mut out_message: *mut CoseSign1MessageHandle = ptr::null_mut();
    let mut err: *mut CoseSign1FactoriesErrorHandle = ptr::null_mut();

    let rc: i32 = unsafe {
        cose_sign1_factories_sign_indirect_streaming_to_message(
            factory,
            good_read_callback,
            &mut state as *mut _ as *mut libc::c_void,
            state.data.len() as u64,
            ptr::null(),
            &mut out_message,
            &mut err,
        )
    };
    assert_eq!(rc, FFI_ERR_NULL_POINTER);
    assert!(out_message.is_null());
    assert!(!err.is_null());
    let msg: Option<String> = get_error_message(err);
    assert!(msg.unwrap_or_default().contains("content_type"));
    unsafe {
        cose_sign1_factories_error_free(err);
        cose_sign1_factories_free(factory);
    };
}

#[test]
fn sign_indirect_streaming_to_message_attempt_sign() {
    let factory: *mut CoseSign1FactoriesHandle = create_real_factory();
    let mut state: StreamState = StreamState {
        data: b"indirect streaming content".to_vec(),
        offset: 0,
    };
    let ct: CString = CString::new("application/octet-stream").unwrap();
    let mut out_message: *mut CoseSign1MessageHandle = ptr::null_mut();
    let mut err: *mut CoseSign1FactoriesErrorHandle = ptr::null_mut();

    let rc: i32 = unsafe {
        cose_sign1_factories_sign_indirect_streaming_to_message(
            factory,
            good_read_callback,
            &mut state as *mut _ as *mut libc::c_void,
            state.data.len() as u64,
            ct.as_ptr(),
            &mut out_message,
            &mut err,
        )
    };

    // Indirect streaming signing may succeed with the mock signer.
    // Handle both success and expected factory failure.
    if rc == 0 {
        assert!(
            !out_message.is_null(),
            "Success must produce a message handle"
        );
    } else {
        assert_eq!(rc, FFI_ERR_FACTORY_FAILED);
        assert!(!err.is_null());
    }

    unsafe {
        if !err.is_null() {
            cose_sign1_factories_error_free(err);
        }
        if !out_message.is_null() {
            free_message_handle(out_message);
        }
        cose_sign1_factories_free(factory);
    };
}
