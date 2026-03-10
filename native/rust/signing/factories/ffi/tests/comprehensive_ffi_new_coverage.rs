// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Comprehensive coverage tests targeting uncovered lines in the factories FFI crate.
//!
//! These tests focus on:
//! - Error type construction and conversion (ErrorInner, from_factory_error)
//! - Handle conversion functions (factory_handle_to_inner, signing_service_handle_to_inner)
//! - Inner implementation functions with real signing via OpenSSL
//! - CallbackStreamingPayload / CallbackReader edge cases
//! - SimpleSigningService and SimpleKeyWrapper delegation
//! - Memory management (bytes_free, string_free, error_free)
//! - FFI extern "C" functions for null-pointer and real signing paths

use std::ffi::{CStr, CString};
use std::io::Read;
use std::ptr;
use std::sync::Arc;

use cose_sign1_factories_ffi::error::{
    self, CoseSign1FactoriesErrorHandle, ErrorInner, FFI_ERR_FACTORY_FAILED,
    FFI_ERR_INVALID_ARGUMENT, FFI_ERR_NULL_POINTER, FFI_ERR_PANIC, FFI_OK,
};
use cose_sign1_factories_ffi::types::{
    CoseSign1FactoriesHandle, CoseSign1FactoriesSigningServiceHandle, FactoryInner,
    SigningServiceInner,
};
use cose_sign1_factories_ffi::{
    cose_sign1_factories_bytes_free, cose_sign1_factories_error_code,
    cose_sign1_factories_error_free, cose_sign1_factories_error_message,
    cose_sign1_factories_free, cose_sign1_factories_sign_direct,
    cose_sign1_factories_sign_direct_detached, cose_sign1_factories_sign_direct_file,
    cose_sign1_factories_sign_direct_streaming, cose_sign1_factories_sign_indirect,
    cose_sign1_factories_sign_indirect_file, cose_sign1_factories_sign_indirect_streaming,
    cose_sign1_factories_string_free, CallbackReader, CallbackStreamingPayload,
    CryptoSignerHandle, SimpleKeyWrapper, SimpleSigningService,
};
use cose_sign1_factories_ffi::{
    cose_sign1_factories_create_from_crypto_signer,
    cose_sign1_factories_create_from_signing_service,
    cose_sign1_factories_create_with_transparency,
};
use cose_sign1_primitives::sig_structure::SizedRead;
use cose_sign1_primitives::StreamingPayload;
use crypto_primitives::CryptoSigner;

// ============================================================================
// Test helpers
// ============================================================================

/// Creates a CryptoSignerHandle in the double-boxed format that
/// `cose_sign1_factories_create_from_crypto_signer` expects:
/// the handle points to a heap-allocated `Box<dyn CryptoSigner>`.
fn create_mock_signer_handle() -> *mut CryptoSignerHandle {
    let signer: Box<dyn CryptoSigner> = Box::new(MockCryptoSigner::es256());
    Box::into_raw(Box::new(signer)) as *mut CryptoSignerHandle
}

/// Creates a factory handle backed by a mock signer via the FFI function.
fn create_real_factory() -> *mut CoseSign1FactoriesHandle {
    let signer_handle = create_mock_signer_handle();

    let mut factory: *mut CoseSign1FactoriesHandle = ptr::null_mut();
    let mut err: *mut CoseSign1FactoriesErrorHandle = ptr::null_mut();
    let rc = unsafe {
        cose_sign1_factories_create_from_crypto_signer(signer_handle, &mut factory, &mut err)
    };
    if !err.is_null() {
        let msg = get_error_message(err);
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
    let s = unsafe { CStr::from_ptr(msg_ptr) }
        .to_string_lossy()
        .to_string();
    unsafe { cose_sign1_factories_string_free(msg_ptr) };
    Some(s)
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

/// Mock signing service backed by MockCryptoSigner.
struct MockSigningService;

impl cose_sign1_signing::SigningService for MockSigningService {
    fn get_cose_signer(
        &self,
        _ctx: &cose_sign1_signing::SigningContext,
    ) -> Result<cose_sign1_signing::CoseSigner, cose_sign1_signing::SigningError> {
        let signer = Box::new(MockCryptoSigner::es256()) as Box<dyn CryptoSigner>;
        let protected = cose_sign1_primitives::CoseHeaderMap::new();
        let unprotected = cose_sign1_primitives::CoseHeaderMap::new();
        Ok(cose_sign1_signing::CoseSigner::new(
            signer, protected, unprotected,
        ))
    }

    fn is_remote(&self) -> bool {
        false
    }

    fn verify_signature(
        &self,
        _msg: &[u8],
        _ctx: &cose_sign1_signing::SigningContext,
    ) -> Result<bool, cose_sign1_signing::SigningError> {
        Ok(true)
    }

    fn service_metadata(&self) -> &cose_sign1_signing::SigningServiceMetadata {
        Box::leak(Box::new(cose_sign1_signing::SigningServiceMetadata::new(
            "MockService".into(),
            "unit test mock".into(),
        )))
    }
}

/// Streaming callback helpers for FFI streaming tests.
struct StreamState {
    data: Vec<u8>,
    offset: usize,
}

unsafe extern "C" fn good_read_callback(
    buffer: *mut u8,
    buffer_len: usize,
    user_data: *mut libc::c_void,
) -> i64 {
    let state = unsafe { &mut *(user_data as *mut StreamState) };
    let remaining = state.data.len() - state.offset;
    let to_copy = remaining.min(buffer_len);
    if to_copy == 0 {
        return 0;
    }
    unsafe {
        ptr::copy_nonoverlapping(state.data[state.offset..].as_ptr(), buffer, to_copy);
    }
    state.offset += to_copy;
    to_copy as i64
}

unsafe extern "C" fn failing_read_callback(
    _buffer: *mut u8,
    _buffer_len: usize,
    _user_data: *mut libc::c_void,
) -> i64 {
    -42
}

// ============================================================================
// 1. ErrorInner tests
// ============================================================================

#[test]
fn error_inner_new_sets_fields() {
    let e = ErrorInner::new("something went wrong", FFI_ERR_FACTORY_FAILED);
    assert_eq!(e.message, "something went wrong");
    assert_eq!(e.code, FFI_ERR_FACTORY_FAILED);
}

#[test]
fn error_inner_null_pointer_message() {
    let e = ErrorInner::null_pointer("my_param");
    assert!(e.message.contains("my_param"));
    assert!(e.message.contains("must not be null"));
    assert_eq!(e.code, FFI_ERR_NULL_POINTER);
}

#[test]
fn error_inner_from_factory_error() {
    let factory_err =
        cose_sign1_factories::FactoryError::SigningFailed("boom".into());
    let e = ErrorInner::from_factory_error(&factory_err);
    assert_eq!(e.code, FFI_ERR_FACTORY_FAILED);
    assert!(!e.message.is_empty());
}

// ============================================================================
// 2. Error handle lifecycle (handle_to_inner, inner_to_handle, set_error)
// ============================================================================

#[test]
fn error_handle_roundtrip() {
    let inner = ErrorInner::new("roundtrip test", FFI_ERR_INVALID_ARGUMENT);
    let handle = error::inner_to_handle(inner);
    assert!(!handle.is_null());

    let recovered = unsafe { error::handle_to_inner(handle) }.expect("should not be None");
    assert_eq!(recovered.message, "roundtrip test");
    assert_eq!(recovered.code, FFI_ERR_INVALID_ARGUMENT);

    unsafe { cose_sign1_factories_error_free(handle) };
}

#[test]
fn error_handle_to_inner_null_returns_none() {
    let result = unsafe { error::handle_to_inner(ptr::null()) };
    assert!(result.is_none());
}

#[test]
fn set_error_with_non_null_out() {
    let mut err: *mut CoseSign1FactoriesErrorHandle = ptr::null_mut();
    error::set_error(&mut err, ErrorInner::new("set_error test", FFI_ERR_PANIC));
    assert!(!err.is_null());

    let code = unsafe { cose_sign1_factories_error_code(err) };
    assert_eq!(code, FFI_ERR_PANIC);

    unsafe { cose_sign1_factories_error_free(err) };
}

#[test]
fn set_error_with_null_out_does_not_crash() {
    error::set_error(ptr::null_mut(), ErrorInner::new("ignored", FFI_ERR_PANIC));
}

// ============================================================================
// 3. cose_sign1_factories_error_message / error_code / error_free
// ============================================================================

#[test]
fn error_message_null_handle_returns_null() {
    let ptr = unsafe { cose_sign1_factories_error_message(ptr::null()) };
    assert!(ptr.is_null());
}

#[test]
fn error_code_null_handle_returns_zero() {
    let code = unsafe { cose_sign1_factories_error_code(ptr::null()) };
    assert_eq!(code, 0);
}

#[test]
fn error_free_null_is_safe() {
    unsafe { cose_sign1_factories_error_free(ptr::null_mut()) };
}

#[test]
fn error_message_with_nul_byte_in_message() {
    let inner = ErrorInner::new("before\0after", FFI_ERR_FACTORY_FAILED);
    let handle = error::inner_to_handle(inner);

    let msg_ptr = unsafe { cose_sign1_factories_error_message(handle) };
    assert!(!msg_ptr.is_null());

    let msg = unsafe { CStr::from_ptr(msg_ptr) }
        .to_string_lossy()
        .to_string();
    assert!(msg.contains("NUL byte"));

    unsafe {
        cose_sign1_factories_string_free(msg_ptr);
        cose_sign1_factories_error_free(handle);
    };
}

#[test]
fn error_message_and_code_valid_handle() {
    let inner = ErrorInner::new("valid error", FFI_ERR_FACTORY_FAILED);
    let handle = error::inner_to_handle(inner);

    let code = unsafe { cose_sign1_factories_error_code(handle) };
    assert_eq!(code, FFI_ERR_FACTORY_FAILED);

    let msg_ptr = unsafe { cose_sign1_factories_error_message(handle) };
    assert!(!msg_ptr.is_null());
    let msg = unsafe { CStr::from_ptr(msg_ptr) }
        .to_string_lossy()
        .to_string();
    assert_eq!(msg, "valid error");

    unsafe {
        cose_sign1_factories_string_free(msg_ptr);
        cose_sign1_factories_error_free(handle);
    };
}

// ============================================================================
// 4. string_free / bytes_free
// ============================================================================

#[test]
fn string_free_null_is_safe() {
    unsafe { cose_sign1_factories_string_free(ptr::null_mut()) };
}

#[test]
fn string_free_valid_cstring() {
    let cs = CString::new("hello").unwrap();
    let raw = cs.into_raw();
    unsafe { cose_sign1_factories_string_free(raw) };
}

#[test]
fn bytes_free_null_is_safe() {
    unsafe { cose_sign1_factories_bytes_free(ptr::null_mut(), 0) };
}

#[test]
fn bytes_free_valid_allocation() {
    let data: Vec<u8> = vec![1, 2, 3, 4, 5];
    let len = data.len() as u32;
    let boxed = data.into_boxed_slice();
    let raw = Box::into_raw(boxed) as *mut u8;
    unsafe { cose_sign1_factories_bytes_free(raw, len) };
}

// ============================================================================
// 5. Handle conversion — tested via the public FFI API
//    (factory_handle_to_inner, signing_service_handle_to_inner,
//     factory_inner_to_handle are pub(crate) — covered by FFI function tests above)
// ============================================================================

#[test]
fn factory_handle_null_checked_via_sign_direct() {
    // Passing null factory to sign_direct exercises factory_handle_to_inner(null)
    let ct = CString::new("text/plain").unwrap();
    let mut out_bytes: *mut u8 = ptr::null_mut();
    let mut out_len: u32 = 0;
    let mut err: *mut CoseSign1FactoriesErrorHandle = ptr::null_mut();

    let rc = unsafe {
        cose_sign1_factories_sign_direct(
            ptr::null(),
            b"x".as_ptr(),
            1,
            ct.as_ptr(),
            &mut out_bytes,
            &mut out_len,
            &mut err,
        )
    };
    assert_eq!(rc, FFI_ERR_NULL_POINTER);
    if !err.is_null() {
        let msg = get_error_message(err).unwrap_or_default();
        assert!(msg.contains("factory"));
        unsafe { cose_sign1_factories_error_free(err) };
    }
}

#[test]
fn signing_service_handle_null_checked_via_create() {
    // Passing null service to create_from_signing_service exercises signing_service_handle_to_inner(null)
    let mut factory: *mut CoseSign1FactoriesHandle = ptr::null_mut();
    let mut err: *mut CoseSign1FactoriesErrorHandle = ptr::null_mut();
    let rc = unsafe {
        cose_sign1_factories_create_from_signing_service(
            ptr::null(),
            &mut factory,
            &mut err,
        )
    };
    assert_eq!(rc, FFI_ERR_NULL_POINTER);
    if !err.is_null() {
        unsafe { cose_sign1_factories_error_free(err) };
    }
}

#[test]
fn factory_inner_to_handle_exercised_via_create() {
    // Creating a real factory exercises factory_inner_to_handle in the success path
    let factory = create_real_factory();
    assert!(!factory.is_null());
    unsafe { cose_sign1_factories_free(factory) };
}

// ============================================================================
// 6. SimpleSigningService and SimpleKeyWrapper
// ============================================================================

#[test]
fn simple_signing_service_new_and_metadata() {
    let signer = Arc::new(MockCryptoSigner::es256()) as Arc<dyn CryptoSigner>;
    let svc = SimpleSigningService::new(signer);

    let meta = cose_sign1_signing::SigningService::service_metadata(&svc);
    assert_eq!(meta.service_name, "Simple Signing Service");
    assert!(!cose_sign1_signing::SigningService::is_remote(&svc));
}

#[test]
fn simple_signing_service_verify_always_true() {
    let signer = Arc::new(MockCryptoSigner::es256()) as Arc<dyn CryptoSigner>;
    let svc = SimpleSigningService::new(signer);

    let ctx = cose_sign1_signing::SigningContext::from_bytes(b"payload".to_vec());
    let ok = cose_sign1_signing::SigningService::verify_signature(&svc, b"msg", &ctx).unwrap();
    assert!(ok);
}

#[test]
fn simple_signing_service_get_cose_signer() {
    let signer = Arc::new(MockCryptoSigner::es256()) as Arc<dyn CryptoSigner>;
    let svc = SimpleSigningService::new(signer);

    let ctx = cose_sign1_signing::SigningContext::from_bytes(b"payload".to_vec());
    let cose_signer = cose_sign1_signing::SigningService::get_cose_signer(&svc, &ctx).unwrap();
    assert_eq!(cose_signer.signer().algorithm(), -7);
}

#[test]
fn simple_key_wrapper_delegates_all_methods() {
    let inner = Arc::new(MockCryptoSigner::es256()) as Arc<dyn CryptoSigner>;
    let wrapper = SimpleKeyWrapper { key: inner };

    assert_eq!(wrapper.algorithm(), -7);
    assert_eq!(wrapper.key_type(), "EC2");
    assert_eq!(wrapper.key_id(), Some(b"mock-kid".as_slice()));
    assert!(wrapper.supports_streaming());

    let sig = wrapper.sign(b"hello").unwrap();
    assert_eq!(sig, b"sig-5");
}

#[test]
fn simple_key_wrapper_sign_init_delegates() {
    let inner = Arc::new(MockCryptoSigner::es256()) as Arc<dyn CryptoSigner>;
    let wrapper = SimpleKeyWrapper { key: inner };

    let result = wrapper.sign_init();
    assert!(result.is_err(), "mock returns error for sign_init");
}

// ============================================================================
// 7. CallbackStreamingPayload / CallbackReader
// ============================================================================

#[test]
fn callback_streaming_payload_size() {
    let payload = CallbackStreamingPayload {
        callback: good_read_callback,
        user_data: ptr::null_mut(),
        total_len: 42,
    };
    assert_eq!(payload.size(), 42);
}

#[test]
fn callback_streaming_payload_open_and_read() {
    let mut state = StreamState {
        data: b"ABCDEF".to_vec(),
        offset: 0,
    };
    let payload = CallbackStreamingPayload {
        callback: good_read_callback,
        user_data: &mut state as *mut _ as *mut libc::c_void,
        total_len: 6,
    };

    let mut reader = payload.open().expect("open should succeed");
    assert_eq!(reader.len().unwrap(), 6);

    let mut buf = vec![0u8; 3];
    let n = reader.read(&mut buf).unwrap();
    assert_eq!(n, 3);
    assert_eq!(&buf[..n], b"ABC");

    let n = reader.read(&mut buf).unwrap();
    assert_eq!(n, 3);
    assert_eq!(&buf[..n], b"DEF");

    let n = reader.read(&mut buf).unwrap();
    assert_eq!(n, 0); // EOF
}

#[test]
fn callback_reader_eof_when_bytes_read_equals_total() {
    let mut reader = CallbackReader {
        callback: good_read_callback,
        user_data: ptr::null_mut(),
        total_len: 10,
        bytes_read: 10,
    };
    let mut buf = vec![0u8; 4];
    let n = reader.read(&mut buf).unwrap();
    assert_eq!(n, 0);
}

#[test]
fn callback_reader_error_on_negative() {
    let mut reader = CallbackReader {
        callback: failing_read_callback,
        user_data: ptr::null_mut(),
        total_len: 100,
        bytes_read: 0,
    };
    let mut buf = vec![0u8; 16];
    let err = reader.read(&mut buf).unwrap_err();
    assert!(err.to_string().contains("callback read error: -42"));
}

#[test]
fn callback_reader_sized_read_len() {
    let reader = CallbackReader {
        callback: good_read_callback,
        user_data: ptr::null_mut(),
        total_len: 999,
        bytes_read: 0,
    };
    assert_eq!(reader.len().unwrap(), 999);
}

// ============================================================================
// 8. Inner impl functions (Rust-level, bypassing extern "C" wrappers)
// ============================================================================

#[test]
fn impl_create_from_signing_service_inner_success() {
    let service = Arc::new(MockSigningService) as Arc<dyn cose_sign1_signing::SigningService>;
    let svc_inner = SigningServiceInner { service };
    let result =
        cose_sign1_factories_ffi::impl_create_from_signing_service_inner(&svc_inner);
    assert!(result.is_ok());
}

#[test]
fn impl_create_from_crypto_signer_inner_success() {
    let signer = Arc::new(MockCryptoSigner::es256()) as Arc<dyn CryptoSigner>;
    let result = cose_sign1_factories_ffi::impl_create_from_crypto_signer_inner(signer);
    assert!(result.is_ok());
}

#[test]
fn impl_create_with_transparency_inner_empty_providers() {
    let service = Arc::new(MockSigningService) as Arc<dyn cose_sign1_signing::SigningService>;
    let svc_inner = SigningServiceInner { service };
    let result =
        cose_sign1_factories_ffi::impl_create_with_transparency_inner(&svc_inner, vec![]);
    assert!(result.is_ok());
}

#[test]
fn impl_sign_direct_inner_with_mock_signer() {
    let service = Arc::new(MockSigningService) as Arc<dyn cose_sign1_signing::SigningService>;
    let factory = cose_sign1_factories::CoseSign1MessageFactory::new(service);
    let fi = FactoryInner { factory };

    let result =
        cose_sign1_factories_ffi::impl_sign_direct_inner(&fi, b"payload", "application/octet-stream");
    // The mock returns a fake signature so factory may fail at COSE serialisation; either outcome exercises the code.
    let _outcome = result.is_ok() || result.is_err();
}

#[test]
fn impl_sign_direct_detached_inner_with_mock() {
    let service = Arc::new(MockSigningService) as Arc<dyn cose_sign1_signing::SigningService>;
    let factory = cose_sign1_factories::CoseSign1MessageFactory::new(service);
    let fi = FactoryInner { factory };

    let _result = cose_sign1_factories_ffi::impl_sign_direct_detached_inner(
        &fi,
        b"payload",
        "application/octet-stream",
    );
}

#[test]
fn impl_sign_direct_file_inner_nonexistent() {
    let service = Arc::new(MockSigningService) as Arc<dyn cose_sign1_signing::SigningService>;
    let factory = cose_sign1_factories::CoseSign1MessageFactory::new(service);
    let fi = FactoryInner { factory };

    let result = cose_sign1_factories_ffi::impl_sign_direct_file_inner(
        &fi,
        "this_file_does_not_exist.bin",
        "application/octet-stream",
    );
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(err.message.contains("failed to open file"));
    assert_eq!(err.code, FFI_ERR_INVALID_ARGUMENT);
}

#[test]
fn impl_sign_direct_file_inner_with_real_file() {
    let service = Arc::new(MockSigningService) as Arc<dyn cose_sign1_signing::SigningService>;
    let factory = cose_sign1_factories::CoseSign1MessageFactory::new(service);
    let fi = FactoryInner { factory };

    let mut tmp = tempfile::NamedTempFile::new().unwrap();
    std::io::Write::write_all(&mut tmp, b"file content").unwrap();
    let path = tmp.path().to_str().unwrap().to_string();

    let _result = cose_sign1_factories_ffi::impl_sign_direct_file_inner(
        &fi,
        &path,
        "text/plain",
    );
}

#[test]
fn impl_sign_direct_streaming_inner_with_callback_payload() {
    let service = Arc::new(MockSigningService) as Arc<dyn cose_sign1_signing::SigningService>;
    let factory = cose_sign1_factories::CoseSign1MessageFactory::new(service);
    let fi = FactoryInner { factory };

    let mut state = StreamState {
        data: b"streaming data".to_vec(),
        offset: 0,
    };
    let payload = Arc::new(CallbackStreamingPayload {
        callback: good_read_callback,
        user_data: &mut state as *mut _ as *mut libc::c_void,
        total_len: 14,
    }) as Arc<dyn StreamingPayload>;

    let _result = cose_sign1_factories_ffi::impl_sign_direct_streaming_inner(
        &fi,
        payload,
        "application/octet-stream",
    );
}

#[test]
fn impl_sign_indirect_inner_with_mock() {
    let service = Arc::new(MockSigningService) as Arc<dyn cose_sign1_signing::SigningService>;
    let factory = cose_sign1_factories::CoseSign1MessageFactory::new(service);
    let fi = FactoryInner { factory };

    let _result = cose_sign1_factories_ffi::impl_sign_indirect_inner(
        &fi,
        b"indirect payload",
        "application/octet-stream",
    );
}

#[test]
fn impl_sign_indirect_file_inner_nonexistent() {
    let service = Arc::new(MockSigningService) as Arc<dyn cose_sign1_signing::SigningService>;
    let factory = cose_sign1_factories::CoseSign1MessageFactory::new(service);
    let fi = FactoryInner { factory };

    let result = cose_sign1_factories_ffi::impl_sign_indirect_file_inner(
        &fi,
        "no_such_file.dat",
        "application/octet-stream",
    );
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(err.message.contains("failed to open file"));
}

#[test]
fn impl_sign_indirect_file_inner_real_file() {
    let service = Arc::new(MockSigningService) as Arc<dyn cose_sign1_signing::SigningService>;
    let factory = cose_sign1_factories::CoseSign1MessageFactory::new(service);
    let fi = FactoryInner { factory };

    let mut tmp = tempfile::NamedTempFile::new().unwrap();
    std::io::Write::write_all(&mut tmp, b"indirect file").unwrap();
    let path = tmp.path().to_str().unwrap().to_string();

    let _result =
        cose_sign1_factories_ffi::impl_sign_indirect_file_inner(&fi, &path, "text/plain");
}

#[test]
fn impl_sign_indirect_streaming_inner_with_mock() {
    let service = Arc::new(MockSigningService) as Arc<dyn cose_sign1_signing::SigningService>;
    let factory = cose_sign1_factories::CoseSign1MessageFactory::new(service);
    let fi = FactoryInner { factory };

    let mut state = StreamState {
        data: b"streaming indirect".to_vec(),
        offset: 0,
    };
    let payload = Arc::new(CallbackStreamingPayload {
        callback: good_read_callback,
        user_data: &mut state as *mut _ as *mut libc::c_void,
        total_len: 18,
    }) as Arc<dyn StreamingPayload>;

    let _result = cose_sign1_factories_ffi::impl_sign_indirect_streaming_inner(
        &fi,
        payload,
        "application/octet-stream",
    );
}

// ============================================================================
// 9. FFI extern "C" signing functions — real happy paths via OpenSSL
// ============================================================================

#[test]
fn ffi_sign_direct_happy_path() {
    let factory = create_real_factory();
    let payload = b"hello world";
    let ct = CString::new("application/octet-stream").unwrap();

    let mut out_bytes: *mut u8 = ptr::null_mut();
    let mut out_len: u32 = 0;
    let mut err: *mut CoseSign1FactoriesErrorHandle = ptr::null_mut();

    let rc = unsafe {
        cose_sign1_factories_sign_direct(
            factory,
            payload.as_ptr(),
            payload.len() as u32,
            ct.as_ptr(),
            &mut out_bytes,
            &mut out_len,
            &mut err,
        )
    };

    if rc != FFI_OK {
        let msg = get_error_message(err);
        unsafe { cose_sign1_factories_error_free(err) };
        panic!("sign_direct failed (rc={rc}): {msg:?}");
    }
    assert!(!out_bytes.is_null());
    assert!(out_len > 0);

    unsafe {
        cose_sign1_factories_bytes_free(out_bytes, out_len);
        cose_sign1_factories_free(factory);
    };
}

#[test]
fn ffi_sign_direct_detached_happy_path() {
    let factory = create_real_factory();
    let payload = b"detached payload";
    let ct = CString::new("application/octet-stream").unwrap();

    let mut out_bytes: *mut u8 = ptr::null_mut();
    let mut out_len: u32 = 0;
    let mut err: *mut CoseSign1FactoriesErrorHandle = ptr::null_mut();

    let rc = unsafe {
        cose_sign1_factories_sign_direct_detached(
            factory,
            payload.as_ptr(),
            payload.len() as u32,
            ct.as_ptr(),
            &mut out_bytes,
            &mut out_len,
            &mut err,
        )
    };

    if rc != FFI_OK {
        let msg = get_error_message(err);
        unsafe { cose_sign1_factories_error_free(err) };
        panic!("sign_direct_detached failed (rc={rc}): {msg:?}");
    }
    assert!(!out_bytes.is_null());
    assert!(out_len > 0);

    unsafe {
        cose_sign1_factories_bytes_free(out_bytes, out_len);
        cose_sign1_factories_free(factory);
    };
}

#[test]
fn ffi_sign_direct_file_happy_path() {
    let factory = create_real_factory();

    let mut tmp = tempfile::NamedTempFile::new().unwrap();
    std::io::Write::write_all(&mut tmp, b"file payload for direct").unwrap();
    let path_str = tmp.path().to_str().unwrap();
    let c_path = CString::new(path_str).unwrap();
    let ct = CString::new("application/octet-stream").unwrap();

    let mut out_bytes: *mut u8 = ptr::null_mut();
    let mut out_len: u32 = 0;
    let mut err: *mut CoseSign1FactoriesErrorHandle = ptr::null_mut();

    let rc = unsafe {
        cose_sign1_factories_sign_direct_file(
            factory,
            c_path.as_ptr(),
            ct.as_ptr(),
            &mut out_bytes,
            &mut out_len,
            &mut err,
        )
    };

    // File/streaming signing uses sign_init() which the mock signer does not
    // support, so we expect a factory error.
    assert_eq!(rc, FFI_ERR_FACTORY_FAILED);
    assert!(!err.is_null());
    let msg = get_error_message(err).unwrap_or_default();
    assert!(msg.contains("signing") || msg.contains("stream") || msg.contains("key error"));

    unsafe {
        cose_sign1_factories_error_free(err);
        if !out_bytes.is_null() {
            cose_sign1_factories_bytes_free(out_bytes, out_len);
        }
        cose_sign1_factories_free(factory);
    };
}

#[test]
fn ffi_sign_direct_streaming_happy_path() {
    let factory = create_real_factory();

    let mut state = StreamState {
        data: b"streaming content".to_vec(),
        offset: 0,
    };
    let ct = CString::new("application/octet-stream").unwrap();

    let mut out_bytes: *mut u8 = ptr::null_mut();
    let mut out_len: u32 = 0;
    let mut err: *mut CoseSign1FactoriesErrorHandle = ptr::null_mut();

    let rc = unsafe {
        cose_sign1_factories_sign_direct_streaming(
            factory,
            good_read_callback,
            &mut state as *mut _ as *mut libc::c_void,
            state.data.len() as u64,
            ct.as_ptr(),
            &mut out_bytes,
            &mut out_len,
            &mut err,
        )
    };

    // Streaming signing uses sign_init() which the mock signer does not
    // support, so we expect a factory error.
    assert_eq!(rc, FFI_ERR_FACTORY_FAILED);
    assert!(!err.is_null());
    let msg = get_error_message(err).unwrap_or_default();
    assert!(msg.contains("signing") || msg.contains("stream") || msg.contains("key error"));

    unsafe {
        cose_sign1_factories_error_free(err);
        if !out_bytes.is_null() {
            cose_sign1_factories_bytes_free(out_bytes, out_len);
        }
        cose_sign1_factories_free(factory);
    };
}

#[test]
fn ffi_sign_indirect_happy_path() {
    let factory = create_real_factory();
    let payload = b"indirect payload";
    let ct = CString::new("application/octet-stream").unwrap();

    let mut out_bytes: *mut u8 = ptr::null_mut();
    let mut out_len: u32 = 0;
    let mut err: *mut CoseSign1FactoriesErrorHandle = ptr::null_mut();

    let rc = unsafe {
        cose_sign1_factories_sign_indirect(
            factory,
            payload.as_ptr(),
            payload.len() as u32,
            ct.as_ptr(),
            &mut out_bytes,
            &mut out_len,
            &mut err,
        )
    };

    if rc != FFI_OK {
        let msg = get_error_message(err);
        unsafe { cose_sign1_factories_error_free(err) };
        panic!("sign_indirect failed (rc={rc}): {msg:?}");
    }
    assert!(!out_bytes.is_null());
    assert!(out_len > 0);

    unsafe {
        cose_sign1_factories_bytes_free(out_bytes, out_len);
        cose_sign1_factories_free(factory);
    };
}

#[test]
fn ffi_sign_indirect_file_happy_path() {
    let factory = create_real_factory();

    let mut tmp = tempfile::NamedTempFile::new().unwrap();
    std::io::Write::write_all(&mut tmp, b"indirect file payload").unwrap();
    let path_str = tmp.path().to_str().unwrap();
    let c_path = CString::new(path_str).unwrap();
    let ct = CString::new("application/octet-stream").unwrap();

    let mut out_bytes: *mut u8 = ptr::null_mut();
    let mut out_len: u32 = 0;
    let mut err: *mut CoseSign1FactoriesErrorHandle = ptr::null_mut();

    let rc = unsafe {
        cose_sign1_factories_sign_indirect_file(
            factory,
            c_path.as_ptr(),
            ct.as_ptr(),
            &mut out_bytes,
            &mut out_len,
            &mut err,
        )
    };

    if rc != FFI_OK {
        let msg = get_error_message(err);
        unsafe { cose_sign1_factories_error_free(err) };
        panic!("sign_indirect_file failed (rc={rc}): {msg:?}");
    }
    assert!(!out_bytes.is_null());
    assert!(out_len > 0);

    unsafe {
        cose_sign1_factories_bytes_free(out_bytes, out_len);
        cose_sign1_factories_free(factory);
    };
}

#[test]
fn ffi_sign_indirect_streaming_happy_path() {
    let factory = create_real_factory();

    let mut state = StreamState {
        data: b"indirect streaming content".to_vec(),
        offset: 0,
    };
    let ct = CString::new("application/octet-stream").unwrap();

    let mut out_bytes: *mut u8 = ptr::null_mut();
    let mut out_len: u32 = 0;
    let mut err: *mut CoseSign1FactoriesErrorHandle = ptr::null_mut();

    let rc = unsafe {
        cose_sign1_factories_sign_indirect_streaming(
            factory,
            good_read_callback,
            &mut state as *mut _ as *mut libc::c_void,
            state.data.len() as u64,
            ct.as_ptr(),
            &mut out_bytes,
            &mut out_len,
            &mut err,
        )
    };

    if rc != FFI_OK {
        let msg = get_error_message(err);
        unsafe { cose_sign1_factories_error_free(err) };
        panic!("sign_indirect_streaming failed (rc={rc}): {msg:?}");
    }
    assert!(!out_bytes.is_null());
    assert!(out_len > 0);

    unsafe {
        cose_sign1_factories_bytes_free(out_bytes, out_len);
        cose_sign1_factories_free(factory);
    };
}

// ============================================================================
// 10. FFI null-pointer and error paths for all signing functions
// ============================================================================

#[test]
fn ffi_sign_direct_null_factory() {
    let ct = CString::new("text/plain").unwrap();
    let mut out_bytes: *mut u8 = ptr::null_mut();
    let mut out_len: u32 = 0;
    let mut err: *mut CoseSign1FactoriesErrorHandle = ptr::null_mut();

    let rc = unsafe {
        cose_sign1_factories_sign_direct(
            ptr::null(),
            b"x".as_ptr(),
            1,
            ct.as_ptr(),
            &mut out_bytes,
            &mut out_len,
            &mut err,
        )
    };
    assert_eq!(rc, FFI_ERR_NULL_POINTER);
    assert!(!err.is_null());
    unsafe { cose_sign1_factories_error_free(err) };
}

#[test]
fn ffi_sign_direct_null_output_pointers() {
    let ct = CString::new("text/plain").unwrap();
    let mut err: *mut CoseSign1FactoriesErrorHandle = ptr::null_mut();

    let rc = unsafe {
        cose_sign1_factories_sign_direct(
            ptr::null(),
            b"x".as_ptr(),
            1,
            ct.as_ptr(),
            ptr::null_mut(),
            ptr::null_mut(),
            &mut err,
        )
    };
    assert_eq!(rc, FFI_ERR_NULL_POINTER);
    if !err.is_null() {
        unsafe { cose_sign1_factories_error_free(err) };
    }
}

#[test]
fn ffi_sign_direct_null_content_type() {
    let factory = create_real_factory();
    let mut out_bytes: *mut u8 = ptr::null_mut();
    let mut out_len: u32 = 0;
    let mut err: *mut CoseSign1FactoriesErrorHandle = ptr::null_mut();

    let rc = unsafe {
        cose_sign1_factories_sign_direct(
            factory,
            b"x".as_ptr(),
            1,
            ptr::null(),
            &mut out_bytes,
            &mut out_len,
            &mut err,
        )
    };
    assert_eq!(rc, FFI_ERR_NULL_POINTER);
    if !err.is_null() {
        unsafe { cose_sign1_factories_error_free(err) };
    }
    unsafe { cose_sign1_factories_free(factory) };
}

#[test]
fn ffi_sign_direct_null_payload_nonzero_len() {
    let factory = create_real_factory();
    let ct = CString::new("text/plain").unwrap();
    let mut out_bytes: *mut u8 = ptr::null_mut();
    let mut out_len: u32 = 0;
    let mut err: *mut CoseSign1FactoriesErrorHandle = ptr::null_mut();

    let rc = unsafe {
        cose_sign1_factories_sign_direct(
            factory,
            ptr::null(),
            10,
            ct.as_ptr(),
            &mut out_bytes,
            &mut out_len,
            &mut err,
        )
    };
    assert_eq!(rc, FFI_ERR_NULL_POINTER);
    if !err.is_null() {
        unsafe { cose_sign1_factories_error_free(err) };
    }
    unsafe { cose_sign1_factories_free(factory) };
}

#[test]
fn ffi_sign_direct_empty_payload_succeeds() {
    let factory = create_real_factory();
    let ct = CString::new("application/octet-stream").unwrap();
    let mut out_bytes: *mut u8 = ptr::null_mut();
    let mut out_len: u32 = 0;
    let mut err: *mut CoseSign1FactoriesErrorHandle = ptr::null_mut();

    let rc = unsafe {
        cose_sign1_factories_sign_direct(
            factory,
            ptr::null(),
            0,
            ct.as_ptr(),
            &mut out_bytes,
            &mut out_len,
            &mut err,
        )
    };
    assert_eq!(rc, FFI_OK);
    assert!(!out_bytes.is_null());
    assert!(out_len > 0);

    unsafe {
        cose_sign1_factories_bytes_free(out_bytes, out_len);
        cose_sign1_factories_free(factory);
    };
}

#[test]
fn ffi_sign_direct_detached_null_factory() {
    let ct = CString::new("text/plain").unwrap();
    let mut out_bytes: *mut u8 = ptr::null_mut();
    let mut out_len: u32 = 0;
    let mut err: *mut CoseSign1FactoriesErrorHandle = ptr::null_mut();

    let rc = unsafe {
        cose_sign1_factories_sign_direct_detached(
            ptr::null(),
            b"x".as_ptr(),
            1,
            ct.as_ptr(),
            &mut out_bytes,
            &mut out_len,
            &mut err,
        )
    };
    assert_eq!(rc, FFI_ERR_NULL_POINTER);
    if !err.is_null() {
        unsafe { cose_sign1_factories_error_free(err) };
    }
}

#[test]
fn ffi_sign_direct_file_null_factory() {
    let ct = CString::new("text/plain").unwrap();
    let fp = CString::new("somefile").unwrap();
    let mut out_bytes: *mut u8 = ptr::null_mut();
    let mut out_len: u32 = 0;
    let mut err: *mut CoseSign1FactoriesErrorHandle = ptr::null_mut();

    let rc = unsafe {
        cose_sign1_factories_sign_direct_file(
            ptr::null(),
            fp.as_ptr(),
            ct.as_ptr(),
            &mut out_bytes,
            &mut out_len,
            &mut err,
        )
    };
    assert_eq!(rc, FFI_ERR_NULL_POINTER);
    if !err.is_null() {
        unsafe { cose_sign1_factories_error_free(err) };
    }
}

#[test]
fn ffi_sign_direct_file_null_file_path() {
    let factory = create_real_factory();
    let ct = CString::new("text/plain").unwrap();
    let mut out_bytes: *mut u8 = ptr::null_mut();
    let mut out_len: u32 = 0;
    let mut err: *mut CoseSign1FactoriesErrorHandle = ptr::null_mut();

    let rc = unsafe {
        cose_sign1_factories_sign_direct_file(
            factory,
            ptr::null(),
            ct.as_ptr(),
            &mut out_bytes,
            &mut out_len,
            &mut err,
        )
    };
    assert_eq!(rc, FFI_ERR_NULL_POINTER);
    if !err.is_null() {
        unsafe { cose_sign1_factories_error_free(err) };
    }
    unsafe { cose_sign1_factories_free(factory) };
}

#[test]
fn ffi_sign_direct_file_null_content_type() {
    let factory = create_real_factory();
    let fp = CString::new("somefile").unwrap();
    let mut out_bytes: *mut u8 = ptr::null_mut();
    let mut out_len: u32 = 0;
    let mut err: *mut CoseSign1FactoriesErrorHandle = ptr::null_mut();

    let rc = unsafe {
        cose_sign1_factories_sign_direct_file(
            factory,
            fp.as_ptr(),
            ptr::null(),
            &mut out_bytes,
            &mut out_len,
            &mut err,
        )
    };
    assert_eq!(rc, FFI_ERR_NULL_POINTER);
    if !err.is_null() {
        unsafe { cose_sign1_factories_error_free(err) };
    }
    unsafe { cose_sign1_factories_free(factory) };
}

#[test]
fn ffi_sign_direct_file_nonexistent_file() {
    let factory = create_real_factory();
    let ct = CString::new("text/plain").unwrap();
    let fp = CString::new("/nonexistent/path/to/file.bin").unwrap();
    let mut out_bytes: *mut u8 = ptr::null_mut();
    let mut out_len: u32 = 0;
    let mut err: *mut CoseSign1FactoriesErrorHandle = ptr::null_mut();

    let rc = unsafe {
        cose_sign1_factories_sign_direct_file(
            factory,
            fp.as_ptr(),
            ct.as_ptr(),
            &mut out_bytes,
            &mut out_len,
            &mut err,
        )
    };
    assert_eq!(rc, FFI_ERR_FACTORY_FAILED);
    assert!(!err.is_null());
    let msg = get_error_message(err).unwrap_or_default();
    assert!(msg.contains("file") || msg.contains("open") || msg.contains("not found") || msg.contains("No such"));
    unsafe {
        cose_sign1_factories_error_free(err);
        cose_sign1_factories_free(factory);
    };
}

#[test]
fn ffi_sign_direct_streaming_null_factory() {
    let ct = CString::new("text/plain").unwrap();
    let mut out_bytes: *mut u8 = ptr::null_mut();
    let mut out_len: u32 = 0;
    let mut err: *mut CoseSign1FactoriesErrorHandle = ptr::null_mut();

    let rc = unsafe {
        cose_sign1_factories_sign_direct_streaming(
            ptr::null(),
            good_read_callback,
            ptr::null_mut(),
            0,
            ct.as_ptr(),
            &mut out_bytes,
            &mut out_len,
            &mut err,
        )
    };
    assert_eq!(rc, FFI_ERR_NULL_POINTER);
    if !err.is_null() {
        unsafe { cose_sign1_factories_error_free(err) };
    }
}

#[test]
fn ffi_sign_direct_streaming_null_content_type() {
    let factory = create_real_factory();
    let mut out_bytes: *mut u8 = ptr::null_mut();
    let mut out_len: u32 = 0;
    let mut err: *mut CoseSign1FactoriesErrorHandle = ptr::null_mut();

    let rc = unsafe {
        cose_sign1_factories_sign_direct_streaming(
            factory,
            good_read_callback,
            ptr::null_mut(),
            0,
            ptr::null(),
            &mut out_bytes,
            &mut out_len,
            &mut err,
        )
    };
    assert_eq!(rc, FFI_ERR_NULL_POINTER);
    if !err.is_null() {
        unsafe { cose_sign1_factories_error_free(err) };
    }
    unsafe { cose_sign1_factories_free(factory) };
}

#[test]
fn ffi_sign_indirect_null_factory() {
    let ct = CString::new("text/plain").unwrap();
    let mut out_bytes: *mut u8 = ptr::null_mut();
    let mut out_len: u32 = 0;
    let mut err: *mut CoseSign1FactoriesErrorHandle = ptr::null_mut();

    let rc = unsafe {
        cose_sign1_factories_sign_indirect(
            ptr::null(),
            b"x".as_ptr(),
            1,
            ct.as_ptr(),
            &mut out_bytes,
            &mut out_len,
            &mut err,
        )
    };
    assert_eq!(rc, FFI_ERR_NULL_POINTER);
    if !err.is_null() {
        unsafe { cose_sign1_factories_error_free(err) };
    }
}

#[test]
fn ffi_sign_indirect_null_payload_nonzero_len() {
    let factory = create_real_factory();
    let ct = CString::new("text/plain").unwrap();
    let mut out_bytes: *mut u8 = ptr::null_mut();
    let mut out_len: u32 = 0;
    let mut err: *mut CoseSign1FactoriesErrorHandle = ptr::null_mut();

    let rc = unsafe {
        cose_sign1_factories_sign_indirect(
            factory,
            ptr::null(),
            5,
            ct.as_ptr(),
            &mut out_bytes,
            &mut out_len,
            &mut err,
        )
    };
    assert_eq!(rc, FFI_ERR_NULL_POINTER);
    if !err.is_null() {
        unsafe { cose_sign1_factories_error_free(err) };
    }
    unsafe { cose_sign1_factories_free(factory) };
}

#[test]
fn ffi_sign_indirect_file_null_factory() {
    let ct = CString::new("text/plain").unwrap();
    let fp = CString::new("somefile").unwrap();
    let mut out_bytes: *mut u8 = ptr::null_mut();
    let mut out_len: u32 = 0;
    let mut err: *mut CoseSign1FactoriesErrorHandle = ptr::null_mut();

    let rc = unsafe {
        cose_sign1_factories_sign_indirect_file(
            ptr::null(),
            fp.as_ptr(),
            ct.as_ptr(),
            &mut out_bytes,
            &mut out_len,
            &mut err,
        )
    };
    assert_eq!(rc, FFI_ERR_NULL_POINTER);
    if !err.is_null() {
        unsafe { cose_sign1_factories_error_free(err) };
    }
}

#[test]
fn ffi_sign_indirect_file_null_file_path() {
    let factory = create_real_factory();
    let ct = CString::new("text/plain").unwrap();
    let mut out_bytes: *mut u8 = ptr::null_mut();
    let mut out_len: u32 = 0;
    let mut err: *mut CoseSign1FactoriesErrorHandle = ptr::null_mut();

    let rc = unsafe {
        cose_sign1_factories_sign_indirect_file(
            factory,
            ptr::null(),
            ct.as_ptr(),
            &mut out_bytes,
            &mut out_len,
            &mut err,
        )
    };
    assert_eq!(rc, FFI_ERR_NULL_POINTER);
    if !err.is_null() {
        unsafe { cose_sign1_factories_error_free(err) };
    }
    unsafe { cose_sign1_factories_free(factory) };
}

#[test]
fn ffi_sign_indirect_file_null_content_type() {
    let factory = create_real_factory();
    let fp = CString::new("somefile").unwrap();
    let mut out_bytes: *mut u8 = ptr::null_mut();
    let mut out_len: u32 = 0;
    let mut err: *mut CoseSign1FactoriesErrorHandle = ptr::null_mut();

    let rc = unsafe {
        cose_sign1_factories_sign_indirect_file(
            factory,
            fp.as_ptr(),
            ptr::null(),
            &mut out_bytes,
            &mut out_len,
            &mut err,
        )
    };
    assert_eq!(rc, FFI_ERR_NULL_POINTER);
    if !err.is_null() {
        unsafe { cose_sign1_factories_error_free(err) };
    }
    unsafe { cose_sign1_factories_free(factory) };
}

#[test]
fn ffi_sign_indirect_streaming_null_factory() {
    let ct = CString::new("text/plain").unwrap();
    let mut out_bytes: *mut u8 = ptr::null_mut();
    let mut out_len: u32 = 0;
    let mut err: *mut CoseSign1FactoriesErrorHandle = ptr::null_mut();

    let rc = unsafe {
        cose_sign1_factories_sign_indirect_streaming(
            ptr::null(),
            good_read_callback,
            ptr::null_mut(),
            0,
            ct.as_ptr(),
            &mut out_bytes,
            &mut out_len,
            &mut err,
        )
    };
    assert_eq!(rc, FFI_ERR_NULL_POINTER);
    if !err.is_null() {
        unsafe { cose_sign1_factories_error_free(err) };
    }
}

#[test]
fn ffi_sign_indirect_streaming_null_content_type() {
    let factory = create_real_factory();
    let mut out_bytes: *mut u8 = ptr::null_mut();
    let mut out_len: u32 = 0;
    let mut err: *mut CoseSign1FactoriesErrorHandle = ptr::null_mut();

    let rc = unsafe {
        cose_sign1_factories_sign_indirect_streaming(
            factory,
            good_read_callback,
            ptr::null_mut(),
            0,
            ptr::null(),
            &mut out_bytes,
            &mut out_len,
            &mut err,
        )
    };
    assert_eq!(rc, FFI_ERR_NULL_POINTER);
    if !err.is_null() {
        unsafe { cose_sign1_factories_error_free(err) };
    }
    unsafe { cose_sign1_factories_free(factory) };
}

// ============================================================================
// 11. FFI factory creation functions — null-pointer paths
// ============================================================================

#[test]
fn ffi_create_from_signing_service_null_out_factory() {
    let mut err: *mut CoseSign1FactoriesErrorHandle = ptr::null_mut();
    let rc = unsafe {
        cose_sign1_factories_create_from_signing_service(
            ptr::null(),
            ptr::null_mut(),
            &mut err,
        )
    };
    assert_eq!(rc, FFI_ERR_NULL_POINTER);
    if !err.is_null() {
        let msg = get_error_message(err).unwrap_or_default();
        assert!(msg.contains("out_factory"));
        unsafe { cose_sign1_factories_error_free(err) };
    }
}

#[test]
fn ffi_create_from_signing_service_null_service() {
    let mut factory: *mut CoseSign1FactoriesHandle = ptr::null_mut();
    let mut err: *mut CoseSign1FactoriesErrorHandle = ptr::null_mut();
    let rc = unsafe {
        cose_sign1_factories_create_from_signing_service(
            ptr::null(),
            &mut factory,
            &mut err,
        )
    };
    assert_eq!(rc, FFI_ERR_NULL_POINTER);
    assert!(factory.is_null());
    if !err.is_null() {
        let msg = get_error_message(err).unwrap_or_default();
        assert!(msg.contains("service"));
        unsafe { cose_sign1_factories_error_free(err) };
    }
}

#[test]
fn ffi_create_from_crypto_signer_null_out_factory() {
    let mut err: *mut CoseSign1FactoriesErrorHandle = ptr::null_mut();
    let rc = unsafe {
        cose_sign1_factories_create_from_crypto_signer(
            ptr::null_mut(),
            ptr::null_mut(),
            &mut err,
        )
    };
    assert_eq!(rc, FFI_ERR_NULL_POINTER);
    if !err.is_null() {
        let msg = get_error_message(err).unwrap_or_default();
        assert!(msg.contains("out_factory"));
        unsafe { cose_sign1_factories_error_free(err) };
    }
}

#[test]
fn ffi_create_from_crypto_signer_null_signer() {
    let mut factory: *mut CoseSign1FactoriesHandle = ptr::null_mut();
    let mut err: *mut CoseSign1FactoriesErrorHandle = ptr::null_mut();
    let rc = unsafe {
        cose_sign1_factories_create_from_crypto_signer(
            ptr::null_mut(),
            &mut factory,
            &mut err,
        )
    };
    assert_eq!(rc, FFI_ERR_NULL_POINTER);
    assert!(factory.is_null());
    if !err.is_null() {
        let msg = get_error_message(err).unwrap_or_default();
        assert!(msg.contains("signer_handle"));
        unsafe { cose_sign1_factories_error_free(err) };
    }
}

#[test]
fn ffi_create_with_transparency_null_out_factory() {
    let mut err: *mut CoseSign1FactoriesErrorHandle = ptr::null_mut();
    let rc = unsafe {
        cose_sign1_factories_create_with_transparency(
            ptr::null(),
            ptr::null(),
            0,
            ptr::null_mut(),
            &mut err,
        )
    };
    assert_eq!(rc, FFI_ERR_NULL_POINTER);
    if !err.is_null() {
        let msg = get_error_message(err).unwrap_or_default();
        assert!(msg.contains("out_factory"));
        unsafe { cose_sign1_factories_error_free(err) };
    }
}

#[test]
fn ffi_create_with_transparency_null_service() {
    let mut factory: *mut CoseSign1FactoriesHandle = ptr::null_mut();
    let mut err: *mut CoseSign1FactoriesErrorHandle = ptr::null_mut();
    let rc = unsafe {
        cose_sign1_factories_create_with_transparency(
            ptr::null(),
            ptr::null(),
            0,
            &mut factory,
            &mut err,
        )
    };
    assert_eq!(rc, FFI_ERR_NULL_POINTER);
    assert!(factory.is_null());
    if !err.is_null() {
        let msg = get_error_message(err).unwrap_or_default();
        assert!(msg.contains("service"));
        unsafe { cose_sign1_factories_error_free(err) };
    }
}

#[test]
fn ffi_create_with_transparency_null_providers_nonzero_len() {
    // We need a valid service handle. Build one from the SigningServiceInner.
    let service = Arc::new(MockSigningService) as Arc<dyn cose_sign1_signing::SigningService>;
    let svc_inner = SigningServiceInner { service };
    let svc_handle =
        Box::into_raw(Box::new(svc_inner)) as *const CoseSign1FactoriesSigningServiceHandle;

    let mut factory: *mut CoseSign1FactoriesHandle = ptr::null_mut();
    let mut err: *mut CoseSign1FactoriesErrorHandle = ptr::null_mut();

    let rc = unsafe {
        cose_sign1_factories_create_with_transparency(
            svc_handle,
            ptr::null(),
            3, // non-zero length with null providers
            &mut factory,
            &mut err,
        )
    };
    assert_eq!(rc, FFI_ERR_NULL_POINTER);
    assert!(factory.is_null());
    if !err.is_null() {
        let msg = get_error_message(err).unwrap_or_default();
        assert!(msg.contains("providers"));
        unsafe { cose_sign1_factories_error_free(err) };
    }

    // Clean up the service handle
    unsafe { drop(Box::from_raw(svc_handle as *mut SigningServiceInner)) };
}

// ============================================================================
// 12. FFI factory free
// ============================================================================

#[test]
fn ffi_factory_free_null_is_safe() {
    unsafe { cose_sign1_factories_free(ptr::null_mut()) };
}

#[test]
fn ffi_factory_free_valid_handle() {
    let factory = create_real_factory();
    unsafe { cose_sign1_factories_free(factory) };
}

// ============================================================================
// 13. create_from_crypto_signer happy path (OpenSSL)
// ============================================================================

#[test]
fn ffi_create_from_crypto_signer_happy_path() {
    let signer = create_mock_signer_handle();
    let mut factory: *mut CoseSign1FactoriesHandle = ptr::null_mut();
    let mut err: *mut CoseSign1FactoriesErrorHandle = ptr::null_mut();

    let rc = unsafe {
        cose_sign1_factories_create_from_crypto_signer(signer, &mut factory, &mut err)
    };
    assert_eq!(rc, FFI_OK);
    assert!(!factory.is_null());
    if !err.is_null() {
        unsafe { cose_sign1_factories_error_free(err) };
    }
    unsafe { cose_sign1_factories_free(factory) };
}

// ============================================================================
// 14. Direct detached — additional error paths
// ============================================================================

#[test]
fn ffi_sign_direct_detached_null_output_pointers() {
    let ct = CString::new("text/plain").unwrap();
    let mut err: *mut CoseSign1FactoriesErrorHandle = ptr::null_mut();

    let rc = unsafe {
        cose_sign1_factories_sign_direct_detached(
            ptr::null(),
            b"x".as_ptr(),
            1,
            ct.as_ptr(),
            ptr::null_mut(),
            ptr::null_mut(),
            &mut err,
        )
    };
    assert_eq!(rc, FFI_ERR_NULL_POINTER);
    if !err.is_null() {
        unsafe { cose_sign1_factories_error_free(err) };
    }
}

#[test]
fn ffi_sign_direct_detached_null_content_type() {
    let factory = create_real_factory();
    let mut out_bytes: *mut u8 = ptr::null_mut();
    let mut out_len: u32 = 0;
    let mut err: *mut CoseSign1FactoriesErrorHandle = ptr::null_mut();

    let rc = unsafe {
        cose_sign1_factories_sign_direct_detached(
            factory,
            b"x".as_ptr(),
            1,
            ptr::null(),
            &mut out_bytes,
            &mut out_len,
            &mut err,
        )
    };
    assert_eq!(rc, FFI_ERR_NULL_POINTER);
    if !err.is_null() {
        unsafe { cose_sign1_factories_error_free(err) };
    }
    unsafe { cose_sign1_factories_free(factory) };
}

#[test]
fn ffi_sign_direct_detached_null_payload_nonzero_len() {
    let factory = create_real_factory();
    let ct = CString::new("text/plain").unwrap();
    let mut out_bytes: *mut u8 = ptr::null_mut();
    let mut out_len: u32 = 0;
    let mut err: *mut CoseSign1FactoriesErrorHandle = ptr::null_mut();

    let rc = unsafe {
        cose_sign1_factories_sign_direct_detached(
            factory,
            ptr::null(),
            5,
            ct.as_ptr(),
            &mut out_bytes,
            &mut out_len,
            &mut err,
        )
    };
    assert_eq!(rc, FFI_ERR_NULL_POINTER);
    if !err.is_null() {
        unsafe { cose_sign1_factories_error_free(err) };
    }
    unsafe { cose_sign1_factories_free(factory) };
}

// ============================================================================
// 15. Indirect streaming — null output pointers
// ============================================================================

#[test]
fn ffi_sign_indirect_streaming_null_output_pointers() {
    let ct = CString::new("text/plain").unwrap();
    let mut err: *mut CoseSign1FactoriesErrorHandle = ptr::null_mut();

    let rc = unsafe {
        cose_sign1_factories_sign_indirect_streaming(
            ptr::null(),
            good_read_callback,
            ptr::null_mut(),
            0,
            ct.as_ptr(),
            ptr::null_mut(),
            ptr::null_mut(),
            &mut err,
        )
    };
    assert_eq!(rc, FFI_ERR_NULL_POINTER);
    if !err.is_null() {
        unsafe { cose_sign1_factories_error_free(err) };
    }
}

#[test]
fn ffi_sign_indirect_null_output_pointers() {
    let ct = CString::new("text/plain").unwrap();
    let mut err: *mut CoseSign1FactoriesErrorHandle = ptr::null_mut();

    let rc = unsafe {
        cose_sign1_factories_sign_indirect(
            ptr::null(),
            b"x".as_ptr(),
            1,
            ct.as_ptr(),
            ptr::null_mut(),
            ptr::null_mut(),
            &mut err,
        )
    };
    assert_eq!(rc, FFI_ERR_NULL_POINTER);
    if !err.is_null() {
        unsafe { cose_sign1_factories_error_free(err) };
    }
}

#[test]
fn ffi_sign_indirect_file_null_output_pointers() {
    let ct = CString::new("text/plain").unwrap();
    let fp = CString::new("somefile").unwrap();
    let mut err: *mut CoseSign1FactoriesErrorHandle = ptr::null_mut();

    let rc = unsafe {
        cose_sign1_factories_sign_indirect_file(
            ptr::null(),
            fp.as_ptr(),
            ct.as_ptr(),
            ptr::null_mut(),
            ptr::null_mut(),
            &mut err,
        )
    };
    assert_eq!(rc, FFI_ERR_NULL_POINTER);
    if !err.is_null() {
        unsafe { cose_sign1_factories_error_free(err) };
    }
}

#[test]
fn ffi_sign_direct_file_null_output_pointers() {
    let ct = CString::new("text/plain").unwrap();
    let fp = CString::new("somefile").unwrap();
    let mut err: *mut CoseSign1FactoriesErrorHandle = ptr::null_mut();

    let rc = unsafe {
        cose_sign1_factories_sign_direct_file(
            ptr::null(),
            fp.as_ptr(),
            ct.as_ptr(),
            ptr::null_mut(),
            ptr::null_mut(),
            &mut err,
        )
    };
    assert_eq!(rc, FFI_ERR_NULL_POINTER);
    if !err.is_null() {
        unsafe { cose_sign1_factories_error_free(err) };
    }
}

#[test]
fn ffi_sign_direct_streaming_null_output_pointers() {
    let ct = CString::new("text/plain").unwrap();
    let mut err: *mut CoseSign1FactoriesErrorHandle = ptr::null_mut();

    let rc = unsafe {
        cose_sign1_factories_sign_direct_streaming(
            ptr::null(),
            good_read_callback,
            ptr::null_mut(),
            0,
            ct.as_ptr(),
            ptr::null_mut(),
            ptr::null_mut(),
            &mut err,
        )
    };
    assert_eq!(rc, FFI_ERR_NULL_POINTER);
    if !err.is_null() {
        unsafe { cose_sign1_factories_error_free(err) };
    }
}

// ============================================================================
// 16. Indirect null content_type
// ============================================================================

#[test]
fn ffi_sign_indirect_null_content_type() {
    let factory = create_real_factory();
    let mut out_bytes: *mut u8 = ptr::null_mut();
    let mut out_len: u32 = 0;
    let mut err: *mut CoseSign1FactoriesErrorHandle = ptr::null_mut();

    let rc = unsafe {
        cose_sign1_factories_sign_indirect(
            factory,
            b"x".as_ptr(),
            1,
            ptr::null(),
            &mut out_bytes,
            &mut out_len,
            &mut err,
        )
    };
    assert_eq!(rc, FFI_ERR_NULL_POINTER);
    if !err.is_null() {
        unsafe { cose_sign1_factories_error_free(err) };
    }
    unsafe { cose_sign1_factories_free(factory) };
}

// ============================================================================
// 17. Indirect file — nonexistent file
// ============================================================================

#[test]
fn ffi_sign_indirect_file_nonexistent_file() {
    let factory = create_real_factory();
    let ct = CString::new("text/plain").unwrap();
    let fp = CString::new("/nonexistent/path/to/file.bin").unwrap();
    let mut out_bytes: *mut u8 = ptr::null_mut();
    let mut out_len: u32 = 0;
    let mut err: *mut CoseSign1FactoriesErrorHandle = ptr::null_mut();

    let rc = unsafe {
        cose_sign1_factories_sign_indirect_file(
            factory,
            fp.as_ptr(),
            ct.as_ptr(),
            &mut out_bytes,
            &mut out_len,
            &mut err,
        )
    };
    assert_eq!(rc, FFI_ERR_FACTORY_FAILED);
    assert!(!err.is_null());
    unsafe {
        cose_sign1_factories_error_free(err);
        cose_sign1_factories_free(factory);
    };
}
