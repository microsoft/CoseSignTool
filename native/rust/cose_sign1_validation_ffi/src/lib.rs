#![deny(unsafe_op_in_unsafe_fn)]

//! Base FFI crate for COSE Sign1 validation.
//!
//! This crate provides the core validator types and error-handling infrastructure.
//! Pack-specific functionality (X.509, MST, AKV, trust policy) lives in separate FFI crates.

use anyhow::Context as _;
use cose_sign1_validation::fluent::{
    CoseSign1CompiledTrustPlan, CoseSign1TrustPack, CoseSign1Validator, DetachedPayload,
    TrustPlanBuilder,
};
use std::cell::RefCell;
use std::ffi::{c_char, CString};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::ptr;
use std::sync::Arc;

static ABI_VERSION: u32 = 1;

thread_local! {
    static LAST_ERROR: RefCell<Option<CString>> = const { RefCell::new(None) };
}

pub fn set_last_error(message: impl Into<String>) {
    let s = message.into();
    let c = CString::new(s).unwrap_or_else(|_| CString::new("error message contained NUL").unwrap());
    LAST_ERROR.with(|slot| {
        *slot.borrow_mut() = Some(c);
    });
}

pub fn clear_last_error() {
    LAST_ERROR.with(|slot| {
        *slot.borrow_mut() = None;
    });
}

fn take_last_error_ptr() -> *mut c_char {
    LAST_ERROR.with(|slot| {
        slot.borrow_mut()
            .take()
            .map(|c| c.into_raw())
            .unwrap_or(ptr::null_mut())
    })
}

#[repr(C)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
#[allow(non_camel_case_types)]
pub enum cose_status_t {
    COSE_OK = 0,
    COSE_ERR = 1,
    COSE_PANIC = 2,
    COSE_INVALID_ARG = 3,
}

#[repr(C)]
pub struct cose_validator_builder_t {
    pub packs: Vec<Arc<dyn CoseSign1TrustPack>>,
    pub compiled_plan: Option<CoseSign1CompiledTrustPlan>,
}

#[repr(C)]
pub struct cose_validator_t {
    pub packs: Vec<Arc<dyn CoseSign1TrustPack>>,
    pub compiled_plan: Option<CoseSign1CompiledTrustPlan>,
}

#[repr(C)]
pub struct cose_validation_result_t {
    pub ok: bool,
    pub failure_message: Option<String>,
}

/// Opaque handle for incrementally building a custom trust policy.
///
/// This lives in the base FFI crate so optional pack FFI crates (certificates/MST/AKV)
/// can add policy helper exports without depending on (and thereby statically duplicating)
/// the trust FFI library.
#[repr(C)]
pub struct cose_trust_policy_builder_t {
    pub builder: Option<TrustPlanBuilder>,
}

pub fn with_trust_policy_builder_mut(
    policy_builder: *mut cose_trust_policy_builder_t,
    f: impl FnOnce(TrustPlanBuilder) -> TrustPlanBuilder,
) -> Result<(), anyhow::Error> {
    let policy_builder = unsafe { policy_builder.as_mut() }
        .ok_or_else(|| anyhow::anyhow!("policy_builder must not be null"))?;
    let builder = policy_builder
        .builder
        .take()
        .ok_or_else(|| anyhow::anyhow!("policy_builder already compiled or invalid"))?;
    policy_builder.builder = Some(f(builder));
    Ok(())
}

pub fn with_catch_unwind<F: FnOnce() -> Result<cose_status_t, anyhow::Error>>(f: F) -> cose_status_t {
    clear_last_error();
    match catch_unwind(AssertUnwindSafe(|| f())) {
        Ok(Ok(status)) => status,
        Ok(Err(err)) => {
            set_last_error(format!("{:#}", err));
            cose_status_t::COSE_ERR
        }
        Err(_) => {
            set_last_error("panic across FFI boundary");
            cose_status_t::COSE_PANIC
        }
    }
}

/// Returns the ABI version for this library.
#[no_mangle]
pub extern "C" fn cose_ffi_abi_version() -> u32 {
    ABI_VERSION
}

/// Returns a newly-allocated UTF-8 string containing the last error message for the current thread.
///
/// Ownership: caller must free via `cose_string_free`.
#[no_mangle]
pub extern "C" fn cose_last_error_message_utf8() -> *mut c_char {
    take_last_error_ptr()
}

#[no_mangle]
pub extern "C" fn cose_last_error_clear() {
    clear_last_error();
}

/// Frees a string previously returned by this library.
#[no_mangle]
pub unsafe extern "C" fn cose_string_free(s: *mut c_char) {
    if s.is_null() {
        return;
    }
    unsafe {
        drop(CString::from_raw(s));
    }
}

#[no_mangle]
pub extern "C" fn cose_validator_builder_new(out: *mut *mut cose_validator_builder_t) -> cose_status_t {
    with_catch_unwind(|| {
        if out.is_null() {
            anyhow::bail!("out must not be null");
        }

        let builder = cose_validator_builder_t {
            packs: Vec::new(),
            compiled_plan: None,
        };
        let boxed = Box::new(builder);
        unsafe {
            *out = Box::into_raw(boxed);
        }
        Ok(cose_status_t::COSE_OK)
    })
}

#[no_mangle]
pub extern "C" fn cose_validator_builder_free(builder: *mut cose_validator_builder_t) {
    if builder.is_null() {
        return;
    }
    unsafe {
        drop(Box::from_raw(builder));
    }
}

// Pack-specific functions moved to separate FFI crates:
// - cose_sign1_validation_ffi_certificates
// - cose_sign1_validation_ffi_mst
// - cose_sign1_validation_ffi_akv
// - cose_sign1_validation_ffi_trust

#[no_mangle]
pub extern "C" fn cose_validator_builder_build(
    builder: *mut cose_validator_builder_t,
    out: *mut *mut cose_validator_t,
) -> cose_status_t {
    with_catch_unwind(|| {
        if out.is_null() {
            anyhow::bail!("out must not be null");
        }
        let builder = unsafe { builder.as_mut() }.context("builder must not be null")?;

        let boxed = Box::new(cose_validator_t {
            packs: builder.packs.clone(),
            compiled_plan: builder.compiled_plan.clone(),
        });
        unsafe {
            *out = Box::into_raw(boxed);
        }
        Ok(cose_status_t::COSE_OK)
    })
}

#[no_mangle]
pub extern "C" fn cose_validator_free(validator: *mut cose_validator_t) {
    if validator.is_null() {
        return;
    }
    unsafe {
        drop(Box::from_raw(validator));
    }
}

#[no_mangle]
pub extern "C" fn cose_validation_result_free(result: *mut cose_validation_result_t) {
    if result.is_null() {
        return;
    }
    unsafe {
        drop(Box::from_raw(result));
    }
}

#[no_mangle]
pub extern "C" fn cose_validation_result_is_success(
    result: *const cose_validation_result_t,
    out_ok: *mut bool,
) -> cose_status_t {
    with_catch_unwind(|| {
        if out_ok.is_null() {
            anyhow::bail!("out_ok must not be null");
        }
        let result = unsafe { result.as_ref() }.context("result must not be null")?;
        unsafe {
            *out_ok = result.ok;
        }
        Ok(cose_status_t::COSE_OK)
    })
}

/// Returns a newly-allocated UTF-8 string describing the failure, or null if success.
///
/// Ownership: caller must free via `cose_string_free`.
#[no_mangle]
pub extern "C" fn cose_validation_result_failure_message_utf8(
    result: *const cose_validation_result_t,
) -> *mut c_char {
    clear_last_error();
    let Some(result) = (unsafe { result.as_ref() }) else {
        set_last_error("result must not be null");
        return ptr::null_mut();
    };

    match &result.failure_message {
        Some(s) => CString::new(s.as_str())
            .unwrap_or_else(|_| CString::new("failure message contained NUL").unwrap())
            .into_raw(),
        None => ptr::null_mut(),
    }
}

#[no_mangle]
pub extern "C" fn cose_validator_validate_bytes(
    validator: *const cose_validator_t,
    cose_bytes: *const u8,
    cose_bytes_len: usize,
    detached_payload: *const u8,
    detached_payload_len: usize,
    out_result: *mut *mut cose_validation_result_t,
) -> cose_status_t {
    with_catch_unwind(|| {
        if out_result.is_null() {
            anyhow::bail!("out_result must not be null");
        }
        let validator = unsafe { validator.as_ref() }.context("validator must not be null")?;
        if cose_bytes.is_null() {
            return Ok(cose_status_t::COSE_INVALID_ARG);
        }

        let message = unsafe { std::slice::from_raw_parts(cose_bytes, cose_bytes_len) };

        let detached = if detached_payload.is_null() {
            None
        } else {
            Some(unsafe { std::slice::from_raw_parts(detached_payload, detached_payload_len) })
        };

        let mut v = match &validator.compiled_plan {
            Some(plan) => CoseSign1Validator::new(plan.clone()),
            None => CoseSign1Validator::new(validator.packs.clone()),
        };

        if let Some(bytes) = detached {
            let payload: Arc<[u8]> = bytes.to_vec().into();
            v = v.with_options(|o| {
                o.detached_payload = Some(DetachedPayload::bytes(payload));
            });
        }

        let bytes: Arc<[u8]> = message.to_vec().into();
        let r = v
            .validate_bytes(bytes)
            .map_err(|e| anyhow::anyhow!(e.to_string()))?;

        let (ok, failure_message) = match r.overall.kind {
            cose_sign1_validation::fluent::ValidationResultKind::Success => (true, None),
            cose_sign1_validation::fluent::ValidationResultKind::Failure
            | cose_sign1_validation::fluent::ValidationResultKind::NotApplicable => {
                let msg = r
                    .overall
                    .failures
                    .first()
                    .map(|f| f.message.clone())
                    .unwrap_or_else(|| "Validation failed".to_string());
                (false, Some(msg))
            }
        };

        let boxed = Box::new(cose_validation_result_t { ok, failure_message });
        unsafe {
            *out_result = Box::into_raw(boxed);
        }

        Ok(cose_status_t::COSE_OK)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ffi_smoke_builder() {
        let mut builder: *mut cose_validator_builder_t = ptr::null_mut();
        assert_eq!(cose_validator_builder_new(&mut builder), cose_status_t::COSE_OK);
        assert!(!builder.is_null());

        // Pack-specific functions now tested in their respective FFI crates
        // (e.g., cose_sign1_validation_ffi_certificates)

        let mut validator: *mut cose_validator_t = ptr::null_mut();
        assert_eq!(
            cose_validator_builder_build(builder, &mut validator),
            cose_status_t::COSE_OK
        );
        assert!(!validator.is_null());

        cose_validator_free(validator);
        cose_validator_builder_free(builder);
    }
}
