// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! C-ABI projection for `cose_sign1_transparent_mst`.
//!
//! This crate provides C-compatible FFI exports for the Microsoft Secure
//! Transparency (MST) extension pack. It enables C/C++ consumers to register
//! the MST trust pack with a validator builder, author trust policies that
//! constrain MST receipt properties (presence, KID, signature verification,
//! statement coverage, statement SHA-256 hash, and trust status), and interact
//! with the MST transparency service for creating and retrieving entries.
//!
//! # ABI Stability
//!
//! All exported functions use `extern "C"` calling convention.
//! Opaque handle types are passed as `*mut` (owned) or `*const` (borrowed).
//!
//! # Panic Safety
//!
//! All exported functions are wrapped in `catch_unwind` to prevent
//! Rust panics from crossing the FFI boundary.
//!
//! # Error Handling
//!
//! Functions return `cose_status_t` (0 = OK, non-zero = error).
//! On error, call `cose_last_error_message_utf8()` for details.
//! Error state is thread-local and safe for concurrent use.
//!
//! # Memory Ownership
//!
//! - `*mut T` parameters transfer ownership TO this function (consumed)
//! - `*const T` parameters are borrowed (caller retains ownership)
//! - `*mut *mut T` out-parameters transfer ownership FROM this function (caller must free)
//! - Every handle type has a corresponding `*_free()` function
//!
//! # Thread Safety
//!
//! All functions are thread-safe. Error state is thread-local.

#![cfg_attr(coverage_nightly, feature(coverage_attribute))]
#![deny(unsafe_op_in_unsafe_fn)]
#![allow(clippy::not_unsafe_ptr_arg_deref)]

use cose_sign1_transparent_mst::validation::facts::{
    MstReceiptKidFact, MstReceiptPresentFact, MstReceiptSignatureVerifiedFact,
    MstReceiptStatementCoverageFact, MstReceiptStatementSha256Fact, MstReceiptTrustedFact,
};
use cose_sign1_transparent_mst::validation::fluent_ext::{
    MstCounterSignatureScopeRulesExt, MstReceiptKidWhereExt, MstReceiptPresentWhereExt,
    MstReceiptSignatureVerifiedWhereExt, MstReceiptStatementCoverageWhereExt,
    MstReceiptStatementSha256WhereExt, MstReceiptTrustedWhereExt,
};
use cose_sign1_transparent_mst::validation::pack::MstTrustPack;
use cose_sign1_validation_ffi::{
    cose_sign1_validator_builder_t, cose_status_t, cose_trust_policy_builder_t, with_catch_unwind,
    with_trust_policy_builder_mut,
};
use std::ffi::{c_char, CStr};
use std::sync::Arc;

fn string_from_ptr(arg_name: &'static str, s: *const c_char) -> Result<String, anyhow::Error> {
    if s.is_null() {
        anyhow::bail!("{arg_name} must not be null");
    }
    // SAFETY: Caller guarantees `s` is a valid, NUL-terminated C string for the duration of this call.
    let s = unsafe { CStr::from_ptr(s) }
        .to_str()
        .map_err(|_| anyhow::anyhow!("{arg_name} must be valid UTF-8"))?;
    Ok(s.to_string())
}

/// C ABI representation of MST trust options.
#[repr(C)]
pub struct cose_mst_trust_options_t {
    /// If true, allow network fetching of JWKS when offline keys are missing.
    pub allow_network: bool,

    /// Offline JWKS JSON string (NULL means no offline JWKS). Ownership is not transferred.
    pub offline_jwks_json: *const c_char,

    /// Optional api-version for CodeTransparency /jwks endpoint (NULL means no api-version).
    pub jwks_api_version: *const c_char,
}

/// Adds the MST trust pack with default options (online mode).
#[no_mangle]
#[cfg_attr(coverage_nightly, coverage(off))]
pub extern "C" fn cose_sign1_validator_builder_with_mst_pack(
    builder: *mut cose_sign1_validator_builder_t,
) -> cose_status_t {
    with_catch_unwind(|| {
        // SAFETY: Pointer was null-checked by .ok_or_else below; dereference is valid for the lifetime of this function.
        let builder = unsafe { builder.as_mut() }
            .ok_or_else(|| anyhow::anyhow!("builder must not be null"))?;
        builder.packs.push(Arc::new(MstTrustPack::online()));
        Ok(cose_status_t::COSE_OK)
    })
}

/// Adds the MST trust pack with custom options (offline JWKS, etc.).
#[no_mangle]
#[cfg_attr(coverage_nightly, coverage(off))]
pub extern "C" fn cose_sign1_validator_builder_with_mst_pack_ex(
    builder: *mut cose_sign1_validator_builder_t,
    options: *const cose_mst_trust_options_t,
) -> cose_status_t {
    with_catch_unwind(|| {
        // SAFETY: Pointer was null-checked by .ok_or_else below; dereference is valid for the lifetime of this function.
        let builder = unsafe { builder.as_mut() }
            .ok_or_else(|| anyhow::anyhow!("builder must not be null"))?;

        let pack = if options.is_null() {
            MstTrustPack::online()
        } else {
            // SAFETY: Pointer was null-checked above (options.is_null() branch); dereference is valid for the lifetime of this function.
            let opts_ref = unsafe { &*options };
            let offline_jwks = if opts_ref.offline_jwks_json.is_null() {
                None
            } else {
                Some(
                    // SAFETY: Caller guarantees `offline_jwks_json` is a valid, NUL-terminated C string for the duration of this call.
                    unsafe { CStr::from_ptr(opts_ref.offline_jwks_json) }
                        .to_str()
                        .map_err(|_| anyhow::anyhow!("invalid UTF-8 in offline_jwks_json"))?
                        .to_string(),
                )
            };
            let api_version = if opts_ref.jwks_api_version.is_null() {
                None
            } else {
                Some(
                    // SAFETY: Caller guarantees `jwks_api_version` is a valid, NUL-terminated C string for the duration of this call.
                    unsafe { CStr::from_ptr(opts_ref.jwks_api_version) }
                        .to_str()
                        .map_err(|_| anyhow::anyhow!("invalid UTF-8 in jwks_api_version"))?
                        .to_string(),
                )
            };

            MstTrustPack::new(opts_ref.allow_network, offline_jwks, api_version)
        };

        builder.packs.push(Arc::new(pack));
        Ok(cose_status_t::COSE_OK)
    })
}

/// Trust-policy helper: require that an MST receipt is present on at least one counter-signature.
///
/// This API is provided by the MST pack FFI library and extends `cose_trust_policy_builder_t`.
#[no_mangle]
#[cfg_attr(coverage_nightly, coverage(off))]
pub extern "C" fn cose_sign1_mst_trust_policy_builder_require_receipt_present(
    policy_builder: *mut cose_trust_policy_builder_t,
) -> cose_status_t {
    with_catch_unwind(|| {
        with_trust_policy_builder_mut(policy_builder, |b| {
            b.for_counter_signature(|s| s.require_mst_receipt_present())
        })?;
        Ok(cose_status_t::COSE_OK)
    })
}

/// Trust-policy helper: require that an MST receipt is not present on all counter-signatures.
#[no_mangle]
#[cfg_attr(coverage_nightly, coverage(off))]
pub extern "C" fn cose_sign1_mst_trust_policy_builder_require_receipt_not_present(
    policy_builder: *mut cose_trust_policy_builder_t,
) -> cose_status_t {
    with_catch_unwind(|| {
        with_trust_policy_builder_mut(policy_builder, |b| {
            b.for_counter_signature(|s| {
                s.require::<MstReceiptPresentFact>(|w| w.require_receipt_not_present())
            })
        })?;
        Ok(cose_status_t::COSE_OK)
    })
}

/// Trust-policy helper: require that the MST receipt signature verified.
#[no_mangle]
#[cfg_attr(coverage_nightly, coverage(off))]
pub extern "C" fn cose_sign1_mst_trust_policy_builder_require_receipt_signature_verified(
    policy_builder: *mut cose_trust_policy_builder_t,
) -> cose_status_t {
    with_catch_unwind(|| {
        with_trust_policy_builder_mut(policy_builder, |b| {
            b.for_counter_signature(|s| s.require_mst_receipt_signature_verified())
        })?;
        Ok(cose_status_t::COSE_OK)
    })
}

/// Trust-policy helper: require that the MST receipt signature did not verify.
#[no_mangle]
#[cfg_attr(coverage_nightly, coverage(off))]
pub extern "C" fn cose_sign1_mst_trust_policy_builder_require_receipt_signature_not_verified(
    policy_builder: *mut cose_trust_policy_builder_t,
) -> cose_status_t {
    with_catch_unwind(|| {
        with_trust_policy_builder_mut(policy_builder, |b| {
            b.for_counter_signature(|s| {
                s.require::<MstReceiptSignatureVerifiedFact>(|w| {
                    w.require_receipt_signature_not_verified()
                })
            })
        })?;
        Ok(cose_status_t::COSE_OK)
    })
}

/// Trust-policy helper: require that the MST receipt issuer contains the provided substring.
#[no_mangle]
#[cfg_attr(coverage_nightly, coverage(off))]
pub extern "C" fn cose_sign1_mst_trust_policy_builder_require_receipt_issuer_contains(
    policy_builder: *mut cose_trust_policy_builder_t,
    needle_utf8: *const c_char,
) -> cose_status_t {
    with_catch_unwind(|| {
        let needle = string_from_ptr("needle_utf8", needle_utf8)?;
        with_trust_policy_builder_mut(policy_builder, |b| {
            b.for_counter_signature(|s| s.require_mst_receipt_issuer_contains(needle))
        })?;
        Ok(cose_status_t::COSE_OK)
    })
}

/// Trust-policy helper: require that the MST receipt issuer equals the provided value.
#[no_mangle]
#[cfg_attr(coverage_nightly, coverage(off))]
pub extern "C" fn cose_sign1_mst_trust_policy_builder_require_receipt_issuer_eq(
    policy_builder: *mut cose_trust_policy_builder_t,
    issuer_utf8: *const c_char,
) -> cose_status_t {
    with_catch_unwind(|| {
        let issuer = string_from_ptr("issuer_utf8", issuer_utf8)?;
        with_trust_policy_builder_mut(policy_builder, |b| {
            b.for_counter_signature(|s| s.require_mst_receipt_issuer_eq(issuer))
        })?;
        Ok(cose_status_t::COSE_OK)
    })
}

/// Trust-policy helper: require that the MST receipt key id (kid) equals the provided value.
#[no_mangle]
#[cfg_attr(coverage_nightly, coverage(off))]
pub extern "C" fn cose_sign1_mst_trust_policy_builder_require_receipt_kid_eq(
    policy_builder: *mut cose_trust_policy_builder_t,
    kid_utf8: *const c_char,
) -> cose_status_t {
    with_catch_unwind(|| {
        let kid = string_from_ptr("kid_utf8", kid_utf8)?;
        with_trust_policy_builder_mut(policy_builder, |b| {
            b.for_counter_signature(|s| s.require_mst_receipt_kid_eq(kid))
        })?;
        Ok(cose_status_t::COSE_OK)
    })
}

/// Trust-policy helper: require that the MST receipt key id (kid) contains the provided substring.
#[no_mangle]
#[cfg_attr(coverage_nightly, coverage(off))]
pub extern "C" fn cose_sign1_mst_trust_policy_builder_require_receipt_kid_contains(
    policy_builder: *mut cose_trust_policy_builder_t,
    needle_utf8: *const c_char,
) -> cose_status_t {
    with_catch_unwind(|| {
        let needle = string_from_ptr("needle_utf8", needle_utf8)?;
        with_trust_policy_builder_mut(policy_builder, |b| {
            b.for_counter_signature(|s| {
                s.require::<MstReceiptKidFact>(|w| w.require_receipt_kid_contains(needle))
            })
        })?;
        Ok(cose_status_t::COSE_OK)
    })
}

/// Trust-policy helper: require that the MST receipt is trusted.
#[no_mangle]
#[cfg_attr(coverage_nightly, coverage(off))]
pub extern "C" fn cose_sign1_mst_trust_policy_builder_require_receipt_trusted(
    policy_builder: *mut cose_trust_policy_builder_t,
) -> cose_status_t {
    with_catch_unwind(|| {
        with_trust_policy_builder_mut(policy_builder, |b| {
            b.for_counter_signature(|s| {
                s.require::<MstReceiptTrustedFact>(|w| w.require_receipt_trusted())
            })
        })?;
        Ok(cose_status_t::COSE_OK)
    })
}

/// Trust-policy helper: require that the MST receipt is not trusted.
#[no_mangle]
#[cfg_attr(coverage_nightly, coverage(off))]
pub extern "C" fn cose_sign1_mst_trust_policy_builder_require_receipt_not_trusted(
    policy_builder: *mut cose_trust_policy_builder_t,
) -> cose_status_t {
    with_catch_unwind(|| {
        with_trust_policy_builder_mut(policy_builder, |b| {
            b.for_counter_signature(|s| {
                s.require::<MstReceiptTrustedFact>(|w| w.require_receipt_not_trusted())
            })
        })?;
        Ok(cose_status_t::COSE_OK)
    })
}

/// Trust-policy helper: convenience = require (receipt trusted) AND (issuer contains substring).
#[no_mangle]
#[cfg_attr(coverage_nightly, coverage(off))]
pub extern "C" fn cose_sign1_mst_trust_policy_builder_require_receipt_trusted_from_issuer_contains(
    policy_builder: *mut cose_trust_policy_builder_t,
    needle_utf8: *const c_char,
) -> cose_status_t {
    with_catch_unwind(|| {
        let needle = string_from_ptr("needle_utf8", needle_utf8)?;
        with_trust_policy_builder_mut(policy_builder, |b| {
            b.for_counter_signature(|s| s.require_mst_receipt_trusted_from_issuer(needle))
        })?;
        Ok(cose_status_t::COSE_OK)
    })
}

/// Trust-policy helper: require that the MST receipt statement SHA-256 digest equals the provided hex string.
#[no_mangle]
#[cfg_attr(coverage_nightly, coverage(off))]
pub extern "C" fn cose_sign1_mst_trust_policy_builder_require_receipt_statement_sha256_eq(
    policy_builder: *mut cose_trust_policy_builder_t,
    sha256_hex_utf8: *const c_char,
) -> cose_status_t {
    with_catch_unwind(|| {
        let sha256_hex = string_from_ptr("sha256_hex_utf8", sha256_hex_utf8)?;
        with_trust_policy_builder_mut(policy_builder, |b| {
            b.for_counter_signature(|s| {
                s.require::<MstReceiptStatementSha256Fact>(|w| {
                    w.require_receipt_statement_sha256_eq(sha256_hex)
                })
            })
        })?;
        Ok(cose_status_t::COSE_OK)
    })
}

/// Trust-policy helper: require that the MST receipt statement coverage equals the provided value.
#[no_mangle]
#[cfg_attr(coverage_nightly, coverage(off))]
pub extern "C" fn cose_sign1_mst_trust_policy_builder_require_receipt_statement_coverage_eq(
    policy_builder: *mut cose_trust_policy_builder_t,
    coverage_utf8: *const c_char,
) -> cose_status_t {
    with_catch_unwind(|| {
        let coverage = string_from_ptr("coverage_utf8", coverage_utf8)?;
        with_trust_policy_builder_mut(policy_builder, |b| {
            b.for_counter_signature(|s| {
                s.require::<MstReceiptStatementCoverageFact>(|w| {
                    w.require_receipt_statement_coverage_eq(coverage)
                })
            })
        })?;
        Ok(cose_status_t::COSE_OK)
    })
}

/// Trust-policy helper: require that the MST receipt statement coverage contains the provided substring.
#[no_mangle]
#[cfg_attr(coverage_nightly, coverage(off))]
pub extern "C" fn cose_sign1_mst_trust_policy_builder_require_receipt_statement_coverage_contains(
    policy_builder: *mut cose_trust_policy_builder_t,
    needle_utf8: *const c_char,
) -> cose_status_t {
    with_catch_unwind(|| {
        let needle = string_from_ptr("needle_utf8", needle_utf8)?;
        with_trust_policy_builder_mut(policy_builder, |b| {
            b.for_counter_signature(|s| {
                s.require::<MstReceiptStatementCoverageFact>(|w| {
                    w.require_receipt_statement_coverage_contains(needle)
                })
            })
        })?;
        Ok(cose_status_t::COSE_OK)
    })
}

// ============================================================================
// MST Transparency Client Signing Support
// ============================================================================

use code_transparency_client::{CodeTransparencyClient, CodeTransparencyClientConfig};
use std::ffi::CString;
use std::slice;

/// Opaque handle for CodeTransparencyClient.
#[repr(C)]
pub struct MstClientHandle(CodeTransparencyClient);

/// Creates a new MST transparency client.
///
/// # Arguments
///
/// * `endpoint` - The base URL of the transparency service (required, null-terminated C string).
/// * `api_version` - Optional API version string (null = use default "2024-01-01").
/// * `api_key` - Optional API key for authentication (null = unauthenticated).
/// * `out_client` - Output pointer for the created client handle.
///
/// # Returns
///
/// * `COSE_OK` on success
/// * `COSE_ERR` on failure (use `cose_last_error_message_utf8` to get details)
///
/// # Safety
///
/// - `endpoint` must be a valid null-terminated C string
/// - `api_version` must be a valid null-terminated C string or null
/// - `api_key` must be a valid null-terminated C string or null
/// - `out_client` must be valid for writes
/// - Caller must free the returned client with `cose_mst_client_free`
#[no_mangle]
#[cfg_attr(coverage_nightly, coverage(off))]
pub extern "C" fn cose_mst_client_new(
    endpoint: *const c_char,
    api_version: *const c_char,
    api_key: *const c_char,
    out_client: *mut *mut MstClientHandle,
) -> cose_status_t {
    with_catch_unwind(|| {
        if out_client.is_null() {
            anyhow::bail!("out_client must not be null");
        }

        // SAFETY: out_client was null-checked above; writing null to initialize the output pointer.
        unsafe {
            *out_client = std::ptr::null_mut();
        }

        let endpoint_str = string_from_ptr("endpoint", endpoint)?;
        let endpoint_url = url::Url::parse(&endpoint_str)
            .map_err(|e| anyhow::anyhow!("invalid endpoint URL: {}", e))?;

        let mut options = CodeTransparencyClientConfig::default();

        if !api_version.is_null() {
            let version_str = string_from_ptr("api_version", api_version)?;
            options.api_version = version_str;
        }

        if !api_key.is_null() {
            let key_str = string_from_ptr("api_key", api_key)?;
            options.api_key = Some(key_str);
        }

        let client = CodeTransparencyClient::new(endpoint_url, options);
        let handle = Box::new(MstClientHandle(client));

        // SAFETY: out_client was null-checked above; caller takes ownership and must free with cose_mst_client_free.
        unsafe {
            *out_client = Box::into_raw(handle);
        }

        Ok(cose_status_t::COSE_OK)
    })
}

/// Frees an MST transparency client handle.
///
/// # Safety
///
/// - `client` must be a valid client handle created by `cose_mst_client_new` or null
/// - The handle must not be used after this call
#[no_mangle]
#[cfg_attr(coverage_nightly, coverage(off))]
pub unsafe extern "C" fn cose_mst_client_free(client: *mut MstClientHandle) {
    if client.is_null() {
        return;
    }
    // SAFETY: Pointer was originally created by Box::into_raw in cose_mst_client_new; caller transfers ownership back.
    unsafe {
        drop(Box::from_raw(client));
    }
}

/// Makes a COSE_Sign1 message transparent by submitting it to the MST service.
///
/// This is a convenience function that combines create_entry and get_entry_statement.
///
/// # Arguments
///
/// * `client` - The MST transparency client handle.
/// * `cose_bytes` - The COSE_Sign1 message bytes to submit.
/// * `cose_len` - Length of the COSE bytes.
/// * `out_bytes` - Output pointer for the transparency statement bytes.
/// * `out_len` - Output pointer for the statement length.
///
/// # Returns
///
/// * `COSE_OK` on success
/// * `COSE_ERR` on failure (use `cose_last_error_message_utf8` to get details)
///
/// # Safety
///
/// - `client` must be a valid client handle
/// - `cose_bytes` must be valid for reads of `cose_len` bytes
/// - `out_bytes` and `out_len` must be valid for writes
/// - Caller must free the returned bytes with `cose_mst_bytes_free`
#[no_mangle]
#[cfg_attr(coverage_nightly, coverage(off))]
pub extern "C" fn cose_sign1_mst_make_transparent(
    client: *const MstClientHandle,
    cose_bytes: *const u8,
    cose_len: usize,
    out_bytes: *mut *mut u8,
    out_len: *mut usize,
) -> cose_status_t {
    with_catch_unwind(|| {
        if out_bytes.is_null() || out_len.is_null() {
            anyhow::bail!("out_bytes and out_len must not be null");
        }

        // SAFETY: out_bytes and out_len were null-checked above; writing initial values to initialize output pointers.
        unsafe {
            *out_bytes = std::ptr::null_mut();
            *out_len = 0;
        }

        // SAFETY: Pointer was null-checked by .ok_or_else below; dereference is valid for the lifetime of this function.
        let client_ref =
            unsafe { client.as_ref() }.ok_or_else(|| anyhow::anyhow!("client must not be null"))?;

        if cose_bytes.is_null() {
            anyhow::bail!("cose_bytes must not be null");
        }

        // SAFETY: Pointer and length were validated above; the slice is valid for the duration of this call.
        let cose_slice = unsafe { slice::from_raw_parts(cose_bytes, cose_len) };

        let statement = client_ref
            .0
            .make_transparent(cose_slice)
            .map_err(|e| anyhow::anyhow!("failed to make transparent: {}", e))?;

        let len = statement.len();
        let boxed = statement.into_boxed_slice();
        let ptr = Box::into_raw(boxed) as *mut u8;

        // SAFETY: out_bytes and out_len were null-checked above; caller takes ownership and must free with cose_mst_bytes_free.
        unsafe {
            *out_bytes = ptr;
            *out_len = len;
        }

        Ok(cose_status_t::COSE_OK)
    })
}

/// Creates a transparency entry by submitting a COSE_Sign1 message.
///
/// This function submits the COSE message, polls for completion, and returns
/// both the operation ID and the final entry ID.
///
/// # Arguments
///
/// * `client` - The MST transparency client handle.
/// * `cose_bytes` - The COSE_Sign1 message bytes to submit.
/// * `cose_len` - Length of the COSE bytes.
/// * `out_operation_id` - Output pointer for the operation ID string.
/// * `out_entry_id` - Output pointer for the entry ID string.
///
/// # Returns
///
/// * `COSE_OK` on success
/// * `COSE_ERR` on failure (use `cose_last_error_message_utf8` to get details)
///
/// # Safety
///
/// - `client` must be a valid client handle
/// - `cose_bytes` must be valid for reads of `cose_len` bytes
/// - `out_operation_id` and `out_entry_id` must be valid for writes
/// - Caller must free the returned strings with `cose_mst_string_free`
#[no_mangle]
#[cfg_attr(coverage_nightly, coverage(off))]
pub extern "C" fn cose_sign1_mst_create_entry(
    client: *const MstClientHandle,
    cose_bytes: *const u8,
    cose_len: usize,
    out_operation_id: *mut *mut c_char,
    out_entry_id: *mut *mut c_char,
) -> cose_status_t {
    with_catch_unwind(|| {
        if out_operation_id.is_null() || out_entry_id.is_null() {
            anyhow::bail!("out_operation_id and out_entry_id must not be null");
        }

        // SAFETY: out_operation_id and out_entry_id were null-checked above; writing null to initialize output pointers.
        unsafe {
            *out_operation_id = std::ptr::null_mut();
            *out_entry_id = std::ptr::null_mut();
        }

        // SAFETY: Pointer was null-checked by .ok_or_else below; dereference is valid for the lifetime of this function.
        let client_ref =
            unsafe { client.as_ref() }.ok_or_else(|| anyhow::anyhow!("client must not be null"))?;

        if cose_bytes.is_null() {
            anyhow::bail!("cose_bytes must not be null");
        }

        // SAFETY: Pointer and length were validated above; the slice is valid for the duration of this call.
        let cose_slice = unsafe { slice::from_raw_parts(cose_bytes, cose_len) };

        let result = client_ref
            .0
            .create_entry(cose_slice)
            .map_err(|e| anyhow::anyhow!("failed to create entry: {}", e))?;

        // The Poller needs to be awaited — create a runtime for the FFI boundary
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|e| anyhow::anyhow!("failed to create runtime: {}", e))?;

        let response = rt
            .block_on(async { result.await })
            .map_err(|e| anyhow::anyhow!("poller failed: {}", e))?;

        let model = response
            .into_model()
            .map_err(|e| anyhow::anyhow!("failed to deserialize: {}", e))?;

        let op_id_cstr = CString::new(model.operation_id)
            .map_err(|_| anyhow::anyhow!("operation_id contains null byte"))?;
        let entry_id_cstr = CString::new(model.entry_id.unwrap_or_default())
            .map_err(|_| anyhow::anyhow!("entry_id contains null byte"))?;

        // SAFETY: out_operation_id and out_entry_id were null-checked above; caller takes ownership and must free with cose_mst_string_free.
        unsafe {
            *out_operation_id = op_id_cstr.into_raw();
            *out_entry_id = entry_id_cstr.into_raw();
        }

        Ok(cose_status_t::COSE_OK)
    })
}

/// Gets the transparency statement for an entry.
///
/// # Arguments
///
/// * `client` - The MST transparency client handle.
/// * `entry_id` - The entry ID (null-terminated C string).
/// * `out_bytes` - Output pointer for the statement bytes.
/// * `out_len` - Output pointer for the statement length.
///
/// # Returns
///
/// * `COSE_OK` on success
/// * `COSE_ERR` on failure (use `cose_last_error_message_utf8` to get details)
///
/// # Safety
///
/// - `client` must be a valid client handle
/// - `entry_id` must be a valid null-terminated C string
/// - `out_bytes` and `out_len` must be valid for writes
/// - Caller must free the returned bytes with `cose_mst_bytes_free`
#[no_mangle]
#[cfg_attr(coverage_nightly, coverage(off))]
pub extern "C" fn cose_sign1_mst_get_entry_statement(
    client: *const MstClientHandle,
    entry_id: *const c_char,
    out_bytes: *mut *mut u8,
    out_len: *mut usize,
) -> cose_status_t {
    with_catch_unwind(|| {
        if out_bytes.is_null() || out_len.is_null() {
            anyhow::bail!("out_bytes and out_len must not be null");
        }

        // SAFETY: out_bytes and out_len were null-checked above; writing initial values to initialize output pointers.
        unsafe {
            *out_bytes = std::ptr::null_mut();
            *out_len = 0;
        }

        // SAFETY: Pointer was null-checked by .ok_or_else below; dereference is valid for the lifetime of this function.
        let client_ref =
            unsafe { client.as_ref() }.ok_or_else(|| anyhow::anyhow!("client must not be null"))?;

        let entry_id_str = string_from_ptr("entry_id", entry_id)?;

        let statement = client_ref
            .0
            .get_entry_statement(&entry_id_str)
            .map_err(|e| anyhow::anyhow!("failed to get entry statement: {}", e))?;

        let len = statement.len();
        let boxed = statement.into_boxed_slice();
        let ptr = Box::into_raw(boxed) as *mut u8;

        // SAFETY: out_bytes and out_len were null-checked above; caller takes ownership and must free with cose_mst_bytes_free.
        unsafe {
            *out_bytes = ptr;
            *out_len = len;
        }

        Ok(cose_status_t::COSE_OK)
    })
}

/// Frees bytes previously returned by MST client functions.
///
/// # Safety
///
/// - `ptr` must have been returned by an MST client function or be null
/// - `len` must be the length returned alongside the bytes
/// - The bytes must not be used after this call
#[no_mangle]
#[cfg_attr(coverage_nightly, coverage(off))]
pub unsafe extern "C" fn cose_mst_bytes_free(ptr: *mut u8, len: usize) {
    if ptr.is_null() {
        return;
    }
    // SAFETY: Pointer was originally created by Box::into_raw in the corresponding MST client function; caller transfers ownership back.
    unsafe {
        drop(Box::from_raw(std::ptr::slice_from_raw_parts_mut(ptr, len)));
    }
}

/// Frees a string previously returned by MST client functions.
///
/// # Safety
///
/// - `s` must have been returned by an MST client function or be null
/// - The string must not be used after this call
#[no_mangle]
#[cfg_attr(coverage_nightly, coverage(off))]
pub unsafe extern "C" fn cose_mst_string_free(s: *mut c_char) {
    if s.is_null() {
        return;
    }
    // SAFETY: Pointer was originally created by CString::into_raw in the corresponding MST client function; caller transfers ownership back.
    unsafe {
        drop(CString::from_raw(s));
    }
}
