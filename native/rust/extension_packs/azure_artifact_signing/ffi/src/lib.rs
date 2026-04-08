// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![cfg_attr(coverage_nightly, feature(coverage_attribute))]

//! C-ABI projection for `cose_sign1_azure_artifact_signing`.
//!
//! This crate provides C-compatible FFI exports for the Azure Artifact Signing
//! (AAS) extension pack. It enables C/C++ consumers to register the AAS trust
//! pack with a validator builder, with support for both default and custom
//! trust options (endpoint URL, account name, certificate profile name).
//!
//! # ABI Stability
//!
//! All exported functions use `extern "C"` calling convention.
//! Opaque handle types are passed as `*mut` (owned) or `*const` (borrowed).
//! The ABI version is available via `cose_sign1_ats_abi_version()`.
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

#![deny(unsafe_op_in_unsafe_fn)]
#![allow(clippy::not_unsafe_ptr_arg_deref)]

use cose_sign1_azure_artifact_signing::options::AzureArtifactSigningOptions;
use cose_sign1_azure_artifact_signing::validation::fluent_ext::AasPrimarySigningKeyScopeRulesExt;
use cose_sign1_azure_artifact_signing::validation::AzureArtifactSigningTrustPack;
use cose_sign1_validation_ffi::{cose_sign1_validator_builder_t, cose_status_t, with_catch_unwind};
use cose_sign1_validation_ffi::{cose_trust_policy_builder_t, with_trust_policy_builder_mut};
use std::ffi::{c_char, CStr};
use std::sync::Arc;

/// C ABI options for Azure Artifact Signing.
#[repr(C)]
pub struct cose_ats_trust_options_t {
    /// AAS endpoint URL (null-terminated UTF-8).
    pub endpoint: *const c_char,
    /// AAS account name (null-terminated UTF-8).
    pub account_name: *const c_char,
    /// Certificate profile name (null-terminated UTF-8).
    pub certificate_profile_name: *const c_char,
}

/// Returns the ABI version for this FFI library.
#[no_mangle]
pub extern "C" fn cose_sign1_ats_abi_version() -> u32 {
    1
}

/// Adds the AAS trust pack with default options.
#[no_mangle]
pub extern "C" fn cose_sign1_validator_builder_with_ats_pack(
    builder: *mut cose_sign1_validator_builder_t,
) -> cose_status_t {
    with_catch_unwind(|| {
        // SAFETY: Pointer was null-checked by `as_mut()` returning `None` (handled by `ok_or_else` below).
        let builder = unsafe { builder.as_mut() }
            .ok_or_else(|| anyhow::anyhow!("builder must not be null"))?;
        builder
            .packs
            .push(Arc::new(AzureArtifactSigningTrustPack::new()));
        Ok(cose_status_t::COSE_OK)
    })
}

/// Adds the AAS trust pack with custom options.
#[no_mangle]
pub extern "C" fn cose_sign1_validator_builder_with_ats_pack_ex(
    builder: *mut cose_sign1_validator_builder_t,
    options: *const cose_ats_trust_options_t,
) -> cose_status_t {
    with_catch_unwind(|| {
        // SAFETY: Pointer was null-checked by `as_mut()` returning `None` (handled by `ok_or_else` below).
        let builder = unsafe { builder.as_mut() }
            .ok_or_else(|| anyhow::anyhow!("builder must not be null"))?;

        // Parse options or use defaults
        let _opts = if options.is_null() {
            None
        } else {
            // SAFETY: Pointer was null-checked above (`options.is_null()` is false in this branch).
            let opts_ref = unsafe { &*options };
            let endpoint = if opts_ref.endpoint.is_null() {
                String::new()
            } else {
                // SAFETY: Caller guarantees `endpoint` is a valid, NUL-terminated C string for the duration of this call.
                unsafe { CStr::from_ptr(opts_ref.endpoint) }
                    .to_str()
                    .unwrap_or_default()
                    .to_string()
            };
            let account = if opts_ref.account_name.is_null() {
                String::new()
            } else {
                // SAFETY: Caller guarantees `account_name` is a valid, NUL-terminated C string for the duration of this call.
                unsafe { CStr::from_ptr(opts_ref.account_name) }
                    .to_str()
                    .unwrap_or_default()
                    .to_string()
            };
            let profile = if opts_ref.certificate_profile_name.is_null() {
                String::new()
            } else {
                // SAFETY: Caller guarantees `certificate_profile_name` is a valid, NUL-terminated C string for the duration of this call.
                unsafe { CStr::from_ptr(opts_ref.certificate_profile_name) }
                    .to_str()
                    .unwrap_or_default()
                    .to_string()
            };
            Some(AzureArtifactSigningOptions {
                endpoint,
                account_name: account,
                certificate_profile_name: profile,
            })
        };

        // For now, always use the default pack (options will be used once AAS SDK is integrated)
        builder
            .packs
            .push(Arc::new(AzureArtifactSigningTrustPack::new()));
        Ok(cose_status_t::COSE_OK)
    })
}

/// Trust-policy helper: require that the signing certificate was issued by
/// Azure Artifact Signing.
///
/// Adds a requirement on `AasSigningServiceIdentifiedFact.is_ats_issued == true`
/// to the primary signing key scope of the trust policy.
///
/// # Safety
///
/// `policy_builder` must be a valid, non-null pointer to a `cose_trust_policy_builder_t`.
#[no_mangle]
#[cfg_attr(coverage_nightly, coverage(off))]
pub extern "C" fn cose_sign1_ats_trust_policy_builder_require_ats_identified(
    policy_builder: *mut cose_trust_policy_builder_t,
) -> cose_status_t {
    with_catch_unwind(|| {
        with_trust_policy_builder_mut(policy_builder, |b| {
            b.for_primary_signing_key(|s| s.require_ats_identified())
        })?;
        Ok(cose_status_t::COSE_OK)
    })
}

/// Trust-policy helper: require that the signing operation is SCITT compliant
/// (AAS-issued with SCITT headers present).
///
/// Adds a requirement on `AasComplianceFact.scitt_compliant == true`
/// to the primary signing key scope of the trust policy.
///
/// # Safety
///
/// `policy_builder` must be a valid, non-null pointer to a `cose_trust_policy_builder_t`.
#[no_mangle]
#[cfg_attr(coverage_nightly, coverage(off))]
pub extern "C" fn cose_sign1_ats_trust_policy_builder_require_ats_compliant(
    policy_builder: *mut cose_trust_policy_builder_t,
) -> cose_status_t {
    with_catch_unwind(|| {
        with_trust_policy_builder_mut(policy_builder, |b| {
            b.for_primary_signing_key(|s| s.require_ats_compliant())
        })?;
        Ok(cose_status_t::COSE_OK)
    })
}
