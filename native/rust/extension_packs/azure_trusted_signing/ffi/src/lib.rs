// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Azure Trusted Signing pack FFI bindings.

#![deny(unsafe_op_in_unsafe_fn)]
#![allow(clippy::not_unsafe_ptr_arg_deref)]

use cose_sign1_azure_trusted_signing::options::AzureTrustedSigningOptions;
use cose_sign1_azure_trusted_signing::validation::AzureTrustedSigningTrustPack;
use cose_sign1_validation_ffi::{
    cose_status_t, cose_sign1_validator_builder_t,
    with_catch_unwind,
};
use std::ffi::{c_char, CStr};
use std::sync::Arc;

/// C ABI options for Azure Trusted Signing.
#[repr(C)]
pub struct cose_ats_trust_options_t {
    /// ATS endpoint URL (null-terminated UTF-8).
    pub endpoint: *const c_char,
    /// ATS account name (null-terminated UTF-8).
    pub account_name: *const c_char,
    /// Certificate profile name (null-terminated UTF-8).
    pub certificate_profile_name: *const c_char,
}

/// Returns the ABI version for this FFI library.
#[no_mangle]
pub extern "C" fn cose_sign1_ats_abi_version() -> u32 {
    1
}

/// Adds the ATS trust pack with default options.
#[no_mangle]
pub extern "C" fn cose_sign1_validator_builder_with_ats_pack(
    builder: *mut cose_sign1_validator_builder_t,
) -> cose_status_t {
    with_catch_unwind(|| {
        let builder = unsafe { builder.as_mut() }
            .ok_or_else(|| anyhow::anyhow!("builder must not be null"))?;
        builder
            .packs
            .push(Arc::new(AzureTrustedSigningTrustPack::new()));
        Ok(cose_status_t::COSE_OK)
    })
}

/// Adds the ATS trust pack with custom options.
#[no_mangle]
pub extern "C" fn cose_sign1_validator_builder_with_ats_pack_ex(
    builder: *mut cose_sign1_validator_builder_t,
    options: *const cose_ats_trust_options_t,
) -> cose_status_t {
    with_catch_unwind(|| {
        let builder = unsafe { builder.as_mut() }
            .ok_or_else(|| anyhow::anyhow!("builder must not be null"))?;

        // Parse options or use defaults
        let _opts = if options.is_null() {
            None
        } else {
            let opts_ref = unsafe { &*options };
            let endpoint = if opts_ref.endpoint.is_null() {
                String::new()
            } else {
                unsafe { CStr::from_ptr(opts_ref.endpoint) }
                    .to_str()
                    .unwrap_or_default()
                    .to_string()
            };
            let account = if opts_ref.account_name.is_null() {
                String::new()
            } else {
                unsafe { CStr::from_ptr(opts_ref.account_name) }
                    .to_str()
                    .unwrap_or_default()
                    .to_string()
            };
            let profile = if opts_ref.certificate_profile_name.is_null() {
                String::new()
            } else {
                unsafe { CStr::from_ptr(opts_ref.certificate_profile_name) }
                    .to_str()
                    .unwrap_or_default()
                    .to_string()
            };
            Some(AzureTrustedSigningOptions {
                endpoint,
                account_name: account,
                certificate_profile_name: profile,
            })
        };

        // For now, always use the default pack (options will be used once ATS SDK is integrated)
        builder
            .packs
            .push(Arc::new(AzureTrustedSigningTrustPack::new()));
        Ok(cose_status_t::COSE_OK)
    })
}

// TODO: Add trust policy builder helpers once the fact types are stabilized:
// cose_sign1_ats_trust_policy_builder_require_ats_identified
// cose_sign1_ats_trust_policy_builder_require_ats_compliant