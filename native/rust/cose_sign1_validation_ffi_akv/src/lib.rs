//! Azure Key Vault pack FFI bindings.
//!
//! This crate exposes the Azure Key Vault KID validation pack to C/C++ consumers.

#![deny(unsafe_op_in_unsafe_fn)]

use cose_sign1_validation_azure_key_vault::facts::{
    AzureKeyVaultKidAllowedFact, AzureKeyVaultKidDetectedFact,
};
use cose_sign1_validation_azure_key_vault::fluent_ext::{
    AzureKeyVaultKidAllowedWhereExt, AzureKeyVaultKidDetectedWhereExt,
    AzureKeyVaultMessageScopeRulesExt,
};
use cose_sign1_validation_azure_key_vault::pack::{AzureKeyVaultTrustOptions, AzureKeyVaultTrustPack};
use cose_sign1_validation_ffi::{
    cose_status_t, cose_trust_policy_builder_t, cose_validator_builder_t, with_catch_unwind,
    with_trust_policy_builder_mut,
};
use std::ffi::{c_char, CStr};
use std::sync::Arc;

/// C ABI representation of Azure Key Vault trust options.
#[repr(C)]
pub struct cose_akv_trust_options_t {
    /// If true, require the KID to look like an Azure Key Vault identifier.
    pub require_azure_key_vault_kid: bool,
    
    /// Null-terminated array of allowed KID pattern strings (supports wildcards * and ?).
    /// NULL pointer means use default patterns (*.vault.azure.net, *.managedhsm.azure.net).
    pub allowed_kid_patterns: *const *const c_char,
}

/// Helper to convert null-terminated string array to Vec<String>.
unsafe fn string_array_to_vec(arr: *const *const c_char) -> Vec<String> {
    if arr.is_null() {
        return Vec::new();
    }
    
    let mut result = Vec::new();
    let mut ptr = arr;
    loop {
        let s = unsafe { *ptr };
        if s.is_null() {
            break;
        }
        if let Ok(cstr) = unsafe { CStr::from_ptr(s).to_str() } {
            result.push(cstr.to_string());
        }
        ptr = unsafe { ptr.add(1) };
    }
    result
}

/// Adds the Azure Key Vault trust pack with default options.
#[no_mangle]
pub extern "C" fn cose_validator_builder_with_akv_pack(
    builder: *mut cose_validator_builder_t,
) -> cose_status_t {
    with_catch_unwind(|| {
        let builder = unsafe { builder.as_mut() }
            .ok_or_else(|| anyhow::anyhow!("builder must not be null"))?;
        builder
            .packs
            .push(Arc::new(AzureKeyVaultTrustPack::new(
                AzureKeyVaultTrustOptions::default(),
            )));
        Ok(cose_status_t::COSE_OK)
    })
}

/// Adds the Azure Key Vault trust pack with custom options (allowed patterns, etc.).
#[no_mangle]
pub extern "C" fn cose_validator_builder_with_akv_pack_ex(
    builder: *mut cose_validator_builder_t,
    options: *const cose_akv_trust_options_t,
) -> cose_status_t {
    with_catch_unwind(|| {
        let builder = unsafe { builder.as_mut() }
            .ok_or_else(|| anyhow::anyhow!("builder must not be null"))?;
        
        let opts = if options.is_null() {
            AzureKeyVaultTrustOptions::default()
        } else {
            let opts_ref = unsafe { &*options };
            let patterns = unsafe { string_array_to_vec(opts_ref.allowed_kid_patterns) };
            AzureKeyVaultTrustOptions {
                require_azure_key_vault_kid: opts_ref.require_azure_key_vault_kid,
                allowed_kid_patterns: if patterns.is_empty() {
                    // Use defaults if no patterns provided
                    vec![
                        "https://*.vault.azure.net/keys/*".to_string(),
                        "https://*.managedhsm.azure.net/keys/*".to_string(),
                    ]
                } else {
                    patterns
                },
            }
        };
        
        builder.packs.push(Arc::new(AzureKeyVaultTrustPack::new(opts)));
        Ok(cose_status_t::COSE_OK)
    })
}

/// Trust-policy helper: require that the message `kid` looks like an Azure Key Vault key identifier.
#[no_mangle]
pub extern "C" fn cose_akv_trust_policy_builder_require_azure_key_vault_kid(
    policy_builder: *mut cose_trust_policy_builder_t,
) -> cose_status_t {
    with_catch_unwind(|| {
        with_trust_policy_builder_mut(policy_builder, |b| {
            b.for_message(|s| s.require_azure_key_vault_kid())
        })?;
        Ok(cose_status_t::COSE_OK)
    })
}

/// Trust-policy helper: require that the message `kid` does not look like an Azure Key Vault key identifier.
#[no_mangle]
pub extern "C" fn cose_akv_trust_policy_builder_require_not_azure_key_vault_kid(
    policy_builder: *mut cose_trust_policy_builder_t,
) -> cose_status_t {
    with_catch_unwind(|| {
        with_trust_policy_builder_mut(policy_builder, |b| {
            b.for_message(|s| {
                s.require::<AzureKeyVaultKidDetectedFact>(|w| w.require_not_azure_key_vault_kid())
            })
        })?;
        Ok(cose_status_t::COSE_OK)
    })
}

/// Trust-policy helper: require that the message `kid` is allowlisted by the AKV pack configuration.
#[no_mangle]
pub extern "C" fn cose_akv_trust_policy_builder_require_azure_key_vault_kid_allowed(
    policy_builder: *mut cose_trust_policy_builder_t,
) -> cose_status_t {
    with_catch_unwind(|| {
        with_trust_policy_builder_mut(policy_builder, |b| {
            b.for_message(|s| s.require_azure_key_vault_kid_allowed())
        })?;
        Ok(cose_status_t::COSE_OK)
    })
}

/// Trust-policy helper: require that the message `kid` is not allowlisted by the AKV pack configuration.
#[no_mangle]
pub extern "C" fn cose_akv_trust_policy_builder_require_azure_key_vault_kid_not_allowed(
    policy_builder: *mut cose_trust_policy_builder_t,
) -> cose_status_t {
    with_catch_unwind(|| {
        with_trust_policy_builder_mut(policy_builder, |b| {
            b.for_message(|s| {
                s.require::<AzureKeyVaultKidAllowedFact>(|w| w.require_kid_not_allowed())
            })
        })?;
        Ok(cose_status_t::COSE_OK)
    })
}
