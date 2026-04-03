//! Azure Key Vault pack FFI bindings.
//!
//! This crate exposes the Azure Key Vault KID validation pack and signing key creation to C/C++ consumers.

#![cfg_attr(coverage_nightly, feature(coverage_attribute))]
#![deny(unsafe_op_in_unsafe_fn)]
#![allow(clippy::not_unsafe_ptr_arg_deref)]

use cose_sign1_azure_key_vault::common::akv_key_client::AkvKeyClient;
use cose_sign1_azure_key_vault::common::crypto_client::KeyVaultCryptoClient;
use cose_sign1_azure_key_vault::signing::akv_signing_key::AzureKeyVaultSigningKey;
use cose_sign1_azure_key_vault::signing::AzureKeyVaultSigningService;
use cose_sign1_azure_key_vault::validation::facts::{
    AzureKeyVaultKidAllowedFact, AzureKeyVaultKidDetectedFact,
};
use cose_sign1_azure_key_vault::validation::fluent_ext::{
    AzureKeyVaultKidAllowedWhereExt, AzureKeyVaultKidDetectedWhereExt,
    AzureKeyVaultMessageScopeRulesExt,
};
use cose_sign1_azure_key_vault::validation::pack::{
    AzureKeyVaultTrustOptions, AzureKeyVaultTrustPack,
};
use cose_sign1_signing_ffi::types::KeyInner;
use cose_sign1_validation_ffi::{
    cose_sign1_validator_builder_t, cose_status_t, cose_trust_policy_builder_t, with_catch_unwind,
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
        // SAFETY: ptr is within the bounds of the null-terminated array; we break on null sentinel.
        let s = unsafe { *ptr };
        if s.is_null() {
            break;
        }
        // SAFETY: s was verified non-null; caller guarantees it points to a null-terminated C string.
        if let Ok(cstr) = unsafe { CStr::from_ptr(s).to_str() } {
            result.push(cstr.to_string());
        }
        // SAFETY: advancing within the null-terminated array; the loop breaks before overrun.
        ptr = unsafe { ptr.add(1) };
    }
    result
}

/// Adds the Azure Key Vault trust pack with default options.
#[no_mangle]
pub extern "C" fn cose_sign1_validator_builder_with_akv_pack(
    builder: *mut cose_sign1_validator_builder_t,
) -> cose_status_t {
    with_catch_unwind(|| {
        // SAFETY: pointer is validated non-null by ok_or_else above.
        let builder = unsafe { builder.as_mut() }
            .ok_or_else(|| anyhow::anyhow!("builder must not be null"))?;
        builder.packs.push(Arc::new(AzureKeyVaultTrustPack::new(
            AzureKeyVaultTrustOptions::default(),
        )));
        Ok(cose_status_t::COSE_OK)
    })
}

/// Adds the Azure Key Vault trust pack with custom options (allowed patterns, etc.).
#[no_mangle]
pub extern "C" fn cose_sign1_validator_builder_with_akv_pack_ex(
    builder: *mut cose_sign1_validator_builder_t,
    options: *const cose_akv_trust_options_t,
) -> cose_status_t {
    with_catch_unwind(|| {
        // SAFETY: pointer is validated non-null by ok_or_else above.
        let builder = unsafe { builder.as_mut() }
            .ok_or_else(|| anyhow::anyhow!("builder must not be null"))?;

        let opts = if options.is_null() {
            AzureKeyVaultTrustOptions::default()
        } else {
            // SAFETY: options was checked non-null on the preceding line.
            let opts_ref = unsafe { &*options };
            // SAFETY: string_array_to_vec handles null pointers internally.
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

        builder
            .packs
            .push(Arc::new(AzureKeyVaultTrustPack::new(opts)));
        Ok(cose_status_t::COSE_OK)
    })
}

/// Trust-policy helper: require that the message `kid` looks like an Azure Key Vault key identifier.
#[no_mangle]
pub extern "C" fn cose_sign1_akv_trust_policy_builder_require_azure_key_vault_kid(
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
pub extern "C" fn cose_sign1_akv_trust_policy_builder_require_not_azure_key_vault_kid(
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
pub extern "C" fn cose_sign1_akv_trust_policy_builder_require_azure_key_vault_kid_allowed(
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
pub extern "C" fn cose_sign1_akv_trust_policy_builder_require_azure_key_vault_kid_not_allowed(
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

// ============================================================================
// AKV Key Client Creation and Signing Key Generation
// ============================================================================

/// Opaque handle for AkvKeyClient.
#[repr(C)]
pub struct AkvKeyClientHandle {
    _private: [u8; 0],
}

/// Helper to convert null-terminated C string to Rust string.
unsafe fn c_str_to_string(ptr: *const c_char) -> Result<String, anyhow::Error> {
    if ptr.is_null() {
        return Err(anyhow::anyhow!("string parameter must not be null"));
    }
    // SAFETY: ptr was checked non-null above; caller guarantees it points to a null-terminated C string.
    unsafe { CStr::from_ptr(ptr) }
        .to_str()
        .map(|s| s.to_string())
        .map_err(|e| anyhow::anyhow!("invalid UTF-8: {}", e))
}

/// Helper to convert optional null-terminated C string to Rust Option<String>.
unsafe fn c_str_to_option_string(ptr: *const c_char) -> Result<Option<String>, anyhow::Error> {
    if ptr.is_null() {
        return Ok(None);
    }
    // SAFETY: c_str_to_string validates null and UTF-8 internally.
    Ok(Some(unsafe { c_str_to_string(ptr) }?))
}

/// Create an AKV key client using DeveloperToolsCredential (for local dev).
/// vault_url: null-terminated UTF-8 (e.g. "https://myvault.vault.azure.net")
/// key_name: null-terminated UTF-8
/// key_version: null-terminated UTF-8, or null for latest
#[no_mangle]
#[cfg_attr(coverage_nightly, coverage(off))]
pub extern "C" fn cose_akv_key_client_new_dev(
    vault_url: *const c_char,
    key_name: *const c_char,
    key_version: *const c_char,
    out_client: *mut *mut AkvKeyClientHandle,
) -> cose_status_t {
    with_catch_unwind(|| {
        if out_client.is_null() {
            return Err(anyhow::anyhow!("out_client must not be null"));
        }

        // SAFETY: out pointer was validated non-null above.
        unsafe { *out_client = std::ptr::null_mut() };

        // SAFETY: c_str_to_string validates null and UTF-8 internally.
        let vault_url_str = unsafe { c_str_to_string(vault_url) }?;
        // SAFETY: c_str_to_string validates null and UTF-8 internally.
        let key_name_str = unsafe { c_str_to_string(key_name) }?;
        // SAFETY: c_str_to_option_string handles null (returns None) and validates UTF-8.
        let key_version_opt = unsafe { c_str_to_option_string(key_version) }?;

        let client =
            AkvKeyClient::new_dev(&vault_url_str, &key_name_str, key_version_opt.as_deref())?;

        let boxed = Box::new(client);
        // SAFETY: out pointer was validated non-null; Box::into_raw produces a valid aligned pointer.
        unsafe { *out_client = Box::into_raw(boxed) as *mut AkvKeyClientHandle };

        Ok(cose_status_t::COSE_OK)
    })
}

/// Create an AKV key client using ClientSecretCredential.
#[no_mangle]
#[cfg_attr(coverage_nightly, coverage(off))]
pub extern "C" fn cose_akv_key_client_new_client_secret(
    vault_url: *const c_char,
    key_name: *const c_char,
    key_version: *const c_char,
    tenant_id: *const c_char,
    client_id: *const c_char,
    client_secret: *const c_char,
    out_client: *mut *mut AkvKeyClientHandle,
) -> cose_status_t {
    with_catch_unwind(|| {
        if out_client.is_null() {
            return Err(anyhow::anyhow!("out_client must not be null"));
        }

        // SAFETY: out pointer was validated non-null above.
        unsafe { *out_client = std::ptr::null_mut() };

        // SAFETY: c_str_to_string validates null and UTF-8 internally.
        let vault_url_str = unsafe { c_str_to_string(vault_url) }?;
        // SAFETY: c_str_to_string validates null and UTF-8 internally.
        let key_name_str = unsafe { c_str_to_string(key_name) }?;
        // SAFETY: c_str_to_option_string handles null (returns None) and validates UTF-8.
        let key_version_opt = unsafe { c_str_to_option_string(key_version) }?;
        // SAFETY: c_str_to_string validates null and UTF-8 internally.
        let tenant_id_str = unsafe { c_str_to_string(tenant_id) }?;
        // SAFETY: c_str_to_string validates null and UTF-8 internally.
        let client_id_str = unsafe { c_str_to_string(client_id) }?;
        // SAFETY: c_str_to_string validates null and UTF-8 internally.
        let client_secret_str = unsafe { c_str_to_string(client_secret) }?;

        let credential: Arc<dyn azure_core::credentials::TokenCredential> =
            azure_identity::ClientSecretCredential::new(
                &tenant_id_str,
                client_id_str,
                azure_core::credentials::Secret::new(client_secret_str),
                None,
            )?;

        let client = AkvKeyClient::new(
            &vault_url_str,
            &key_name_str,
            key_version_opt.as_deref(),
            credential,
        )?;

        let boxed = Box::new(client);
        // SAFETY: out pointer was validated non-null; Box::into_raw produces a valid aligned pointer.
        unsafe { *out_client = Box::into_raw(boxed) as *mut AkvKeyClientHandle };

        Ok(cose_status_t::COSE_OK)
    })
}

/// Free an AKV key client.
#[no_mangle]
pub extern "C" fn cose_akv_key_client_free(client: *mut AkvKeyClientHandle) {
    if client.is_null() {
        return;
    }
    // SAFETY: ptr was created by Box::into_raw in the corresponding _new function
    // and must not have been freed previously. Caller must not use the handle after this call.
    unsafe {
        drop(Box::from_raw(client as *mut AkvKeyClient));
    }
}

/// Create a signing key handle from an AKV key client.
/// The returned key can be used with the signing FFI (cosesign1_impl_signing_service_create etc).
/// Note: This consumes the AKV client handle - the client is no longer valid after this call.
#[no_mangle]
#[cfg_attr(coverage_nightly, coverage(off))]
pub extern "C" fn cose_sign1_akv_create_signing_key(
    akv_client: *mut AkvKeyClientHandle,
    out_key: *mut *mut cose_sign1_signing_ffi::CoseKeyHandle,
) -> cose_status_t {
    with_catch_unwind(|| {
        if out_key.is_null() {
            return Err(anyhow::anyhow!("out_key must not be null"));
        }

        // SAFETY: out pointer was validated non-null above.
        unsafe { *out_key = std::ptr::null_mut() };

        if akv_client.is_null() {
            return Err(anyhow::anyhow!("akv_client must not be null"));
        }

        // SAFETY: ptr was created by Box::into_raw in the corresponding _new function
        // and must not have been freed previously. Caller must not use the handle after this call.
        let client = unsafe { Box::from_raw(akv_client as *mut AkvKeyClient) };

        let signing_key = AzureKeyVaultSigningKey::new(client)?;

        let key_inner = KeyInner {
            key: Arc::new(signing_key),
        };

        let boxed = Box::new(key_inner);
        // SAFETY: out pointer was validated non-null; Box::into_raw produces a valid aligned pointer.
        unsafe { *out_key = Box::into_raw(boxed) as *mut cose_sign1_signing_ffi::CoseKeyHandle };

        Ok(cose_status_t::COSE_OK)
    })
}

// ============================================================================
// AKV Signing Service FFI
// ============================================================================

/// Opaque handle for AKV signing service.
#[allow(dead_code)]
pub struct AkvSigningServiceHandle(
    cose_sign1_azure_key_vault::signing::AzureKeyVaultSigningService,
);

/// Create an AKV signing service from a key client.
///
/// # Safety
/// - `client` must be a valid AkvKeyClientHandle (created by `cose_akv_key_client_new_*`)
/// - `out` must be valid for writes
/// - The `client` handle is consumed by this call and must not be used afterward
#[no_mangle]
#[cfg_attr(coverage_nightly, coverage(off))]
pub extern "C" fn cose_sign1_akv_create_signing_service(
    client: *mut AkvKeyClientHandle,
    out: *mut *mut AkvSigningServiceHandle,
) -> cose_status_t {
    with_catch_unwind(|| {
        if out.is_null() {
            anyhow::bail!("out must not be null");
        }

        // SAFETY: out pointer was validated non-null above.
        unsafe { *out = std::ptr::null_mut() };

        if client.is_null() {
            anyhow::bail!("client must not be null");
        }

        // SAFETY: ptr was created by Box::into_raw in the corresponding _new function
        // and must not have been freed previously. Caller must not use the handle after this call.
        let akv_client = unsafe { Box::from_raw(client as *mut AkvKeyClient) };

        // Box the client as a KeyVaultCryptoClient
        let crypto_client: Box<dyn KeyVaultCryptoClient> = Box::new(*akv_client);

        // Create the signing service
        let mut service = AzureKeyVaultSigningService::new(crypto_client)?;

        // Initialize the service
        service.initialize()?;

        // SAFETY: out pointer was validated non-null; Box::into_raw produces a valid aligned pointer.
        unsafe { *out = Box::into_raw(Box::new(AkvSigningServiceHandle(service))) };
        Ok(cose_status_t::COSE_OK)
    })
}

/// Free an AKV signing service handle.
#[no_mangle]
pub extern "C" fn cose_sign1_akv_signing_service_free(handle: *mut AkvSigningServiceHandle) {
    if !handle.is_null() {
        // SAFETY: ptr was created by Box::into_raw in the corresponding _new function
        // and must not have been freed previously. Caller must not use the handle after this call.
        unsafe { drop(Box::from_raw(handle)) };
    }
}
