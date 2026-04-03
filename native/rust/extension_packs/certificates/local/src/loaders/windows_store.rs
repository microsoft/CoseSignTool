// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Windows certificate store loading.
//!
//! Uses a thin [`CertStoreProvider`] trait to abstract the Win32 CryptoAPI,
//! so that all business logic (thumbprint normalization, store selection,
//! result mapping) can be unit tested with a mock provider.
//!
//! ## Architecture
//!
//! ```text
//! ┌──────────────────────────────────────────────┐
//! │  load_from_store_by_thumbprint()             │  ← public API
//! │  load_from_provider()                        │  ← testable core
//! │    normalize_thumbprint()                    │
//! │    hex_decode()                              │
//! │    provider.find_by_sha1_hash()              │  ← trait call
//! │    map StoreCertificate → Certificate        │
//! ├──────────────────────────────────────────────┤
//! │  CertStoreProvider trait                     │  ← seam
//! ├──────────────────────────────────────────────┤
//! │  win32::Win32CertStoreProvider               │  ← thin FFI (integration test only)
//! │    CertOpenStore / CertFindCertificateInStore│
//! └──────────────────────────────────────────────┘
//! ```
//!
//! Maps V2 `WindowsCertificateStoreCertificateSource`.

use crate::certificate::Certificate;
use crate::error::CertLocalError;

// ============================================================================
// Public types
// ============================================================================

/// Certificate store location (matches .NET `StoreLocation`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StoreLocation {
    /// HKEY_CURRENT_USER certificate store.
    CurrentUser,
    /// HKEY_LOCAL_MACHINE certificate store.
    LocalMachine,
}

/// Certificate store name (matches .NET `StoreName`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StoreName {
    /// "MY" — Personal certificates.
    My,
    /// "ROOT" — Trusted Root Certification Authorities.
    Root,
    /// "CA" — Intermediate Certification Authorities.
    CertificateAuthority,
}

impl StoreName {
    /// Win32 store name string.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::My => "MY",
            Self::Root => "ROOT",
            Self::CertificateAuthority => "CA",
        }
    }
}

/// Raw certificate data returned by the store provider.
#[derive(Debug, Clone)]
pub struct StoreCertificate {
    /// DER-encoded certificate bytes.
    pub cert_der: Vec<u8>,
    /// DER-encoded PKCS#8 private key, if exportable.
    pub private_key_der: Option<Vec<u8>>,
}

// ============================================================================
// Thin provider trait — the only seam that touches Win32 / Crypt32.dll
// ============================================================================

/// Abstracts the Windows certificate store operations.
///
/// The real implementation (`Win32CertStoreProvider`) calls Crypt32.dll.
/// Unit tests inject a mock that returns canned data.
pub trait CertStoreProvider: Send + Sync {
    /// Find a certificate by its SHA-1 hash bytes.
    ///
    /// # Arguments
    /// * `thumb_bytes` — 20-byte SHA-1 hash
    /// * `store_name` — e.g. `StoreName::My`
    /// * `store_location` — e.g. `StoreLocation::CurrentUser`
    ///
    /// Returns the DER cert + optional private key, or an error.
    fn find_by_sha1_hash(
        &self,
        thumb_bytes: &[u8],
        store_name: StoreName,
        store_location: StoreLocation,
    ) -> Result<StoreCertificate, CertLocalError>;
}

// ============================================================================
// Business logic — fully unit-testable via injected provider
// ============================================================================

/// Normalize a thumbprint string: strip non-hex chars, uppercase, validate length.
pub fn normalize_thumbprint(thumbprint: &str) -> Result<String, CertLocalError> {
    let normalized: String = thumbprint
        .chars()
        .filter(|c| c.is_ascii_hexdigit())
        .collect::<String>()
        .to_uppercase();

    if normalized.len() != 40 {
        return Err(CertLocalError::LoadFailed(format!(
            "Invalid SHA-1 thumbprint length: expected 40 hex chars, got {} (from input '{}')",
            normalized.len(),
            thumbprint,
        )));
    }

    Ok(normalized)
}

/// Decode a hex string to bytes.
pub fn hex_decode(hex: &str) -> Result<Vec<u8>, CertLocalError> {
    if !hex.len().is_multiple_of(2) {
        return Err(CertLocalError::LoadFailed(
            "Hex string must have even length".into(),
        ));
    }
    (0..hex.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&hex[i..i + 2], 16)
                .map_err(|e| CertLocalError::LoadFailed(format!("Invalid hex: {}", e)))
        })
        .collect()
}

/// Load a certificate from a store provider by thumbprint.
///
/// This is the **testable core**: it normalizes the thumbprint, decodes hex,
/// calls the injected provider, and maps the result to a `Certificate`.
pub fn load_from_provider(
    provider: &dyn CertStoreProvider,
    thumbprint: &str,
    store_name: StoreName,
    store_location: StoreLocation,
) -> Result<Certificate, CertLocalError> {
    let normalized = normalize_thumbprint(thumbprint)?;
    let thumb_bytes = hex_decode(&normalized)?;

    let store_cert = provider.find_by_sha1_hash(&thumb_bytes, store_name, store_location)?;

    let mut cert = Certificate::new(store_cert.cert_der);
    cert.private_key_der = store_cert.private_key_der;
    Ok(cert)
}

// ============================================================================
// Public convenience functions (use the real Win32 provider)
// ============================================================================

/// Loads a certificate from the Windows certificate store by SHA-1 thumbprint.
///
/// # Arguments
///
/// * `thumbprint` - SHA-1 thumbprint as a hex string (spaces/colons/dashes stripped)
/// * `store_name` - Which store to search (My, Root, CA)
/// * `store_location` - CurrentUser or LocalMachine
#[cfg(all(target_os = "windows", feature = "windows-store"))]
pub fn load_from_store_by_thumbprint(
    thumbprint: &str,
    store_name: StoreName,
    store_location: StoreLocation,
) -> Result<Certificate, CertLocalError> {
    let provider = win32::Win32CertStoreProvider;
    load_from_provider(&provider, thumbprint, store_name, store_location)
}

/// Loads a certificate by thumbprint with default store (My / CurrentUser).
#[cfg(all(target_os = "windows", feature = "windows-store"))]
pub fn load_from_store_by_thumbprint_default(
    thumbprint: &str,
) -> Result<Certificate, CertLocalError> {
    load_from_store_by_thumbprint(thumbprint, StoreName::My, StoreLocation::CurrentUser)
}

// ============================================================================
// Non-Windows stubs
// ============================================================================

#[cfg(not(all(target_os = "windows", feature = "windows-store")))]
pub fn load_from_store_by_thumbprint(
    _thumbprint: &str,
    _store_name: StoreName,
    _store_location: StoreLocation,
) -> Result<Certificate, CertLocalError> {
    Err(CertLocalError::LoadFailed(
        "Windows certificate store support requires Windows OS + feature=\"windows-store\"".into(),
    ))
}

#[cfg(not(all(target_os = "windows", feature = "windows-store")))]
pub fn load_from_store_by_thumbprint_default(
    _thumbprint: &str,
) -> Result<Certificate, CertLocalError> {
    Err(CertLocalError::LoadFailed(
        "Windows certificate store support requires Windows OS + feature=\"windows-store\"".into(),
    ))
}

// ============================================================================
// Win32 provider implementation — thin FFI layer (integration-test only)
// ============================================================================

#[cfg(all(target_os = "windows", feature = "windows-store"))]
pub mod win32 {
    use super::*;
    use std::ffi::c_void;
    use std::ptr;

    // Win32 constants
    const CERT_SYSTEM_STORE_CURRENT_USER: u32 = 1 << 16;
    const CERT_SYSTEM_STORE_LOCAL_MACHINE: u32 = 2 << 16;
    const CERT_STORE_READONLY_FLAG: u32 = 0x00008000;
    const CERT_STORE_PROV_SYSTEM_W: *const i8 = 10 as *const i8;
    const X509_ASN_ENCODING: u32 = 0x00000001;
    const PKCS_7_ASN_ENCODING: u32 = 0x00010000;
    const CERT_FIND_SHA1_HASH: u32 = 0x00010000;

    #[repr(C)]
    struct CERT_CONTEXT {
        dw_cert_encoding_type: u32,
        pb_cert_encoded: *const u8,
        cb_cert_encoded: u32,
        p_cert_info: *const c_void,
        h_cert_store: *const c_void,
    }

    #[repr(C)]
    struct CRYPT_HASH_BLOB {
        cb_data: u32,
        pb_data: *const u8,
    }

    #[link(name = "crypt32")]
    extern "system" {
        fn CertOpenStore(
            lp_sz_store_provider: *const i8,
            dw_encoding_type: u32,
            h_crypt_prov: usize,
            dw_flags: u32,
            pv_para: *const c_void,
        ) -> *mut c_void;

        fn CertCloseStore(h_cert_store: *mut c_void, dw_flags: u32) -> i32;

        fn CertFindCertificateInStore(
            h_cert_store: *mut c_void,
            dw_cert_encoding_type: u32,
            dw_find_flags: u32,
            dw_find_type: u32,
            pv_find_para: *const c_void,
            p_prev_cert_context: *const CERT_CONTEXT,
        ) -> *const CERT_CONTEXT;

        fn CertFreeCertificateContext(p_cert_context: *const CERT_CONTEXT) -> i32;
    }

    /// Real Win32 `CertStoreProvider` backed by Crypt32.dll.
    ///
    /// This is the **only** type that makes FFI calls. Everything above it
    /// is pure Rust business logic that can be unit-tested with a mock.
    pub struct Win32CertStoreProvider;

    impl CertStoreProvider for Win32CertStoreProvider {
        fn find_by_sha1_hash(
            &self,
            thumb_bytes: &[u8],
            store_name: StoreName,
            store_location: StoreLocation,
        ) -> Result<StoreCertificate, CertLocalError> {
            let location_flag: u32 = match store_location {
                StoreLocation::CurrentUser => CERT_SYSTEM_STORE_CURRENT_USER,
                StoreLocation::LocalMachine => CERT_SYSTEM_STORE_LOCAL_MACHINE,
            };

            let store_name_str = store_name.as_str();
            let store_name_wide: Vec<u16> = store_name_str
                .encode_utf16()
                .chain(std::iter::once(0))
                .collect();

            // Open store
            let store_handle = unsafe {
                CertOpenStore(
                    CERT_STORE_PROV_SYSTEM_W,
                    0,
                    0,
                    location_flag | CERT_STORE_READONLY_FLAG,
                    store_name_wide.as_ptr() as *const c_void,
                )
            };

            if store_handle.is_null() {
                return Err(CertLocalError::LoadFailed(format!(
                    "Failed to open certificate store: {:?}\\{}",
                    store_location, store_name_str
                )));
            }

            // Search by SHA-1 hash
            let hash_blob = CRYPT_HASH_BLOB {
                cb_data: thumb_bytes.len() as u32,
                pb_data: thumb_bytes.as_ptr(),
            };

            let cert_context = unsafe {
                CertFindCertificateInStore(
                    store_handle,
                    X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                    0,
                    CERT_FIND_SHA1_HASH,
                    &hash_blob as *const CRYPT_HASH_BLOB as *const c_void,
                    ptr::null(),
                )
            };

            if cert_context.is_null() {
                unsafe { CertCloseStore(store_handle, 0) };
                return Err(CertLocalError::LoadFailed(format!(
                    "Certificate not found in {:?}\\{}",
                    store_location, store_name_str
                )));
            }

            // Extract DER
            let cert_der = unsafe {
                let ctx = &*cert_context;
                std::slice::from_raw_parts(ctx.pb_cert_encoded, ctx.cb_cert_encoded as usize)
                    .to_vec()
            };

            // Clean up
            unsafe {
                CertFreeCertificateContext(cert_context);
                CertCloseStore(store_handle, 0);
            };

            // Private key export requires NCrypt — TODO
            Ok(StoreCertificate {
                cert_der,
                private_key_der: None,
            })
        }
    }
}
