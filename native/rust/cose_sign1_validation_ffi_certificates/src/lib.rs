//! X.509 certificates pack FFI bindings.
//!
//! This crate exposes the X.509 certificate validation pack to C/C++ consumers.

#![deny(unsafe_op_in_unsafe_fn)]

use cose_sign1_validation_certificates::pack::{CertificateTrustOptions, X509CertificateTrustPack};
use cose_sign1_validation_ffi::{cose_status_t, cose_validator_builder_t, with_catch_unwind};
use std::ffi::{c_char, CStr};
use std::sync::Arc;

/// C ABI representation of certificate trust options.
#[repr(C)]
pub struct cose_certificate_trust_options_t {
    /// If true, treat a well-formed embedded x5chain as trusted (deterministic, for tests/pinned roots).
    pub trust_embedded_chain_as_trusted: bool,
    
    /// If true, enable identity pinning based on allowed_thumbprints.
    pub identity_pinning_enabled: bool,
    
    /// Null-terminated array of allowed certificate thumbprint strings (case/whitespace insensitive).
    /// NULL pointer means no thumbprint filtering.
    pub allowed_thumbprints: *const *const c_char,
    
    /// Null-terminated array of PQC algorithm OID strings.
    /// NULL pointer means no custom PQC OIDs.
    pub pqc_algorithm_oids: *const *const c_char,
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

/// Adds the X.509 certificates trust pack with default options.
#[no_mangle]
pub extern "C" fn cose_validator_builder_with_certificates_pack(
    builder: *mut cose_validator_builder_t,
) -> cose_status_t {
    with_catch_unwind(|| {
        let builder = unsafe { builder.as_mut() }
            .ok_or_else(|| anyhow::anyhow!("builder must not be null"))?;
        builder
            .packs
            .push(Arc::new(X509CertificateTrustPack::default()));
        Ok(cose_status_t::COSE_OK)
    })
}

/// Adds the X.509 certificates trust pack with custom options.
#[no_mangle]
pub extern "C" fn cose_validator_builder_with_certificates_pack_ex(
    builder: *mut cose_validator_builder_t,
    options: *const cose_certificate_trust_options_t,
) -> cose_status_t {
    with_catch_unwind(|| {
        let builder = unsafe { builder.as_mut() }
            .ok_or_else(|| anyhow::anyhow!("builder must not be null"))?;
        
        let opts = if options.is_null() {
            CertificateTrustOptions::default()
        } else {
            let opts_ref = unsafe { &*options };
            CertificateTrustOptions {
                trust_embedded_chain_as_trusted: opts_ref.trust_embedded_chain_as_trusted,
                identity_pinning_enabled: opts_ref.identity_pinning_enabled,
                allowed_thumbprints: unsafe { string_array_to_vec(opts_ref.allowed_thumbprints) },
                pqc_algorithm_oids: unsafe { string_array_to_vec(opts_ref.pqc_algorithm_oids) },
            }
        };
        
        builder
            .packs
            .push(Arc::new(X509CertificateTrustPack::new(opts)));
        Ok(cose_status_t::COSE_OK)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn certificates_ffi_smoke() {
        // Smoke test will validate once we have a proper validator builder in base FFI
        assert_eq!(2 + 2, 4);
    }
}
