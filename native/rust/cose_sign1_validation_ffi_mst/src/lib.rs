//! Transparent MST pack FFI bindings.
//!
//! This crate exposes the Microsoft Secure Transparency (MST) receipt verification pack to C/C++ consumers.

#![deny(unsafe_op_in_unsafe_fn)]

use cose_sign1_validation_ffi::{cose_status_t, cose_validator_builder_t, with_catch_unwind};
use cose_sign1_validation_transparent_mst::pack::MstTrustPack;
use std::ffi::{c_char, CStr};
use std::sync::Arc;

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
pub extern "C" fn cose_validator_builder_with_mst_pack(
    builder: *mut cose_validator_builder_t,
) -> cose_status_t {
    with_catch_unwind(|| {
        let builder = unsafe { builder.as_mut() }
            .ok_or_else(|| anyhow::anyhow!("builder must not be null"))?;
        builder.packs.push(Arc::new(MstTrustPack::online()));
        Ok(cose_status_t::COSE_OK)
    })
}

/// Adds the MST trust pack with custom options (offline JWKS, etc.).
#[no_mangle]
pub extern "C" fn cose_validator_builder_with_mst_pack_ex(
    builder: *mut cose_validator_builder_t,
    options: *const cose_mst_trust_options_t,
) -> cose_status_t {
    with_catch_unwind(|| {
        let builder = unsafe { builder.as_mut() }
            .ok_or_else(|| anyhow::anyhow!("builder must not be null"))?;
        
        let pack = if options.is_null() {
            MstTrustPack::online()
        } else {
            let opts_ref = unsafe { &*options };
            let offline_jwks = if opts_ref.offline_jwks_json.is_null() {
                None
            } else {
                Some(unsafe { CStr::from_ptr(opts_ref.offline_jwks_json) }
                    .to_str()
                    .map_err(|_| anyhow::anyhow!("invalid UTF-8 in offline_jwks_json"))?
                    .to_string())
            };
            
            let api_version = if opts_ref.jwks_api_version.is_null() {
                None
            } else {
                Some(unsafe { CStr::from_ptr(opts_ref.jwks_api_version) }
                    .to_str()
                    .map_err(|_| anyhow::anyhow!("invalid UTF-8 in jwks_api_version"))?
                    .to_string())
            };
            
            MstTrustPack {
                allow_network: opts_ref.allow_network,
                offline_jwks_json: offline_jwks,
                jwks_api_version: api_version,
            }
        };
        
        builder.packs.push(Arc::new(pack));
        Ok(cose_status_t::COSE_OK)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mst_ffi_smoke() {
        assert_eq!(2 + 2, 4);
    }
}
