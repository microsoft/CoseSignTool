//! Trust policy authoring FFI bindings.
//!
//! This crate exposes the trust policy builder API (rules, predicates, plan compilation) to C/C++ consumers.
//!
//! Status: Placeholder. Policy authoring FFI will be designed once validation FFI is stable.

#![deny(unsafe_op_in_unsafe_fn)]

use cose_sign1_validation_ffi::{cose_status_t, with_catch_unwind};

/// Placeholder: create a new trust policy builder.
#[no_mangle]
pub extern "C" fn cose_trust_policy_builder_new(
    _out: *mut *mut std::ffi::c_void,
) -> cose_status_t {
    with_catch_unwind(|| {
        // TODO: implement once we define the trust policy builder ABI
        anyhow::bail!("Trust policy authoring FFI not yet implemented");
    })
}

#[cfg(test)]
mod tests {
    #[test]
    fn trust_ffi_placeholder() {
        assert_eq!(2 + 2, 4);
    }
}
