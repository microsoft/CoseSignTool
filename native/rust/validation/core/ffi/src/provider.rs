// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Compile-time CBOR provider selection for FFI.
//!
//! The concrete [`CborProvider`] used by all FFI entry points is selected via
//! Cargo feature flags.  Exactly one `cbor-*` feature must be enabled.
//!
//! | Feature          | Provider                                       |
//! |------------------|------------------------------------------------|
//! | `cbor-everparse` | [`cbor_primitives_everparse::EverParseCborProvider`] |
//!
//! To add a new provider, create a `cbor_primitives_<name>` crate that
//! implements [`cbor_primitives::CborProvider`], add a corresponding Cargo
//! feature to this crate's `Cargo.toml`, and extend the `cfg` blocks below.

#[cfg(feature = "cbor-everparse")]
pub type FfiCborProvider = cbor_primitives_everparse::EverParseCborProvider;

// Guard: at least one provider must be selected.
#[cfg(not(feature = "cbor-everparse"))]
compile_error!(
    "No CBOR provider feature enabled for cose_sign1_validation_ffi. \
     Enable exactly one of: cbor-everparse"
);

/// Instantiate the compile-time-selected CBOR provider.
#[cfg_attr(coverage_nightly, coverage(off))]
pub fn ffi_cbor_provider() -> FfiCborProvider {
    FfiCborProvider::default()
}
