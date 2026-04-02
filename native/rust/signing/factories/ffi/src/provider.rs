// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! CBOR provider singleton for FFI layer.
//!
//! Provides a global CBOR encoder/decoder provider that is configured at compile time.

/// Gets the CBOR provider instance.
///
/// Returns the EverParse CBOR provider.
#[cfg(feature = "cbor-everparse")]
pub fn get_provider() -> &'static cbor_primitives_everparse::EverParseCborProvider {
    &cbor_primitives_everparse::EverParseCborProvider
}

#[cfg(not(feature = "cbor-everparse"))]
compile_error!("No CBOR provider selected. Enable 'cbor-everparse' feature.");
