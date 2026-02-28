// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Compile-time CBOR provider selection.
//!
//! The concrete CBOR provider is selected at build time via Cargo features.
//! A global singleton instance is available via [`cbor_provider()`] — no need
//! to pass a provider through method signatures.
//!
//! # Usage
//!
//! ```ignore
//! use cose_primitives::provider::cbor_provider;
//!
//! let provider = cbor_provider();
//! let encoder = provider.encoder();
//! ```

use std::sync::OnceLock;

use cbor_primitives::CborProvider;

#[cfg(feature = "cbor-everparse")]
mod selected {
    pub type Provider = cbor_primitives_everparse::EverParseCborProvider;
}

#[cfg(not(feature = "cbor-everparse"))]
compile_error!(
    "No CBOR provider feature enabled for cose_primitives. \
     Enable exactly one of: cbor-everparse"
);

/// The CBOR provider type selected at compile time.
pub type CborProviderImpl = selected::Provider;

/// The concrete encoder type for the selected provider.
pub type Encoder = <CborProviderImpl as CborProvider>::Encoder;

/// The concrete decoder type for the selected provider.
pub type Decoder<'a> = <CborProviderImpl as CborProvider>::Decoder<'a>;

static PROVIDER: OnceLock<CborProviderImpl> = OnceLock::new();

/// Returns a reference to the global CBOR provider singleton.
pub fn cbor_provider() -> &'static CborProviderImpl {
    PROVIDER.get_or_init(CborProviderImpl::default)
}

/// Creates a new encoder from the global provider.
pub fn encoder() -> Encoder {
    cbor_provider().encoder()
}

/// Creates a new decoder for the given data.
pub fn decoder(data: &[u8]) -> Decoder<'_> {
    cbor_provider().decoder(data)
}
