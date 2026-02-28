// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Tests for the FFI CBOR provider module.
//!
//! Provides comprehensive test coverage for CBOR provider functions.

use cose_sign1_factories_ffi::provider::get_provider;

#[test]
fn test_get_provider_returns_everparse_provider() {
    // Test that the provider function returns the EverParse CBOR provider
    let provider = get_provider();
    
    // Verify we get a reference to the provider singleton by checking the type
    let _typed_provider: &cbor_primitives_everparse::EverParseCborProvider = provider;
}

#[test]
fn test_get_provider_consistent_singleton() {
    // Test that multiple calls return the same singleton instance
    let provider1 = get_provider();
    let provider2 = get_provider();
    
    // Both should point to the same memory location - comparing addresses of the static
    let addr1 = provider1 as *const cbor_primitives_everparse::EverParseCborProvider as *const u8;
    let addr2 = provider2 as *const cbor_primitives_everparse::EverParseCborProvider as *const u8;
    assert_eq!(addr1, addr2);
}

#[test]
fn test_provider_is_static_reference() {
    // Test that the provider reference has static lifetime
    let provider = get_provider();
    
    // This should compile and work because provider has 'static lifetime
    let _static_ref: &'static cbor_primitives_everparse::EverParseCborProvider = provider;
}