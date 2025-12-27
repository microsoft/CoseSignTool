// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use std::collections::BTreeMap;

// Force-link the crate so its `inventory::submit!` registrations are included.
use cosesign1_x509 as _;

use cosesign1_abstractions::{
    resolve_signing_key, CoseHeaderMap, HeaderKey, HeaderValue, ParsedCoseSign1,
};

#[test]
fn x5c_provider_accepts_single_cert_encoded_as_bstr() {
    // Some producers encode single-certificate `x5c` as a CBOR bstr (not an array).
    // The provider should accept this and treat it as a 1-element chain.
    let cert_der = vec![0x30, 0x03, 0x02, 0x01, 0x00]; // Minimal-ish DER-ish bytes; provider doesn't parse here.

    let mut unprotected = BTreeMap::<HeaderKey, HeaderValue>::new();
    unprotected.insert(HeaderKey::Int(33), HeaderValue::Bytes(cert_der.clone()));

    let parsed = ParsedCoseSign1 {
        protected_headers: CoseHeaderMap::new_protected(vec![], BTreeMap::new()),
        unprotected_headers: CoseHeaderMap::new_unprotected(unprotected),
        payload: None,
        signature: vec![],
    };

    let resolved = resolve_signing_key(&parsed).expect("provider should resolve x5c signing key");
    assert_eq!(resolved.provider_name, "x5c");
    assert_eq!(resolved.public_key_bytes, cert_der);

    // Ensure the provider also attached the chain material.
    let material = resolved.material.expect("x5c provider should attach cert chain");
    let chain = material
        .downcast_ref::<Vec<Vec<u8>>>()
        .expect("x5c provider material should be Vec<Vec<u8>>");
    assert_eq!(chain.as_slice(), &[resolved.public_key_bytes.clone()]);
}
