# cose_sign1_crypto_openssl

OpenSSL-based cryptographic provider for CoseSign1 using safe Rust bindings.

## Overview

This crate provides `CoseKey` implementations backed by OpenSSL's EVP API using the safe Rust `openssl` crate. It is an alternative to the legacy `cose_openssl` crate which uses unsafe FFI.

## Features

- ✅ **Safe Rust**: Uses high-level `openssl` crate bindings (not `openssl-sys`)
- ✅ **ECDSA**: P-256, P-384, P-521 (ES256, ES384, ES512)
- ✅ **RSA**: PKCS#1 v1.5 and PSS padding (RS256/384/512, PS256/384/512)
- ✅ **EdDSA**: Ed25519 signatures
- ⚙️ **PQC**: Optional ML-DSA support (feature-gated)

## Usage

```rust
use cose_sign1_crypto_openssl::{OpenSslCryptoProvider, EvpPrivateKey};
use cose_sign1_primitives::{CoseSign1Builder, CoseHeaderMap, ES256};
use openssl::ec::{EcKey, EcGroup};
use openssl::nid::Nid;

// Generate an EC P-256 key
let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)?;
let ec_key = EcKey::generate(&group)?;
let private_key = EvpPrivateKey::from_ec(ec_key)?;

// Create a signing key
let signing_key = OpenSslCryptoProvider::create_signing_key(
    private_key,
    ES256, // -7
    None,  // No key ID
);

// Sign a message
let mut protected = CoseHeaderMap::new();
protected.set_alg(ES256);

let message = CoseSign1Builder::new()
    .protected(protected)
    .sign(&signing_key, b"Hello, COSE!")?;
```

## Algorithm Support

| COSE Alg | Name | Description | Status |
|----------|------|-------------|--------|
| -7 | ES256 | ECDSA P-256 + SHA-256 | ✅ |
| -35 | ES384 | ECDSA P-384 + SHA-384 | ✅ |
| -36 | ES512 | ECDSA P-521 + SHA-512 | ✅ |
| -257 | RS256 | RSASSA-PKCS1-v1_5 + SHA-256 | ✅ |
| -258 | RS384 | RSASSA-PKCS1-v1_5 + SHA-384 | ✅ |
| -259 | RS512 | RSASSA-PKCS1-v1_5 + SHA-512 | ✅ |
| -37 | PS256 | RSASSA-PSS + SHA-256 | ✅ |
| -38 | PS384 | RSASSA-PSS + SHA-384 | ✅ |
| -39 | PS512 | RSASSA-PSS + SHA-512 | ✅ |
| -8 | EdDSA | Ed25519 | ✅ |

## Architecture

```
┌─────────────────────────────────────────┐
│   CoseKey Trait (cose_sign1_primitives) │
└─────────────────┬───────────────────────┘
                  │ implements
┌─────────────────▼────────────────────────┐
│  OpenSslSigningKey / VerificationKey     │
│  (cose_key_impl.rs)                      │
└─────────────────┬────────────────────────┘
                  │ delegates to
     ┌────────────┴────────────┐
     │                         │
┌────▼────────┐       ┌────────▼─────────┐
│ evp_signer  │       │  evp_verifier    │
│ (sign ops)  │       │  (verify ops)    │
└────┬────────┘       └────────┬─────────┘
     │                         │
     │       ┌─────────────────┘
     │       │
┌────▼───────▼──────┐
│  openssl crate    │
│  (safe Rust API)  │
└───────────────────┘
```

## Comparison with `cose_openssl`

| Aspect | `cose_sign1_crypto_openssl` | `cose_openssl` |
|--------|----------------------------|----------------|
| **Safety** | Safe Rust bindings | Unsafe `openssl-sys` FFI |
| **API Level** | High-level `openssl` crate | Low-level C API wrappers |
| **CBOR** | Uses `cbor_primitives` | Custom `cborrs-nondet` |
| **Maintenance** | Easier (safe abstractions) | Harder (unsafe code) |
| **Use Case** | New projects, general use | Backwards compat, low-level control |

**Recommendation**: Use `cose_sign1_crypto_openssl` for new projects. The `cose_openssl` crate is maintained for backwards compatibility only.

## ECDSA Signature Format

COSE requires ECDSA signatures in fixed-length (r || s) format, but OpenSSL produces DER-encoded signatures. This crate automatically handles the conversion via the `ecdsa_format` module.

## Dependencies

- `cose_sign1_primitives` - Core COSE types and traits
- `openssl` 0.10 - Safe Rust bindings to OpenSSL

## License

MIT License - Copyright (c) Microsoft Corporation.
