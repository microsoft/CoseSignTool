# cbor_primitives_everparse

EverParse-backed implementation of the `cbor_primitives` traits.

Uses [cborrs](https://github.com/project-everest/everparse) -- a formally
verified CBOR parser recommended by Microsoft Research (MSR).

## Features

- Deterministic CBOR encoding (RFC 8949 Core Deterministic)
- Formally verified parsing (EverParse/Pulse)
- `CborProvider`, `CborEncoder`, `CborDecoder`, and `DynCborProvider` implementations

## Limitations

- **No floating-point support**: The verified parser does not handle CBOR floats.
  This is intentional -- security-critical CBOR payloads should not contain floats.

## Usage

```rust
use cbor_primitives::CborProvider;
use cbor_primitives_everparse::EverParseCborProvider;

let provider = EverParseCborProvider::default();
let mut encoder = provider.encoder();
encoder.encode_map(1).unwrap();
encoder.encode_i64(1).unwrap();
encoder.encode_i64(-7).unwrap();
let bytes = encoder.into_bytes();

let mut decoder = provider.decoder(&bytes);
// ...
```

## FFI

This crate is used internally by all FFI crates via compile-time feature
selection. See [docs/cbor-providers.md](../docs/cbor-providers.md).
