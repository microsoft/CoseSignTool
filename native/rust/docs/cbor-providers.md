# CBOR Provider Selection Guide

The COSE Sign1 library is decoupled from any specific CBOR implementation via
the `cbor_primitives` trait crate.  Every layer — Rust libraries, FFI crates,
and C/C++ projections — can use a different provider without touching
application code.

## Available Providers

| Crate | Provider type | Feature flag | Notes |
|-------|--------------|--------------|-------|
| `cbor_primitives_everparse` | `EverParseCborProvider` | `cbor-everparse` (default) | Formally verified by MSR.  No float support. |

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│  cbor_primitives              (trait crate, zero deps)      │
│   CborProvider / CborEncoder / CborDecoder / DynCborProvider│
└──────────────────────────┬──────────────────────────────────┘
                           │ implements
┌──────────────────────────▼──────────────────────────────────┐
│  cbor_primitives_everparse    (EverParse/cborrs)            │
│   EverParseCborProvider                                     │
└──────────────────────────┬──────────────────────────────────┘
                           │ used by
┌──────────────────────────▼──────────────────────────────────┐
│  Rust libraries                                             │
│   cose_sign1_primitives   (generic <P: CborProvider>)       │
│   cose_sign1_validation   (DynCborProvider internally)      │
│   packs: certificates, MST, AKV                             │
└──────────────────────────┬──────────────────────────────────┘
                           │ compile-time selection
┌──────────────────────────▼──────────────────────────────────┐
│  FFI crates (provider.rs — feature-gated type alias)        │
│   cose_sign1_primitives_ffi                                 │
│   cose_sign1_signing_ffi                                    │
│   cose_sign1_validation_ffi  → pack FFI crates              │
└──────────────────────────┬──────────────────────────────────┘
                           │ links
┌──────────────────────────▼──────────────────────────────────┐
│  C / C++ projections                                        │
│   Same headers, same API — provider is baked into the .lib  │
└─────────────────────────────────────────────────────────────┘
```

## Rust Library Code (Generic)

Library functions accept a generic `CborProvider` or use `DynCborProvider`:

```rust
use cbor_primitives::CborProvider;
use cose_sign1_primitives::CoseSign1Message;

// Static dispatch (used in cose_sign1_primitives)
pub fn parse<P: CborProvider>(provider: P, data: &[u8]) -> Result<CoseSign1Message, Error> {
    CoseSign1Message::parse(provider, data)
}

// Dynamic dispatch (used inside the validation pipeline)
pub fn validate(provider: &dyn DynCborProvider, data: &[u8]) -> Result<(), Error> { ... }
```

## Rust Application Code

Applications choose the concrete provider at the call site:

```rust
use cbor_primitives_everparse::EverParseCborProvider;
use cose_sign1_validation::fluent::*;

let validator = CoseSign1Validator::new(trust_packs);
let result = validator
    .validate_bytes(EverParseCborProvider, cose_bytes)
    .expect("validation");
```

## FFI Crates (Compile-Time Selection)

Each FFI crate has a `provider.rs` module that defines `FfiCborProvider` via a
Cargo feature flag:

```rust
// cose_sign1_*_ffi/src/provider.rs
#[cfg(feature = "cbor-everparse")]
pub type FfiCborProvider = cbor_primitives_everparse::EverParseCborProvider;

pub fn ffi_cbor_provider() -> FfiCborProvider {
    FfiCborProvider::default()
}
```

All FFI entry points call `ffi_cbor_provider()` rather than naming a concrete
type.  The default feature is `cbor-everparse`, so `cargo build` just works.

### Building with a different provider

```powershell
# Default (EverParse):
cargo build --release -p cose_sign1_validation_ffi

# Hypothetical future provider:
cargo build --release -p cose_sign1_validation_ffi --no-default-features --features cbor-<name>
```

The produced `.lib` / `.dll` / `.so` has **identical symbols and C ABI** — only
the backing CBOR implementation changes.  C/C++ headers and CMake targets
require zero modifications.

## Adding a New Provider

1. Create `cbor_primitives_<name>` implementing `CborProvider`, `CborEncoder`,
   `CborDecoder`, and `DynCborProvider`.
2. In each FFI crate's `Cargo.toml`, add:
   ```toml
   cbor_primitives_<name> = { path = "../cbor_primitives_<name>", optional = true }

   [features]
   cbor-<name> = ["dep:cbor_primitives_<name>"]
   ```
3. In each FFI crate's `src/provider.rs`, add:
   ```rust
   #[cfg(feature = "cbor-<name>")]
   pub type FfiCborProvider = cbor_primitives_<name>::<ProviderType>;
   ```
4. Rebuild the FFI libraries with `--features cbor-<name>`.
5. No C/C++ header changes needed.
