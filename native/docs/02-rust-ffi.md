# Rust workspace + FFI crates

## What lives where

- `native/rust/` is a Cargo workspace.
- The “core” implementation crates are the source of truth.
- The `*_ffi*` crates build the C ABI boundary and are what native code links to.

## Key crates (conceptual)

### Primitives + Signing FFI
- `cose_sign1_primitives_ffi` -- Parse, verify, header access (~25 exports)
- `cose_sign1_signing_ffi` -- Build and sign COSE_Sign1 messages (~22 exports)

### Validation FFI
- Base FFI crate: `cose_sign1_validation_ffi` (~12 exports)
- Per-pack FFI crates (pinned behind vcpkg features):
  - `cose_sign1_validation_ffi_certificates` (~34 exports)
  - `cose_sign1_validation_ffi_mst` (~17 exports)
  - `cose_sign1_validation_ffi_akv` (~6 exports)
  - `cose_sign1_validation_primitives_ffi` (~29 exports)

### CBOR Provider Selection

FFI crates select their CBOR provider at **compile time** via Cargo feature
flags.  Each FFI crate contains `src/provider.rs` with a feature-gated type
alias.  The default feature `cbor-everparse` selects EverParse (formally
verified by MSR).

To build with a different provider:
```powershell
cargo build --release -p cose_sign1_validation_ffi --no-default-features --features cbor-<name>
```

The C/C++ ABI is unchanged -- same headers, same function signatures.
See [cbor-providers.md](../rust/docs/cbor-providers.md) for the full guide.

## Build the Rust artifacts locally

From repo root:

```powershell
cd native/rust
cargo build --release --workspace
```

This produces libraries under:

- `native/rust/target/release/` (release)
- `native/rust/target/debug/` (debug)

## Why vcpkg is the recommended native entry point

You *can* build Rust first and then build `native/c` or `native/c_pp` directly, but the recommended consumption story is:

- use `vcpkg` to build/install the Rust FFI artifacts
- link to a single CMake package (`cose_sign1_validation`) and its targets

This makes consuming apps reproducible and avoids custom ad-hoc “copy the right libs” steps.

See [vcpkg consumption](03-vcpkg.md).
