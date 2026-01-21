# Rust workspace + FFI crates

## What lives where

- `native/rust/` is a Cargo workspace.
- The “core” implementation crates are the source of truth.
- The `*_ffi*` crates build the C ABI boundary and are what native code links to.

## Key crates (conceptual)

- Base FFI crate: `cose_sign1_validation_ffi`
- Optional FFI crates (pinned behind vcpkg features):
  - `cose_sign1_validation_ffi_certificates`
  - `cose_sign1_validation_ffi_mst`
  - `cose_sign1_validation_ffi_akv`
  - `cose_sign1_validation_ffi_trust`

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
