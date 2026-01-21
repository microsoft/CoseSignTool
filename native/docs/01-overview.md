# Overview: repo layout and mental model

## Mental model

- **Rust is the implementation**.
- **Native projections are thin**:
  - **C**: ABI-stable function surface + pack feature macros
  - **C++**: header-only RAII wrappers + fluent builders
- **Everything is shipped through one vcpkg port**:
  - The port builds the Rust FFI static libraries using `cargo`.
  - The port installs C/C++ headers.
  - The port provides CMake targets you link against.

## Repository layout (native)

- `native/rust/`
  - Rust workspace (implementation + FFI crates)
- `native/c/`
  - C projection headers + native tests + CMake build
- `native/c_pp/`
  - C++ projection headers + native tests + CMake build
- `native/vcpkg_ports/cosesign1-validation-native/`
  - Overlay port used to build/install everything via vcpkg

## Packs (optional features)

The native surface is modular: optional packs contribute additional validation facts and policy helpers.

Current packs:

- `certificates` (X.509)
- `mst` (Microsoft Secure Transparency)
- `akv` (Azure Key Vault)
- `trust` (trust-policy / trust-plan authoring)

On the C side these are exposed by compile definitions:

- `COSE_HAS_CERTIFICATES_PACK`
- `COSE_HAS_MST_PACK`
- `COSE_HAS_AKV_PACK`
- `COSE_HAS_TRUST_PACK`

When consuming via vcpkg+CMake, those definitions are applied automatically when the corresponding pack libs are present.

## How the vcpkg port works

The overlay port:

- builds selected Rust FFI crates in both `debug` and `release` profiles
- installs the resulting **static libraries** into the vcpkg installed tree
- installs the C headers (and optionally the C++ headers)
- provides a CMake config package named `cose_sign1_validation`

See [vcpkg consumption](03-vcpkg.md) for copy/paste usage.
