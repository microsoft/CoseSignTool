# Native development (Rust-first, C/C++ projections via vcpkg)

This folder is the entry point for native developers.

## Rust-first documentation

The Rust implementation is the **source of truth**. If you are trying to understand behavior, APIs,
or extension points, prefer the Rust docs first:

- Rust workspace docs: `native/rust/docs/README.md`
- Crate README surfaces under `native/rust/*/README.md`
- Runnable examples live under each crate’s `examples/` folder

This `native/docs/` folder focuses on how Rust is packaged and consumed from native code.

## What you get

- A Rust implementation of COSE_Sign1 validation (source of truth)
- C and C++ projections (headers + CMake targets) backed by Rust FFI libraries
- A single vcpkg port (`cosesign1-validation-native`) that builds the Rust FFI and installs the C/C++ projections

## Start here

### Consuming from C/C++ (recommended path)

If you want to consume this from a native app/library, start with:

- [vcpkg + CMake consumption](03-vcpkg.md)

Then jump to the projection that matches your integration:

- [C projection guide](04-c-projection.md)
- [C++ projection guide](05-cpp-projection.md)

Those guides include the expected include/link model and small end-to-end examples.

### Developing in this repo (Rust + projections)

If you want to modify the Rust validator and/or projections:

- [Architecture + repo layout](01-overview.md)
- [Rust workspace + FFI crates](02-rust-ffi.md)

### Quality & safety workflows

- [Testing, ASAN, and coverage](06-testing-coverage-asan.md)

### Troubleshooting

- [Troubleshooting](07-troubleshooting.md)
