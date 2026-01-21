# Native development (Rust-first, C/C++ projections via vcpkg)

This folder is the entry point for native developers.

## What you get

- A Rust implementation of COSE_Sign1 validation (the source of truth)
- C and C++ projections (headers + CMake targets) backed by Rust FFI static libraries
- A single vcpkg port (`cosesign1-validation-native`) that builds the Rust FFI and installs the C/C++ projections

## Start here

1) If you want to *consume* the library in a native app/library, start with:
- [vcpkg + CMake consumption](03-vcpkg.md)

2) If you want to *develop* the library in this repo (modify Rust / projections), start with:
- [Architecture + repo layout](01-overview.md)
- [Rust workspace + FFI crates](02-rust-ffi.md)

3) If you want to use the projections directly:
- [C projection guide](04-c-projection.md)
- [C++ projection guide](05-cpp-projection.md)

4) For quality / safety workflows:
- [Testing, ASAN, and coverage](06-testing-coverage-asan.md)

5) If something goes sideways:
- [Troubleshooting](07-troubleshooting.md)
