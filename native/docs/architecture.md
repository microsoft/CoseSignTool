<!--
Copyright (c) Microsoft Corporation.
Licensed under the MIT License.
-->

# Native verifier architecture

The `native/` side of this repo is a **C ABI + C++ header-only wrappers** over the Rust verifier implementation.

It is designed so that:

- C/C++ callers can consume a stable, C-friendly API surface.
- C++ callers can use RAII wrappers (`<cosesign1/cosesign1.hpp>`) instead of manual allocation/free.
- The heavy lifting (COSE parsing + signature verification + X.509 + MST) stays implemented in Rust.

## Layers

- **Rust verifier crates** (authoritative implementation)
  - See `rust/` for the Rust workspace and `rust/docs/` for Rust-centric docs.

- **C ABI static libraries** (built from Rust)
  - Exposed via headers like `cosesign1/cosesign1.h`, `cosesign1/x509.h`, `cosesign1/mst.h`.
  - Uses an explicit “result object” model (allocate in the library, free via `*_free`).

- **C++ projection (header-only wrappers)**
  - Exposed via `<cosesign1/cosesign1.hpp>`.
  - Wraps the C ABI types into small value/RAII types like `cosesign1::CoseSign1` and `cosesign1::ValidationResult`.

## Data flow (high level)

1. Parse COSE_Sign1 bytes into a message object (C++: `CoseSign1::from_bytes`, C: call verify functions directly).
2. Verify the COSE signature (optional for MST-only workflows).
3. Run additional trust checks:
   - X.509 `x5c` chain validation (from message headers)
   - MST receipt verification

All APIs ultimately return a `ValidationResult` describing:

- whether verification succeeded
- which validator produced the result
- failures (with error codes + human-readable messages)

## Where to start

- Consumption (vcpkg + CMake) and full build instructions: `native/docs/README.md`
- “Copy/paste” patterns: `examples.md`
- Verification guide: `verification.md`
- Tests and coverage: `testing-and-coverage.md`
- Consumer apps:
  - C++: `native/docs/hello-world/cpp`
  - C: `native/docs/hello-world/c`
