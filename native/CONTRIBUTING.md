<!-- Copyright (c) Microsoft Corporation. Licensed under the MIT License. -->

# Contributing to Native CoseSignTool

Thank you for your interest in improving the native COSE Sign1 SDK. This guide
covers everything you need to build, test, and submit changes to the
`native/` directory.

## Table of Contents

- [Development Setup](#development-setup)
- [Building](#building)
- [Testing](#testing)
- [Coverage Requirements](#coverage-requirements)
- [Code Style](#code-style)
- [Architecture Rules](#architecture-rules)
- [Naming Conventions](#naming-conventions)
- [PR Review Checklist](#pr-review-checklist)
- [Adding a New Extension Pack](#adding-a-new-extension-pack)
- [Adding a New FFI Export](#adding-a-new-ffi-export)

---

## Development Setup

### Required Tools

| Tool | Version | Purpose |
|------|---------|---------|
| **Rust** | stable (edition 2021) | Core implementation |
| **OpenSSL** | 3.0+ | Crypto backend (via `OPENSSL_DIR` or vcpkg) |
| **CMake** | 3.20+ | C/C++ projection builds |
| **C compiler** | C11 (MSVC / GCC / Clang) | C projection tests |
| **C++ compiler** | C++17 (MSVC 2017+ / GCC 7+ / Clang 5+) | C++ projection tests |
| **vcpkg** | Latest | Recommended C/C++ consumption path |

### Optional Tools

| Tool | Purpose |
|------|---------|
| OpenCppCoverage | C/C++ line coverage on Windows |
| cargo-llvm-cov | Rust line coverage (`cargo +nightly llvm-cov`) |
| GTest | C/C++ test framework (fetched automatically by CMake) |

### OpenSSL via vcpkg (recommended on Windows)

```powershell
vcpkg install openssl:x64-windows
$env:OPENSSL_DIR = "C:\vcpkg\installed\x64-windows"
$env:PATH = "$env:OPENSSL_DIR\bin;$env:PATH"
```

### First Build

```powershell
cd native/rust
cargo build --workspace           # debug build — verifies toolchain + OpenSSL
cargo test --workspace            # run all Rust tests
```

---

## Building

### Rust

```powershell
cd native/rust
cargo build --release --workspace # release build (produces FFI .lib / .dll)
cargo check --workspace           # type-check only (faster iteration)
```

### C Projection

```powershell
cd native/rust && cargo build --release --workspace  # build FFI libs first
cd native/c
cmake -B build -DBUILD_TESTING=ON
cmake --build build --config Release
```

### C++ Projection

```powershell
cd native/rust && cargo build --release --workspace  # build FFI libs first
cd native/c_pp
cmake -B build -DBUILD_TESTING=ON
cmake --build build --config Release
```

### Via vcpkg (builds everything)

```powershell
vcpkg install cosesign1-validation-native[cpp,certificates,mst,signing] `
    --overlay-ports=native/vcpkg_ports
```

---

## Testing

### Rust

```powershell
cd native/rust
cargo test --workspace                               # all tests
cargo test -p cose_sign1_validation                  # single crate
cargo test -p cose_sign1_certificates -- --nocapture # with stdout
```

### C / C++

```powershell
# After building (see above)
ctest --test-dir native/c/build -C Release
ctest --test-dir native/c_pp/build -C Release
```

### Full Pipeline (build + test + coverage + ASAN)

```powershell
./native/collect-coverage-asan.ps1 -Configuration Debug -MinimumLineCoveragePercent 90
```

This single script:
1. Builds Rust FFI crates
2. Runs C projection tests with coverage + ASAN
3. Runs C++ projection tests with coverage + ASAN
4. Fails if coverage < 90%

### Test Conventions

- **Arrange-Act-Assert** pattern in all tests.
- **Parallel-safe**: no shared mutable state, unique temp file names.
- **Both paths**: every feature needs positive *and* negative test cases.
- **FFI null safety**: every pointer parameter in every FFI function needs a
  null-pointer test.
- **Roundtrip tests**: sign → parse → validate for end-to-end confidence.

---

## Coverage Requirements

| Component | Minimum | Tool | Command |
|-----------|---------|------|---------|
| Rust library crates | ≥ 90% line | `cargo llvm-cov` | `cd native/rust && ./collect-coverage.ps1` |
| C projection | ≥ 90% line | OpenCppCoverage | `cd native/c && ./collect-coverage.ps1` |
| C++ projection | ≥ 90% line | OpenCppCoverage | `cd native/c_pp && ./collect-coverage.ps1` |

### What May Be Excluded from Coverage

Only FFI boundary stubs may use `#[cfg_attr(coverage_nightly, coverage(off))]`:

| Allowed | Example |
|---------|---------|
| ✅ FFI panic handlers | `handle_panic()` |
| ✅ ABI version functions | `cose_*_abi_version()` |
| ✅ Free functions | `cose_*_free()` |
| ✅ Error accessors | `cose_last_error_*()` |

### What Must NEVER Be Excluded

- Business logic
- Validation / parsing
- Error handling branches
- Crypto operations
- Builder methods

Every `coverage(off)` annotation must include a comment justifying why the code
is unreachable.

---

## Code Style

### Rust

| Rule | Example |
|------|---------|
| Copyright header on every `.rs` file | `// Copyright (c) Microsoft Corporation.` / `// Licensed under the MIT License.` |
| Manual `Display` + `Error` impls | No `thiserror` in production crates |
| `// SAFETY:` comment on every `unsafe` block | Explains why the operation is sound |
| No `.unwrap()` / `.expect()` in production code | Tests are fine |
| Prefer `.into()` over `.to_string()` for literals | `"message".into()` not `"message".to_string()` |

Full formatting and lint rules are in
[`.editorconfig`](../.editorconfig) and the Cargo workspace `[lints]` table.

### C

| Rule | Example |
|------|---------|
| `extern "C"` guards in every header | `#ifdef __cplusplus` / `extern "C" {` / `#endif` |
| Include guards (`#ifndef`) | `#ifndef COSE_SIGN1_VALIDATION_H` |
| `*const` for borrowed pointers | `const cose_sign1_message_t* msg` |
| `*mut` / non-const for ownership transfer | `cose_sign1_message_t** out_msg` |

### C++

| Rule | Example |
|------|---------|
| Move-only classes | Delete copy ctor + copy assignment |
| Null-check in destructor | `if (handle_) cose_*_free(handle_);` |
| `@see` on copy methods | Point to zero-copy alternative |
| Namespace: `cose::sign1::` | Shared types in `cose::` |

---

## Architecture Rules

### Dependencies Flow DOWN Only

```
Primitives  ←  Domain Crates  ←  Extension Packs  ←  FFI Crates  ←  C/C++ Headers
```

- **Never** depend upward (e.g., primitives must not depend on validation).
- **Never** depend sideways between extension packs (e.g., certificates must
  not depend on MST).

### Single Responsibility

| Layer | Allowed | Not Allowed |
|-------|---------|-------------|
| Primitives | Types, traits, constants | Policy, I/O, network |
| Domain crates | Business logic for one area | Cross-area dependencies |
| Extension packs | Service integration via traits | Direct domain-crate coupling |
| FFI crates | ABI translation only | Business logic |
| C/C++ headers | Inline RAII wrappers | Compiled code |

### External Dependency Rules

1. Every external crate must be listed in `allowed-dependencies.toml`.
2. Prefer `std` over third-party (see [DEPENDENCY-PHILOSOPHY.md](docs/DEPENDENCY-PHILOSOPHY.md)).
3. No proc-macro crates in the core dependency path.
4. Azure SDK dependencies only in extension packs, gated behind Cargo features.

---

## Naming Conventions

### Rust Crate Names

| Pattern | Example | Purpose |
|---------|---------|---------|
| `*_primitives` | `cbor_primitives` | Zero-policy trait crates |
| `cose_sign1_*` | `cose_sign1_signing` | Domain / extension crates |
| `*_ffi` | `cose_sign1_signing_ffi` | FFI projection of parent crate |
| `*_local` | `cose_sign1_certificates_local` | Local/test utility crates |
| `*_test_utils` | `cose_sign1_validation_test_utils` | Shared test infrastructure |

### FFI Function Prefixes

| Prefix | Scope | Example |
|--------|-------|---------|
| `cose_` | Shared COSE types | `cose_headermap_new`, `cose_crypto_signer_free` |
| `cose_sign1_` | Sign1 operations | `cose_sign1_message_parse`, `cose_sign1_builder_sign` |
| `cose_sign1_certificates_` | Certificates pack | `cose_sign1_certificates_trust_policy_builder_*` |
| `cose_sign1_mst_` | MST pack | `cose_sign1_mst_options_new` |
| `cose_sign1_akv_` | AKV pack | `cose_sign1_akv_options_new` |
| `did_x509_` | DID:x509 | `did_x509_parse` |

### C++ Class Names

Classes mirror Rust types in `PascalCase` within namespaces:

| Rust | C++ |
|------|-----|
| `CoseSign1Message` | `cose::sign1::CoseSign1Message` |
| `ValidatorBuilder` | `cose::sign1::ValidatorBuilder` |
| `CoseHeaderMap` | `cose::CoseHeaderMap` |

---

## PR Review Checklist

Every native PR is evaluated on these dimensions. Address each before
requesting review.

### 1. Zero-Copy / No-Allocation

- [ ] No unnecessary `.clone()`, `.to_vec()`, `.to_owned()` on large types
- [ ] FFI handle conversions use bounded lifetimes (`<'a>`), not `'static`
- [ ] C++ accessors return `ByteView` (borrowed), not `std::vector` (copied)
- [ ] `_consume` / `_to_message` variants provided where applicable

### 2. Safety & Correctness

- [ ] Every FFI pointer parameter is null-checked before dereference
- [ ] Every `extern "C"` function is wrapped in `catch_unwind`
- [ ] Every `unsafe` block has a `// SAFETY:` comment
- [ ] Memory ownership documented: who allocates, who frees, which `*_free()`

### 3. API Design

- [ ] Builder patterns are fluent (return `&mut self` or `Self`)
- [ ] Error types use manual `Display + Error` (no `thiserror`)
- [ ] C++ classes are move-only (copy deleted)
- [ ] C headers have `extern "C"` guards

### 4. Test Quality

- [ ] Positive and negative paths covered
- [ ] FFI null-pointer safety tests for every parameter
- [ ] Roundtrip test (sign → parse → validate) if applicable
- [ ] No shared mutable state between tests (parallel-safe)

### 5. Documentation

- [ ] Public Rust APIs have `///` doc comments
- [ ] FFI functions have `# Safety` sections
- [ ] C++ methods have `@see` cross-refs to zero-copy alternatives
- [ ] Module-level `//!` comment in every new `lib.rs`

---

## Adding a New Extension Pack

1. Create the crate structure:

```
extension_packs/my_pack/
├── Cargo.toml
├── src/
│   ├── lib.rs                  # Module docs + pub use
│   ├── signing/mod.rs          # If contributing to signing
│   └── validation/
│       ├── mod.rs
│       ├── trust_pack.rs       # impl CoseSign1TrustPack
│       ├── fact_producer.rs    # impl TrustFactProducer
│       └── key_resolver.rs     # impl SigningKeyResolver (optional)
├── tests/                      # Integration tests
└── ffi/
    ├── Cargo.toml              # crate-type = ["staticlib", "cdylib"]
    └── src/
        ├── lib.rs              # FFI exports with catch_unwind
        ├── types.rs            # Opaque handle types
        └── provider.rs         # CBOR provider selection
```

2. Add to workspace `members` in `native/rust/Cargo.toml`.
3. Create C header: `native/c/include/cose/sign1/extension_packs/my_pack.h`
4. Create C++ header: `native/c_pp/include/cose/sign1/extension_packs/my_pack.hpp`
5. Add feature to vcpkg port (`native/vcpkg_ports/`).
6. Add `COSE_HAS_MY_PACK` define to CMake.

---

## Adding a New FFI Export

When you add a public API to a Rust library crate that needs C/C++ access:

1. **Rust FFI**: Add `#[no_mangle] pub extern "C" fn cose_*()` in the FFI crate.
2. **C header**: Add matching declaration in the appropriate `.h` file.
3. **C++ header**: Add RAII wrapper method in the corresponding `.hpp` file.
4. **Null tests**: Add null-pointer safety tests for every pointer parameter.
5. **C/C++ tests**: Add GTest coverage for the new function.

The C/C++ headers are hand-maintained (not auto-generated) — this is
intentional to preserve the header hierarchy and enable C++ RAII patterns. See
[rust/docs/ffi_guide.md](rust/docs/ffi_guide.md) for the rationale.

---

## Questions?

- Architecture questions → [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)
- Ownership/memory questions → [docs/FFI-OWNERSHIP.md](docs/FFI-OWNERSHIP.md)
- Dependency questions → [docs/DEPENDENCY-PHILOSOPHY.md](docs/DEPENDENCY-PHILOSOPHY.md)
- Rust-specific docs → [rust/docs/](rust/docs/)