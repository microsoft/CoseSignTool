<!-- Copyright (c) Microsoft Corporation. Licensed under the MIT License. -->

# Native COSE Sign1 SDK

A production-grade **Rust / C / C++** implementation of [COSE Sign1](https://datatracker.ietf.org/doc/html/rfc9052)
signing, validation, and trust-policy evaluation — with streaming support for
payloads of any size.

```
┌──────────────────────────────────────────────────────────┐
│   Your Application (C, C++, or Rust)                     │
├──────────────────────────────────────────────────────────┤
│   C++ RAII Headers   │   C Headers   │   Rust API       │
│   (header-only)      │   (ABI-stable)│   (source of     │
│   native/c_pp/       │   native/c/   │    truth)        │
├──────────────────────┴───────────────┤   native/rust/   │
│   FFI Crates (extern "C", panic-safe)│                   │
├──────────────────────────────────────┴───────────────────┤
│   Rust Library Crates (primitives → signing → validation)│
└──────────────────────────────────────────────────────────┘
```

## Key Properties

| Property | How |
|----------|-----|
| **Zero unnecessary allocation** | `Arc<[u8]>` sharing, `ByteView` borrows, move-not-clone builders |
| **Streaming sign & verify** | 64 KB chunks — sign or verify a 10 GB payload in ~65 KB of memory |
| **Formally verified CBOR** | Default backend is Microsoft Research's EverParse (cborrs) |
| **Modular extension packs** | X.509, Azure Key Vault, Microsoft Transparency — link only what you need |
| **Compile-time provider selection** | CBOR and crypto providers are Cargo features, not runtime decisions |
| **Panic-safe FFI** | Every `extern "C"` function wrapped in `catch_unwind` with thread-local errors |

## Quick Start

### Rust

```bash
cd native/rust
cargo test --workspace                              # run all tests
cargo run -p cose_sign1_validation_demo -- selftest # run the demo
```

### C

```bash
# 1. Build Rust FFI libraries
cd native/rust && cargo build --release --workspace

# 2. Build & test the C projection
cd native/c
cmake -B build -DBUILD_TESTING=ON
cmake --build build --config Release
ctest --test-dir build -C Release
```

### C++

```bash
# 1. Build Rust FFI libraries (same as above)
cd native/rust && cargo build --release --workspace

# 2. Build & test the C++ projection
cd native/c_pp
cmake -B build -DBUILD_TESTING=ON
cmake --build build --config Release
ctest --test-dir build -C Release
```

### Via vcpkg (recommended for C/C++ consumers)

```bash
vcpkg install cosesign1-validation-native[cpp,certificates,mst,signing] \
    --overlay-ports=native/vcpkg_ports
```

Then in your `CMakeLists.txt`:

```cmake
find_package(cose_sign1_validation CONFIG REQUIRED)
target_link_libraries(my_app PRIVATE cosesign1_validation_native::cose_sign1)      # C
target_link_libraries(my_app PRIVATE cosesign1_validation_native::cose_sign1_cpp)  # C++
```

## Code Examples

### Sign a payload (C++)

```cpp
#include <cose/sign1/signing.hpp>
#include <cose/crypto/openssl.hpp>

auto signer  = cose::crypto::OpenSslSigner::FromDer(key_der.data(), key_der.size());
auto factory = cose::sign1::SignatureFactory::FromCryptoSigner(signer);
auto bytes   = factory.SignDirectBytes(payload.data(), payload.size(), "application/json");
```

### Validate with trust policy (C++)

```cpp
#include <cose/cose.hpp>

cose::ValidatorBuilder builder;
cose::WithCertificates(builder);

cose::TrustPolicyBuilder policy(builder);
policy.RequireContentTypeNonEmpty();
cose::RequireX509ChainTrusted(policy);

auto plan      = policy.Compile();
cose::WithCompiledTrustPlan(builder, plan);
auto validator = builder.Build();
auto result    = validator.Validate(cose_bytes);
```

### Parse and inspect (C)

```c
#include <cose/sign1.h>

cose_sign1_message_t* msg = NULL;
cose_sign1_message_parse(cose_bytes, len, &msg);

int64_t alg = 0;
cose_sign1_message_algorithm(msg, &alg);
printf("Algorithm: %lld\n", alg);

cose_sign1_message_free(msg);
```

## Directory Layout

```
native/
├── rust/                 Rust workspace — the source of truth
│   ├── primitives/         CBOR, crypto, and COSE type layers
│   ├── signing/            Builder, factory, header contributions
│   ├── validation/         Trust engine, staged validator, demo
│   ├── extension_packs/    Certificates, AKV, MST, AAS
│   ├── did/                DID:x509 utilities
│   └── cli/                Command-line tool
├── c/                    C projection
│   ├── include/cose/       C headers (mirrors Rust crate tree)
│   └── tests/              GTest-based C tests
├── c_pp/                 C++ projection
│   ├── include/cose/       Header-only RAII wrappers
│   └── tests/              GTest-based C++ tests
└── docs/                 Cross-cutting documentation
    ├── ARCHITECTURE.md     Full architecture reference
    ├── FFI-OWNERSHIP.md    Ownership & memory model across the FFI boundary
    └── DEPENDENCY-PHILOSOPHY.md  Why each dependency exists
```

## Dependency Philosophy

The SDK follows a **minimal-footprint** strategy:

- **Core crates** depend only on `openssl`, `sha2`, `x509-parser`, `base64`, and `cborrs` — each irreplaceable.
- **Azure dependencies** (`tokio`, `reqwest`, `azure_*`) exist only in extension packs and are feature-gated.
- **No proc-macro crates** in the core path — no `thiserror`, no `derive_builder`.
- **Standard library first** — `std::sync::LazyLock` replaced `once_cell`; `std::sync::Mutex` replaced `parking_lot`.

See [docs/DEPENDENCY-PHILOSOPHY.md](docs/DEPENDENCY-PHILOSOPHY.md) for the full rationale.

## Documentation

| Document | What it covers |
|----------|---------------|
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | Complete architecture, naming conventions, extension packs, CLI |
| [docs/FFI-OWNERSHIP.md](docs/FFI-OWNERSHIP.md) | Ownership model, handle lifecycle, zero-copy patterns |
| [docs/DEPENDENCY-PHILOSOPHY.md](docs/DEPENDENCY-PHILOSOPHY.md) | Why each dependency exists, addition guidelines |
| [rust/README.md](rust/README.md) | Crate inventory and Rust quick start |
| [rust/docs/memory-characteristics.md](rust/docs/memory-characteristics.md) | Per-operation memory profiles, streaming analysis |
| [rust/docs/ffi_guide.md](rust/docs/ffi_guide.md) | FFI crate reference, buffer patterns, build integration |
| [rust/docs/signing_flow.md](rust/docs/signing_flow.md) | Signing pipeline, factory types, post-sign verification |
| [c/README.md](c/README.md) | C API reference, examples, error handling |
| [c_pp/README.md](c_pp/README.md) | C++ RAII reference, examples, exception handling |
| [CONTRIBUTING.md](CONTRIBUTING.md) | Development setup, testing, PR checklist |

## Extension Packs

| Pack | Rust Crate | Purpose |
|------|-----------|---------|
| X.509 Certificates | `cose_sign1_certificates` | `x5chain` parsing, certificate trust verification |
| Azure Key Vault | `cose_sign1_azure_key_vault` | KID-based key resolution and allow-listing |
| Microsoft Transparency | `cose_sign1_transparent_mst` | MST receipt verification (Merkle Sealed Transparency) |
| Azure Artifact Signing | `cose_sign1_azure_artifact_signing` | Azure Trusted Signing integration |
| Ephemeral Certs | `cose_sign1_certificates_local` | Test/dev certificate generation |

Each pack is a separate Rust crate with its own FFI projection, C header, and
C++ wrapper. Link only the packs you need — the CMake build auto-discovers
available packs and sets `COSE_HAS_*` defines accordingly.

## Quality Gates

| Gate | Threshold | Tool |
|------|-----------|------|
| Rust line coverage | ≥ 90% | `cargo llvm-cov` |
| C/C++ line coverage | ≥ 90% | OpenCppCoverage |
| Address sanitizer | Clean | MSVC ASAN via `collect-coverage-asan.ps1` |
| Dependency allowlist | Enforced | `allowed-dependencies.toml` |

## License

[MIT](../LICENSE) — Copyright (c) Microsoft Corporation.