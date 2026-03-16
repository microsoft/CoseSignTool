# vcpkg: single-port native consumption

## The port

- vcpkg port name: `cosesign1-validation-native`
- CMake package name: `cose_sign1_validation`
- CMake targets:
  - `cosesign1_validation_native::cose_sign1` (C)
  - `cosesign1_validation_native::cose_sign1_cpp` (C++) when feature `cpp` is enabled

The port is implemented as an **overlay port** in this repo at:

- `native/vcpkg_ports/cosesign1-validation-native/`

## Features (configuration options)

Feature | Purpose | C compile define
---|---|---
`cpp` | Install C++ projection headers + CMake target | (n/a)
`certificates` | Enable X.509 pack | `COSE_HAS_CERTIFICATES_PACK`
`certificates-local` | Enable local certificate generation | `COSE_HAS_CERTIFICATES_LOCAL`
`mst` | Enable MST pack | `COSE_HAS_MST_PACK`
`akv` | Enable AKV pack | `COSE_HAS_AKV_PACK`
`trust` | Enable trust-policy/trust-plan pack | `COSE_HAS_TRUST_PACK`
`signing` | Enable signing APIs | `COSE_HAS_SIGNING`
`primitives` | Enable primitives (message parsing/inspection) | `COSE_HAS_PRIMITIVES`
`factories` | Enable signing factories (message construction) | `COSE_HAS_FACTORIES`
`crypto` | Enable OpenSSL crypto provider (ECDSA, ML-DSA) | `COSE_HAS_CRYPTO_OPENSSL`
`cbor-everparse` | Enable EverParse CBOR provider | `COSE_CBOR_EVERPARSE`
`headers` | Enable CWT headers support | `COSE_HAS_CWT_HEADERS`
`did-x509` | Enable DID:x509 support | `COSE_HAS_DID_X509`

Defaults: `cpp`, `certificates`, `signing`, `primitives`, `mst`, `certificates-local`, `crypto`, `factories`.

## Provider Selection

### Crypto Provider
The `crypto` feature enables the OpenSSL crypto provider:
- **Use case:** Signing COSE Sign1 messages, generating certificates
- **Algorithms:** ECDSA P-256/P-384/P-521, ML-DSA-65/87/44 (PQC)
- **Requires:** OpenSSL 3.0+ (with experimental PQC support for ML-DSA)
- **Sets:** `COSE_HAS_CRYPTO_OPENSSL` preprocessor define

Without `crypto`, the library is validation-only (no signing capabilities).

### CBOR Provider
The `cbor-everparse` feature enables the EverParse CBOR parser:
- **Use case:** Formally verified CBOR parsing for security-critical applications
- **Default:** Enabled by default
- **Sets:** `COSE_CBOR_EVERPARSE` preprocessor define

EverParse is currently the only supported CBOR provider.

### Factory Feature
The `factories` feature enables high-level signing APIs:
- **Dependencies:** Requires `signing` and `crypto` features
- **Use case:** Simplified COSE Sign1 message construction with fluent API
- **APIs:** `cose_sign1_factory_from_crypto_signer()` (C), `cose::SignatureFactory` (C++)
- **Sets:** `COSE_HAS_FACTORIES` preprocessor define

Factories wrap lower-level signing APIs with:
- Direct signing (embedded payload)
- Indirect signing (detached payload)
- File-based streaming for large payloads
- Callback-based streaming

## Install with overlay ports

Assuming `VCPKG_ROOT` is set (or vcpkg is on `PATH`) and this repo is checked out locally:

```powershell
# Discover vcpkg root — set VCPKG_ROOT if not already configured
$vcpkg = $env:VCPKG_ROOT ?? (Split-Path (Get-Command vcpkg).Source)

& "$vcpkg\vcpkg" install cosesign1-validation-native[cpp,certificates,mst,akv,trust] `
    --overlay-ports="$PSScriptRoot\..\native\vcpkg_ports"
```

Notes:

- The port runs `cargo build` internally. Ensure Rust is installed and on PATH.
- The port is **static-only** (it installs static libraries).

## Use from CMake (toolchain)

Configure your project with the vcpkg toolchain file:

```powershell
cmake -S . -B out -DCMAKE_TOOLCHAIN_FILE="$env:VCPKG_ROOT/scripts/buildsystems/vcpkg.cmake"
```

In your `CMakeLists.txt`:

```cmake
find_package(cose_sign1_validation CONFIG REQUIRED)

# C API
target_link_libraries(your_target PRIVATE cosesign1_validation_native::cose_sign1)

# C++ API (requires feature "cpp")
target_link_libraries(your_cpp_target PRIVATE cosesign1_validation_native::cose_sign1_cpp)
```

The port’s config file also links required platform libs (e.g., Windows system libs) for the C target.

## What gets installed

- C headers under `include/cose/…`
- C++ headers under `include/cose/…` (when `cpp` is enabled)
- Rust FFI static libraries under `lib/` and `debug/lib/`

## Development workflow tips

- If you’re iterating on the port, prefer `--editable` workflows by pointing vcpkg at this repo and using overlay ports.
- If a vcpkg install seems stale, use:

```powershell
& "$env:VCPKG_ROOT\vcpkg" remove cosesign1-validation-native
```

or bump the port version for internal testing.
