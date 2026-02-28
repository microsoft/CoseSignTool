---
applyTo: "native/c/**,native/c_pp/**,native/include/**"
---
# Native C/C++ Projection Standards — CoseSignTool

> Applies to `native/c/` and `native/c_pp/` directories.

## File Layout

```
native/
  c/
    include/cose/                     ← C headers
      cose.h                          ← Shared COSE types, status codes, IANA constants
      sign1.h                         ← COSE_Sign1 message primitives (includes cose.h)
      sign1/
        validation.h                  ← Validator builder/runner
        trust.h                       ← Trust plan/policy authoring
        signing.h                     ← Sign1 builder, signing service, factory
        factories.h                   ← Multi-factory wrapper
        cwt.h                         ← CWT claims builder/serializer
        extension_packs/
          certificates.h              ← X.509 certificate trust pack
          certificates_local.h        ← Ephemeral certificate generation
          azure_key_vault.h           ← Azure Key Vault trust pack
          mst.h                       ← Microsoft Transparency trust pack
      crypto/
        openssl.h                     ← OpenSSL crypto provider
      did/
        x509.h                        ← DID:x509 utilities
    tests/                            ← C test files (GTest + plain)
    examples/                         ← C example programs
    CMakeLists.txt                    ← C project
  c_pp/
    include/cose/                     ← C++ RAII headers (same tree shape)
      cose.hpp                        ← Umbrella (conditionally includes everything)
      sign1.hpp                       ← CoseSign1Message, CoseHeaderMap
      sign1/
        validation.hpp                ← ValidatorBuilder, Validator, ValidationResult
        trust.hpp                     ← TrustPlanBuilder, TrustPolicyBuilder
        signing.hpp                   ← CoseSign1Builder, SigningService, SignatureFactory
        factories.hpp                 ← Factory multi-wrapper
        cwt.hpp                       ← CwtClaims fluent builder
        extension_packs/
          certificates.hpp
          certificates_local.hpp
          azure_key_vault.hpp
          mst.hpp
      crypto/
        openssl.hpp                   ← CryptoProvider, CryptoSigner, CryptoVerifier
      did/
        x509.hpp                      ← ParsedDid, DidX509* free functions
    tests/                            ← C++ test files (GTest + plain)
    examples/                         ← C++ example programs
    CMakeLists.txt                    ← C++ project
```

**Key design principle:** The header tree mirrors the Rust crate hierarchy.
- `cose.h` / `cose.hpp` = shared COSE layer (`cose_primitives` crate)
- `sign1.h` / `sign1.hpp` = Sign1 primitives (`cose_sign1_primitives` crate)
- `sign1/*` = Sign1 domain crates (signing, validation, trust, extension packs)
- Including `sign1.h` auto-includes `cose.h`

## C Header Conventions

### File Structure
```c
// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef COSE_FEATURE_H
#define COSE_FEATURE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Opaque handle types */
typedef struct cose_widget_t cose_widget_t;

/* Status codes (if not already defined) */
/* #include "cose_sign1.h" for cose_status_t */

/** @brief Create a new widget. */
cose_status_t cose_widget_new(cose_widget_t** out);

/** @brief Free a widget. */
void cose_widget_free(cose_widget_t* widget);

#ifdef __cplusplus
}
#endif

#endif /* COSE_FEATURE_H */
```

### Rules
- Include guards: `#ifndef COSE_FEATURE_H` / `#define` / `#endif`
- `extern "C"` wrapper for C++ compat
- Opaque handles via `typedef struct X X;`
- Doxygen `/** @brief */` on every function
- All functions return `cose_status_t` (except free/version/query functions)
- `const` correctness on all read-only pointer params
- `size_t` for lengths, `int64_t` for COSE labels, `bool` for flags

### Naming
- Functions: `cose_{module}_{action}` (e.g., `cose_validator_builder_new`)
- Types: `cose_{type}_t` (e.g., `cose_validator_t`)
- Constants: `COSE_{CATEGORY}_{NAME}` (e.g., `COSE_ALG_ES256`, `COSE_HEADER_ALG`)
- Pack helpers: `cose_{pack}_trust_policy_builder_require_{predicate}`

## C++ Header Conventions

### Namespace
All C++ wrappers live in `namespace cose { }`.

### RAII Pattern
```cpp
namespace cose {

class Widget {
public:
    // Factory method (throws on failure)
    static Widget New(/* params */) {
        cose_widget_t* handle = nullptr;
        detail::ThrowIfNotOk(cose_widget_new(&handle));
        return Widget(handle);
    }

    // Move-only (non-copyable)
    Widget(Widget&& other) noexcept : handle_(std::exchange(other.handle_, nullptr)) {}
    Widget& operator=(Widget&& other) noexcept {
        if (this != &other) {
            if (handle_) cose_widget_free(handle_);
            handle_ = std::exchange(other.handle_, nullptr);
        }
        return *this;
    }
    Widget(const Widget&) = delete;
    Widget& operator=(const Widget&) = delete;

    // Destructor frees handle
    ~Widget() { if (handle_) cose_widget_free(handle_); }

    // Native handle access
    cose_widget_t* native_handle() const { return handle_; }

private:
    explicit Widget(cose_widget_t* h) : handle_(h) {}
    cose_widget_t* handle_;
};

} // namespace cose
```

### Rules
- All RAII classes are **move-only** (delete copy ctor/assignment)
- Destructors call the C `*_free` function
- Factory methods are `static` and throw `cose::cose_error` on failure
- `native_handle()` accessor for interop
- Header-only implementation (inline in `.hpp`)
- Include the corresponding C header: `#include <cose/sign1/validation.h>`

### Exception Classes
```cpp
class cose_error : public std::runtime_error {
public:
    explicit cose_error(const std::string& msg) : std::runtime_error(msg) {}
    explicit cose_error(cose_status_t status);  // fetches cose_last_error_message_utf8()
};
```

### Umbrella Header
`cose.hpp` conditionally includes pack headers:
```cpp
#ifdef COSE_HAS_CERTIFICATES_PACK
#include <cose/sign1/extension_packs/certificates.hpp>
#endif
#ifdef COSE_HAS_SIGNING
#include <cose/sign1/signing.hpp>
#endif
```

### Return Types
- Methods returning `CoseSign1Message` (rich object) are preferred when `COSE_HAS_PRIMITIVES` is available.
- `*Bytes()` overloads return `std::vector<uint8_t>` for serialization.
- Use `std::optional` for values that may be absent (header lookups).

## CMake Conventions

### FFI Library Discovery
```cmake
find_library(COSE_FFI_MY_LIB
    NAMES cose_sign1_my_ffi
    PATHS ${RUST_FFI_DIR}
)

if(COSE_FFI_MY_LIB)
    message(STATUS "Found my pack: ${COSE_FFI_MY_LIB}")
    target_link_libraries(cose_sign1 INTERFACE ${COSE_FFI_MY_LIB})
    target_compile_definitions(cose_sign1 INTERFACE COSE_HAS_MY_PACK)
endif()
```

### Rules
- Base FFI lib (`cose_sign1_validation_ffi`) is REQUIRED.
- Pack libs are OPTIONAL — guarded with `if(LIB_VAR)`.
- Each found pack sets `COSE_HAS_*` compile definitions.
- Use INTERFACE libraries (header-only projections).
- Link platform system libs: Win32 (`ws2_32`, `advapi32`, `bcrypt`, `ntdll`, `userenv`), Unix (`pthread`, `dl`, `m`).
- Support `COSE_ENABLE_ASAN` option for address sanitizer.
- Install rules export under `cose::` namespace.

## Feature Defines

| Define | Set When |
|--------|----------|
| `COSE_HAS_CERTIFICATES_PACK` | certificates FFI lib found |
| `COSE_HAS_MST_PACK` | MST FFI lib found |
| `COSE_HAS_AKV_PACK` | AKV FFI lib found |
| `COSE_HAS_TRUST_PACK` | trust FFI lib found |
| `COSE_HAS_PRIMITIVES` | primitives FFI lib found |
| `COSE_HAS_SIGNING` | signing FFI lib found |
| `COSE_HAS_CWT_HEADERS` | headers FFI lib found |
| `COSE_HAS_DID_X509` | DID:x509 FFI lib found |

These MUST be set in both C and C++ CMakeLists.txt AND in `.vscode/c_cpp_properties.json` for IntelliSense.

## vcpkg Port

The vcpkg port at `native/vcpkg_ports/cosesign1-validation-native/` provides:
- Default features: `certificates`, `cpp`, `signing`, `primitives`, `mst`
- Optional features: `akv`, `trust`, `headers`, `did-x509`
- Each feature builds its Rust FFI crate and installs headers

When adding a new pack: add its feature to `vcpkg.json`, cargo build to `portfile.cmake`, and targets to `Config.cmake`.

## Example Programs

### C Example Pattern
```c
int main(int argc, char* argv[]) {
    /* ... */
    
    /* Resource declarations */
    cose_validator_t* validator = NULL;
    cose_validation_result_t* result = NULL;
    
    /* Use CHECK macros for error handling */
    COSE_CHECK(cose_validator_builder_new(&builder));
    /* ... */
    
cleanup:
    if (result) cose_validation_result_free(result);
    if (validator) cose_validator_free(validator);
    return exit_code;
}
```

### C++ Example Pattern
```cpp
int main() {
    try {
        auto builder = cose::ValidatorBuilder();
        auto validator = builder.Build();
        auto result = validator.Validate(bytes, {});
        // No cleanup needed — RAII handles it
    } catch (const cose::cose_error& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }
}
```

## Testing

- C tests: Plain C executables + GTest (if available via vcpkg)
- C++ tests: GTest preferred, plain C++ fallback
- Real-world trust plan tests use file-based test data with CMake `COMPILE_DEFINITIONS` for paths
- Address sanitizer support via GTest DLL copy logic on Windows
