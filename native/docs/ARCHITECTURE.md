# Native FFI Architecture

This document describes the complete architecture of the native (C/C++) projections for the COSE Sign1 validation library.

## Overview

The native projections provide three layers of abstraction:
1. **Rust FFI Layer**: C ABI exports from Rust using `extern "C"`
2. **C Projection**: Direct C API wrapping the FFI layer
3. **C++ Projection**: RAII wrappers providing modern C++ idioms

All three layers follow a **per-pack modular architecture**, allowing consumers to include and link only the functionality they need.

## Per-Pack Modularity

The library is organized into packs, each providing specific validation functionality:

- **Base**: Core validator, builder, result types (required)
- **Certificates Pack**: X.509 certificate validation
- **MST Pack**: Merkle Sealed Transparency receipt verification
- **AKV Pack**: Azure Key Vault KID validation
- **Trust Pack**: Trust policy authoring (future milestone)

Each pack is:
- A separate Rust FFI crate (staticlib/cdylib)
- A separate C header file
- A separate C++ header file
- An optional CMake target
- An optional vcpkg feature (future)

## Layer 1: Rust FFI

### Directory Structure
```
native/rust/
├── cose_sign1_validation_ffi/          # Base FFI (required)
│   ├── Cargo.toml                      # crate-type = ["cdylib", "staticlib", "rlib"]
│   └── src/
│       ├── lib.rs                      # Core types, builder, validator
│       ├── error.rs                    # Panic catching, thread-local errors
│       └── version.rs                  # ABI versioning
├── cose_sign1_validation_ffi_certificates/  # Certificates pack FFI
│   ├── Cargo.toml                      # crate-type = ["staticlib", "cdylib"]
│   └── src/
│       ├── lib.rs                      # Pack registration function
│       └── options.rs                  # C ABI options struct
├── cose_sign1_validation_ffi_mst/      # MST pack FFI
├── cose_sign1_validation_ffi_akv/      # AKV pack FFI
└── cose_sign1_validation_ffi_trust/    # Trust pack FFI (placeholder)
```

### Build Artifacts
- **Windows**: `*.dll` + `*.dll.lib` (import library)
- **Linux**: `*.so`
- **macOS**: `*.dylib`

Static libraries (`.lib`/`.a`) also available for all packs.

### C ABI Types
```c
// Opaque handles
typedef struct cose_validator_builder_t cose_validator_builder_t;
typedef struct cose_validator_t cose_validator_t;
typedef struct cose_validation_result_t cose_validation_result_t;

// Status codes
typedef enum {
    COSE_OK = 0,
    COSE_ERR = 1,
    COSE_PANIC = 2,
    COSE_INVALID_ARG = 3
} cose_status_t;

// Pack options (one struct per pack)
typedef struct cose_certificate_trust_options_t { /* ... */ } cose_certificate_trust_options_t;
typedef struct cose_mst_trust_options_t { /* ... */ } cose_mst_trust_options_t;
typedef struct cose_akv_trust_options_t { /* ... */ } cose_akv_trust_options_t;
```

### Key Functions (Base)
```c
cose_validator_builder_t* cose_validator_builder_new(void);
void cose_validator_builder_free(cose_validator_builder_t*);
cose_status_t cose_validator_builder_build(cose_validator_builder_t*, cose_validator_t**);
cose_status_t cose_validator_validate_bytes(cose_validator_t*, const uint8_t*, size_t, 
                                             const uint8_t*, size_t, cose_validation_result_t**);
```

### Key Functions (Per-Pack)
```c
// Certificates pack
cose_status_t cose_validator_builder_with_certificates_pack(cose_validator_builder_t*);
cose_status_t cose_validator_builder_with_certificates_pack_ex(cose_validator_builder_t*, 
                                                                 cose_certificate_trust_options_t*);

// MST pack
cose_status_t cose_validator_builder_with_mst_pack(cose_validator_builder_t*);
cose_status_t cose_validator_builder_with_mst_pack_ex(cose_validator_builder_t*, 
                                                       cose_mst_trust_options_t*);

// AKV pack
cose_status_t cose_validator_builder_with_akv_pack(cose_validator_builder_t*);
cose_status_t cose_validator_builder_with_akv_pack_ex(cose_validator_builder_t*, 
                                                       cose_akv_trust_options_t*);
```

## Layer 2: C Projection

### Directory Structure
```
native/c/
├── CMakeLists.txt                      # Build system with conditional pack linking
├── README.md                           # C API documentation
├── include/cose/
│   ├── cose_sign1.h                    # Base API (required)
│   ├── cose_certificates.h             # Certificates pack API
│   ├── cose_mst.h                      # MST pack API
│   └── cose_azure_key_vault.h          # AKV pack API
└── tests/
    ├── CMakeLists.txt
    └── smoke_test.c                    # Basic validation test
```

### CMake Configuration
```cmake
find_library(COSE_FFI_BASE_LIB cose_sign1_validation_ffi REQUIRED)
find_library(COSE_FFI_CERTIFICATES_LIB cose_sign1_validation_ffi_certificates)
find_library(COSE_FFI_MST_LIB cose_sign1_validation_ffi_mst)
find_library(COSE_FFI_AKV_LIB cose_sign1_validation_ffi_akv)

if(COSE_FFI_CERTIFICATES_LIB)
    target_link_libraries(cose_sign1 PUBLIC ${COSE_FFI_CERTIFICATES_LIB})
    target_compile_definitions(cose_sign1 PUBLIC COSE_HAS_CERTIFICATES_PACK)
endif()
# ... similar for MST and AKV
```

### Header Organization
Each pack header:
1. Includes `cose_sign1.h` (base types)
2. Declares pack-specific options struct
3. Declares pack registration functions
4. Protected by include guards
5. Uses `extern "C"` for C++ compatibility

### Usage Example (C)
```c
#include <cose/cose_sign1.h>
#include <cose/cose_certificates.h>

cose_validator_builder_t* builder = cose_validator_builder_new();
cose_validator_builder_with_certificates_pack(builder);

cose_validator_t* validator;
if (cose_validator_builder_build(builder, &validator) != COSE_OK) {
    fprintf(stderr, "Build failed: %s\n", cose_last_error_message_utf8());
    cose_validator_builder_free(builder);
    return 1;
}

cose_validation_result_t* result;
cose_validator_validate_bytes(validator, cose_bytes, cose_len, NULL, 0, &result);

if (cose_validation_result_ok(result)) {
    printf("Valid!\n");
} else {
    char* msg = cose_validation_result_failure_message(result);
    printf("Invalid: %s\n", msg);
    cose_string_free(msg);
}

cose_validation_result_free(result);
cose_validator_free(validator);
cose_validator_builder_free(builder);
```

## Layer 3: C++ Projection

### Directory Structure
```
native/c_pp/
├── CMakeLists.txt                      # Interface library with conditional pack linking
├── README.md                           # C++ API documentation
├── include/cose/
│   ├── validator.hpp                   # Base RAII types (required)
│   ├── certificates.hpp                # Certificates pack RAII
│   ├── mst.hpp                         # MST pack RAII
│   ├── azure_key_vault.hpp             # AKV pack RAII
│   └── cose.hpp                        # Convenience header (includes all)
└── tests/
    ├── CMakeLists.txt
    └── smoke_test.cpp                  # RAII validation test
```

### RAII Design Principles
- **Non-copyable**: Copy constructors deleted
- **Movable**: Move constructors/assignment enabled
- **Exception-based**: Errors throw `cose::cose_error`
- **Automatic cleanup**: Destructors call FFI free functions
- **Modern C++17**: Uses `std::vector`, `std::string`, structured bindings

### Key Classes

#### Base (validator.hpp)
```cpp
namespace cose {
    // Exception type
    class cose_error : public std::runtime_error { /* ... */ };
    
    // RAII wrapper for validation result
    class ValidationResult {
        cose_validation_result_t* handle;
    public:
        ValidationResult(cose_validation_result_t*);
        ~ValidationResult();
        bool Ok() const;
        std::string FailureMessage() const;
    };
    
    // RAII wrapper for validator
    class Validator {
        cose_validator_t* handle;
    public:
        Validator(cose_validator_t*);
        ~Validator();
        ValidationResult Validate(const std::vector<uint8_t>& cose_bytes,
                                  const std::vector<uint8_t>& detached_payload = {});
    };
    
    // Fluent builder base class
    class ValidatorBuilder {
    protected:
        cose_validator_builder_t* handle;
    public:
        ValidatorBuilder();
        virtual ~ValidatorBuilder();
        Validator Build();
    };
}
```

#### Per-Pack Extensions (certificates.hpp, mst.hpp, azure_key_vault.hpp)
```cpp
namespace cose {
    // Options use C++ types
    struct CertificateOptions {
        bool trust_embedded_chain_as_trusted = false;
        bool identity_pinning_enabled = false;
        std::vector<std::string> allowed_thumbprints;
        std::vector<std::string> pqc_algorithm_oids;
    };
    
    // Builder extends base class
    class ValidatorBuilderWithCertificates : public ValidatorBuilder {
    public:
        ValidatorBuilderWithCertificates& WithCertificates();
        ValidatorBuilderWithCertificates& WithCertificates(const CertificateOptions& options);
    };
}
```

### Usage Example (C++)
```cpp
#include <cose/certificates.hpp>

try {
    // Fluent builder with pack
    auto validator = cose::ValidatorBuilderWithCertificates()
        .WithCertificates()
        .Build();
    
    std::vector<uint8_t> cose_bytes = /* ... */;
    auto result = validator.Validate(cose_bytes);
    
    if (result.Ok()) {
        std::cout << "Valid!\n";
    } else {
        std::cout << "Invalid: " << result.FailureMessage() << "\n";
    }
    
    // RAII cleanup happens automatically
} catch (const cose::cose_error& e) {
    std::cerr << "Error: " << e.what() << "\n";
    return 1;
}
```

## Build System Integration

### CMake Workflow
1. Build Rust FFI libraries: `cargo build --release --workspace`
2. Configure C projection: `cmake -B build -S native/c -DBUILD_TESTING=ON`
3. Build C projection: `cmake --build build --config Release`
4. Configure C++ projection: `cmake -B build -S native/c_pp -DBUILD_TESTING=ON`
5. Build C++ projection: `cmake --build build --config Release`
6. Run tests: `ctest -C Release` (requires Rust DLLs in PATH)

### vcpkg (Overlay Port)
```json
{
    "name": "cosesign1-validation-native",
    "version-string": "0.1.0",
    "description": "C and C++ projections for COSE_Sign1 validation (Rust FFI-backed)",
    "supports": "windows | linux | osx",
    "default-features": ["certificates", "cpp"],
    "features": {
        "cpp": {
            "description": "Install C++ projection headers + CMake target"
        },
        "certificates": {
            "description": "Build/install X.509 certificates pack FFI and enable COSE_HAS_CERTIFICATES_PACK"
        },
        "mst": {
            "description": "Build/install MST pack FFI and enable COSE_HAS_MST_PACK"
        },
        "akv": {
            "description": "Build/install Azure Key Vault pack FFI and enable COSE_HAS_AKV_PACK"
        },
        "trust": {
            "description": "Build/install trust-policy pack FFI and enable COSE_HAS_TRUST_PACK"
        }
    }
}
```

## Error Handling

### Rust FFI Layer
- All public functions wrapped in `with_catch_unwind()`
- Panics converted to `COSE_PANIC` status code
- Error messages stored thread-locally
- Retrieved via `cose_last_error_message_utf8()`

### C Projection
- Check status codes after every call
- Use `cose_last_error_message_utf8()` for details
- Manually free all returned strings with `cose_string_free()`

### C++ Projection
- Exceptions thrown for all errors
- `cose::cose_error` includes detailed message
- RAII ensures cleanup even during exception unwinding
- No manual resource management needed

## Testing Strategy

### Smoke Tests (Current)
- **C**: Builder creation, pack registration, validator build
- **C++**: RAII wrappers, fluent API, exception handling, all packs

### Future Integration Tests
- Real COSE Sign1 message validation
- Certificate chain validation scenarios
- MST receipt verification with mock receipts
- AKV KID validation with pattern matching
- Trust policy evaluation
- Negative test cases (invalid signatures, expired certs, etc.)

### Coverage Testing
- **Rust**: `cargo-llvm-cov` with 95% target (already achieved)
- **C**: OpenCppCoverage (Windows) or gcov (Linux)
- **C++**: OpenCppCoverage (Windows) or gcov (Linux)

## Documentation

Each layer provides:
- **README.md**: Usage guide with examples
- **API reference**: Inline comments in headers
- **Architecture guide**: This document
- **Progress log**: [FFI_PROJECTIONS_PROGRESS.md](FFI_PROJECTIONS_PROGRESS.md)

## Future Work

### Milestone M3: Trust Policy Authoring
- Expose trust policy DSL to C/C++
- `TrustPlanBuilder` FFI
- C and C++ wrappers for policy construction
- Default trust plans

### Milestone M4: Comprehensive Testing
- Integration tests with real COSE messages
- Certificate validation test suite
- MST verification test suite
- Performance benchmarks

### Milestone M5: Packaging
- vcpkg port with per-pack features
- CMake find_package support
- Conan package (optional)
- Documentation site

### Milestone M6: Coverage & CI
- OpenCppCoverage scripts for C/C++
- GitHub Actions workflow for native builds
- Coverage reporting and enforcement
- Cross-platform testing (Windows, Linux, macOS)
