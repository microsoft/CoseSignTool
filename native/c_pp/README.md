# COSE Sign1 C++ API

Modern C++ (C++17) projection for the COSE Sign1 validation library with RAII wrappers and fluent builder pattern.

## Prerequisites

- CMake 3.20 or later
- C++17-capable compiler (MSVC 2017+, GCC 7+, Clang 5+)
- Rust toolchain (to build the underlying FFI libraries)

## Building

### 1. Build the Rust FFI libraries

```bash
cd ../rust
cargo build --release --workspace
```

### 2. Configure and build the C++ projection

```bash
mkdir build
cd build
cmake .. -DBUILD_TESTING=ON
cmake --build . --config Release
```

### 3. Run tests

```bash
ctest -C Release
```

## Usage Example

### Basic validation with certificates pack

```cpp
#include <cose/cose.hpp>

int main() {
    try {
        // Build validator with certificates pack
        auto validator = cose::ValidatorBuilderWithCertificates()
            .WithCertificates()
            .Build();
        
        // Validate COSE Sign1 message
        std::vector<uint8_t> cose_bytes = /* ... */;
        auto result = validator.Validate(cose_bytes);
        
        if (result.Ok()) {
            std::cout << "✓ Validation successful\n";
        } else {
            std::cout << "✗ Validation failed: " 
                      << result.FailureMessage() << "\n";
        }
        
    } catch (const cose::cose_error& e) {
        std::cerr << "Error: " << e.what() << "\n";
        return 1;
    }
    
    return 0;
}
```

### Using custom options

```cpp
#include <cose/certificates.hpp>

// Certificate options
cose::CertificateOptions cert_opts;
cert_opts.trust_embedded_chain_as_trusted = true;
cert_opts.identity_pinning_enabled = true;
cert_opts.allowed_thumbprints = {
    "ABCD1234...",
    "5678EFGH..."
};

auto validator = cose::ValidatorBuilderWithCertificates()
    .WithCertificates(cert_opts)
    .Build();
```

### Multiple packs (requires separate includes)

```cpp
// Note: This requires a more complex inheritance structure
// For now, use individual pack builder classes
// Future: implement a unified builder that composes all packs
```

## Per-Pack Headers

The C++ projection follows the per-pack modular design:

- `<cose/validator.hpp>` - Base validator and builder (required)
- `<cose/certificates.hpp>` - X.509 certificate pack wrappers
- `<cose/mst.hpp>` - MST receipt verification pack wrappers
- `<cose/azure_key_vault.hpp>` - Azure Key Vault KID validation pack wrappers
- `<cose/cose.hpp>` - Convenience header (includes all available packs)

Include only the headers you need. Each pack header provides:
- An options struct (e.g., `CertificateOptions`)
- A builder extension class (e.g., `ValidatorBuilderWithCertificates`)
- Pack-specific methods (e.g., `.WithCertificates()`)

## Pack Options

### Certificates Pack

```cpp
cose::CertificateOptions opts;
opts.trust_embedded_chain_as_trusted = true;  // For testing/pinned roots
opts.identity_pinning_enabled = true;
opts.allowed_thumbprints = {"ABCD...", "1234..."};
opts.pqc_algorithm_oids = {"1.2.3.4.5"};

builder.WithCertificates(opts);
```

### MST Pack

```cpp
cose::MstOptions opts;
opts.allow_network = false;
opts.offline_jwks_json = R"({"keys":[...]})";
opts.jwks_api_version = "2024-01-01";

builder.WithMst(opts);
```

### Azure Key Vault Pack

```cpp
cose::AzureKeyVaultOptions opts;
opts.require_azure_key_vault_kid = true;
opts.allowed_kid_patterns = {
    "https://*.vault.azure.net/keys/*",
    "https://*.managedhsm.azure.net/keys/*"
};

builder.WithAzureKeyVault(opts);
```

## RAII and Exception Safety

All C++ wrappers use RAII for automatic resource management:
- No manual `free()` calls needed
- Resources cleaned up automatically via destructors
- Move semantics supported for efficient transfers
- Copy constructors deleted (move-only types)

Errors are reported via `cose::cose_error` exceptions that include detailed error messages from the underlying FFI layer.

## Design Principles

- **Header-only wrappers**: All C++ code is in headers, no separate `.cpp` compilation needed
- **Zero-cost abstraction**: Minimal overhead over C API
- **Modern C++**: Uses C++17 features (structured bindings, if-init, etc.)
- **Per-pack modularity**: Include and link only what you need
- **Exception-based error handling**: Natural C++ idiom
- **RAII resource management**: No manual cleanup required

## Comparison with C API

| Feature | C API | C++ API |
|---------|-------|---------|
| Resource management | Manual `*_free()` | Automatic RAII |
| Error handling | Status codes + `cose_last_error_message_utf8()` | Exceptions with messages |
| Builder pattern | Function calls | Fluent method chaining |
| String handling | `char*` + manual free | `std::string` |
| Binary data | `uint8_t*` + length | `std::vector<uint8_t>` |
| Options | C structs with pointers | C++ structs with STL containers |

## Memory Safety

- All heap allocations managed by RAII
- No raw pointers in public API (except internally for FFI)
- Move semantics prevent double-free
- Deleted copy constructors prevent accidental copying of resources
