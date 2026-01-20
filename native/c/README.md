# COSE Sign1 C API

C projection for the COSE Sign1 validation library.

## Prerequisites

- CMake 3.20 or later
- C11-capable compiler (MSVC, GCC, Clang)
- Rust toolchain (to build the underlying FFI libraries)

## Building

### 1. Build the Rust FFI libraries

```bash
cd ../rust
cargo build --release --workspace
```

This will produce the FFI libraries in `../rust/target/release/`.

### 2. Configure and build the C projection

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

```c
#include <cose/cose_sign1.h>
#include <cose/cose_certificates.h>

int main(void) {
    // Create validator builder
    cose_validator_builder_t* builder = NULL;
    cose_status_t status = cose_validator_builder_new(&builder);
    if (status != COSE_OK) {
        char* err = cose_last_error_message_utf8();
        fprintf(stderr, "Error: %s\n", err);
        cose_string_free(err);
        return 1;
    }
    
    // Add X.509 certificate validation pack
    status = cose_validator_builder_with_certificates_pack(builder);
    if (status != COSE_OK) {
        // Handle error...
    }
    
    // Build validator
    cose_validator_t* validator = NULL;
    status = cose_validator_builder_build(builder, &validator);
    if (status != COSE_OK) {
        // Handle error...
    }
    
    // Validate COSE Sign1 message
    cose_validation_result_t* result = NULL;
    status = cose_validator_validate_bytes(
        validator,
        cose_bytes, cose_bytes_len,
        NULL, 0,  // No detached payload
        &result
    );
    
    if (status == COSE_OK) {
        bool ok = false;
        cose_validation_result_is_success(result, &ok);
        if (ok) {
            printf("✓ Validation successful\n");
        } else {
            char* msg = cose_validation_result_failure_message_utf8(result);
            printf("✗ Validation failed: %s\n", msg);
            cose_string_free(msg);
        }
        cose_validation_result_free(result);
    }
    
    // Cleanup
    cose_validator_free(validator);
    cose_validator_builder_free(builder);
    
    return 0;
}
```

## Available Pack Headers

- `<cose/cose_sign1.h>` - Base validation API (required)
- `<cose/cose_certificates.h>` - X.509 certificate validation pack
- `<cose/cose_mst.h>` - Microsoft Secure Transparency receipt verification pack
- `<cose/cose_azure_key_vault.h>` - Azure Key Vault KID validation pack

## Pack Options

Each pack supports two functions:
- `cose_validator_builder_with_<pack>_pack()` - Use default (secure) options
- `cose_validator_builder_with_<pack>_pack_ex()` - Use custom options

### Certificates Pack Options

```c
cose_certificate_trust_options_t opts = {
    .trust_embedded_chain_as_trusted = true,  // For testing/pinned roots
    .identity_pinning_enabled = true,
    .allowed_thumbprints = (const char*[]){
        "ABCD1234...",
        NULL  // NULL-terminated
    },
    .pqc_algorithm_oids = NULL  // No custom PQC OIDs
};
cose_validator_builder_with_certificates_pack_ex(builder, &opts);
```

### MST Pack Options

```c
cose_mst_trust_options_t opts = {
    .allow_network = false,
    .offline_jwks_json = "{...}",  // JWKS JSON string
    .jwks_api_version = NULL
};
cose_validator_builder_with_mst_pack_ex(builder, &opts);
```

### Azure Key Vault Pack Options

```c
cose_akv_trust_options_t opts = {
    .require_azure_key_vault_kid = true,
    .allowed_kid_patterns = (const char*[]){
        "https://*.vault.azure.net/keys/*",
        "https://*.managedhsm.azure.net/keys/*",
        NULL
    }
};
cose_validator_builder_with_akv_pack_ex(builder, &opts);
```

## Error Handling

All functions return `cose_status_t`:
- `COSE_OK` - Success
- `COSE_ERR` - Error (retrieve message with `cose_last_error_message_utf8()`)
- `COSE_PANIC` - Rust panic (should not occur in normal usage)
- `COSE_INVALID_ARG` - Invalid argument (e.g., null pointer)

Error messages are thread-local. Always call `cose_string_free()` on strings returned by the library.

## Memory Management

- All `*_new()` functions allocate handles that must be freed with corresponding `*_free()` functions
- `*_free()` functions accept NULL pointers (no-op)
- Strings returned by the library must be freed with `cose_string_free()`
- String arrays in option structs are NOT owned by the library (caller retains ownership)
